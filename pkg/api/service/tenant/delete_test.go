package tenant_test

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"sync"
	"testing"
	"time"

	s3bkt "github.com/fil-forge/libforge/commands/s3/bucket"

	"github.com/fil-forge/hilt/internal/testutil"
	tenantsvc "github.com/fil-forge/hilt/pkg/api/service/tenant"
	"github.com/fil-forge/hilt/pkg/grant"
	"github.com/fil-forge/hilt/pkg/store"
	accesskeystore "github.com/fil-forge/hilt/pkg/store/accesskey"
	accesskeypostgres "github.com/fil-forge/hilt/pkg/store/accesskey/postgres"
	bucketpostgres "github.com/fil-forge/hilt/pkg/store/bucket/postgres"
	delegationpostgres "github.com/fil-forge/hilt/pkg/store/delegation/postgres"
	principalpostgres "github.com/fil-forge/hilt/pkg/store/principal/postgres"
	providerpostgres "github.com/fil-forge/hilt/pkg/store/provider/postgres"
	revocationpostgres "github.com/fil-forge/hilt/pkg/store/revocation/postgres"
	"github.com/fil-forge/hilt/pkg/store/tenant"
	tenantpostgres "github.com/fil-forge/hilt/pkg/store/tenant/postgres"
	wrapkeystore "github.com/fil-forge/hilt/pkg/store/wrapkey"
	wrapkeyspostgres "github.com/fil-forge/hilt/pkg/store/wrapkey/postgres"
	"github.com/fil-forge/hilt/pkg/tasks"
	"github.com/fil-forge/hilt/pkg/tasks/revocationqueue"
	"github.com/fil-forge/hilt/pkg/tasks/tenantqueue"
	"github.com/fil-forge/hilt/pkg/vault"
	vaultmemory "github.com/fil-forge/hilt/pkg/vault/memory"
	"github.com/fil-forge/hilt/pkg/wrapkey"
	"github.com/fil-forge/libforge/taskrunner"
	"github.com/fil-forge/ucantone/did"
	"github.com/fil-forge/ucantone/did/plc"
	"github.com/fil-forge/ucantone/multikey"
	"github.com/fil-forge/ucantone/multikey/secp256k1"
	"github.com/fil-forge/ucantone/ucan"
	"github.com/fil-forge/ucantone/ucan/command"
	"github.com/fil-forge/ucantone/ucan/delegation"
	"github.com/ipfs/go-cid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

// events records, in order, each publish the revocation service took and each
// tombstone the DID directory took.
type events struct {
	mu  sync.Mutex
	log []string
}

const (
	published   = "publish"
	deactivated = "deactivate"
)

func (e *events) add(ev string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.log = append(e.log, ev)
}

func (e *events) list() []string {
	e.mu.Lock()
	defer e.mu.Unlock()
	return slices.Clone(e.log)
}

// plcDirectory is an httptest-backed did:plc directory: it serves the
// tenant's genesis operation as its last until it takes a tombstone, and the
// tombstone after.
type plcDirectory struct {
	events *events
	// beforeTombstone runs, when set, before a tombstone is taken.
	beforeTombstone func()

	mu            sync.Mutex
	genesis       []byte
	tombstone     []byte
	deactivated   bool
	lastStatus    int
	postStatus    int
	deactivations int
}

func (d *plcDirectory) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		d.mu.Lock()
		status, body := d.lastStatus, d.genesis
		if d.deactivated {
			body = d.tombstone
		}
		d.mu.Unlock()
		if status != 0 {
			w.WriteHeader(status)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(body)
	case http.MethodPost:
		if d.beforeTombstone != nil {
			d.beforeTombstone()
		}
		d.mu.Lock()
		defer d.mu.Unlock()
		if d.postStatus != 0 {
			w.WriteHeader(d.postStatus)
			return
		}
		d.deactivations++
		d.deactivated = true
		d.events.add(deactivated)
		w.WriteHeader(http.StatusOK)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

// fail makes reading the last operation answer last, and taking a tombstone
// answer post, when either is not zero.
func (d *plcDirectory) fail(last, post int) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.lastStatus, d.postStatus = last, post
}

func (d *plcDirectory) setDeactivated() {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.deactivated = true
}

func (d *plcDirectory) tombstones() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.deactivations
}

type deleteEnv struct {
	svc     *tenantsvc.Service
	pool    *pgxpool.Pool
	runner  *taskrunner.Runner
	secrets vault.Vault
	swarf   *testutil.FakeSwarf
	events  *events
	// directory is the DID directory the deletion deactivates the DID in.
	directory *plcDirectory
	// tenantID is the tenant's DID, and issuer signs as it.
	tenantID did.DID
	issuer   ucan.Issuer
	// keys are the tenant's access keys: a service key and a key bound to
	// user-1.
	keys []did.DID
	// bucketID is the tenant's bucket, which has a policy.
	bucketID did.DID
	// grants are the delegations the tenant issued its keys, which they hold.
	grants []cid.Cid
	// owed are the revocations the tenant owes.
	owed []cid.Cid
	// vaultPaths are the vault entries the deletion removes.
	vaultPaths []string
}

// deleteSetup builds a tenant service over a test database and a fake DID
// directory and revocation service, with a tenant "tenant-1" of the status
// given that has a bucket with a policy and the bucket's root delegation, two
// principals (one of them removed), a service key and a key bound to the live
// principal, both holding grants and with their secrets in the vault, a wrap
// key, and owed revocations, more than one batch of them. wrap replaces what
// queue-tenant's handlers work through.
func deleteSetup(t *testing.T, status tenant.Status, wrap ...func(*tenantqueue.Deps)) deleteEnv {
	t.Helper()
	pool := testutil.PostgresOrSkip(t)
	ctx := t.Context()

	signer, err := secp256k1.Generate()
	require.NoError(t, err)
	key := signer.KeyDID()
	tenantID, genesis, err := plc.New(signer,
		plc.WithRotationKeys(key),
		plc.WithVerificationMethods(map[string]did.DID{"hilt": key}),
	)
	require.NoError(t, err)
	var genesisJSON, tombstoneJSON bytes.Buffer
	require.NoError(t, genesis.MarshalDagJSON(&genesisJSON))
	tomb, err := plc.NewTombstoneFromPrevious(genesis)
	require.NoError(t, err)
	signedTomb, err := plc.SignTombstone(signer, tomb)
	require.NoError(t, err)
	require.NoError(t, signedTomb.MarshalDagJSON(&tombstoneJSON))

	ev := &events{}
	directory := &plcDirectory{events: ev, genesis: genesisJSON.Bytes(), tombstone: tombstoneJSON.Bytes()}
	dirServer := httptest.NewServer(directory)
	t.Cleanup(dirServer.Close)
	endpoint, err := url.Parse(dirServer.URL)
	require.NoError(t, err)
	plcClient, err := plc.NewDirectoryClient(*endpoint)
	require.NoError(t, err)

	env := deleteEnv{pool: pool, events: ev, directory: directory, tenantID: tenantID, issuer: multikey.NewIssuer(tenantID, signer)}
	tenants, principals := tenantpostgres.New(pool), principalpostgres.New(pool)
	buckets, accessKeys, delegations := bucketpostgres.New(pool), accesskeypostgres.New(pool), delegationpostgres.New(pool)
	wrapKeys := wrapkeyspostgres.New(pool)
	secrets := vaultmemory.New()
	env.secrets = secrets
	require.NoError(t, tenants.Add(ctx, tenantID, "tenant-1", tenant.Active))
	require.NoError(t, secrets.Write(ctx, vault.TenantKeyPath(tenantID), signer.Bytes()))

	wrapKP, err := wrapkey.Generate()
	require.NoError(t, err)
	wrapPath := wrapkeystore.VaultKey(tenantID, 1)
	require.NoError(t, secrets.Write(ctx, wrapPath, wrapKP.Bytes()))
	require.NoError(t, wrapKeys.Add(ctx, wrapkeystore.Input{Tenant: tenantID, Version: 1, KID: wrapKP.Public().String(), VaultKey: wrapPath}))

	require.NoError(t, principals.Add(ctx, tenantID, "user-1"))
	require.NoError(t, principals.Add(ctx, tenantID, "user-2"))
	testutil.Exec(t, pool, principals.TombstoneStatement(tenantID, "user-2"))

	providerID := testutil.RandomDID(t)
	require.NoError(t, providerpostgres.New(pool).Add(ctx, providerID, "region-1", nil))
	bucketIssuer := testutil.RandomIssuer(t)
	env.bucketID = bucketIssuer.DID()
	require.NoError(t, buckets.Add(ctx, env.bucketID, tenantID, providerID, "tenant-1-bucket"))
	root, err := delegation.Delegate(bucketIssuer, tenantID, env.bucketID, command.Top(), delegation.WithNoExpiration())
	require.NoError(t, err)
	require.NoError(t, delegations.PutBatch(ctx, []ucan.Delegation{root}))
	testutil.PutPolicy(t, pool, tenantID, env.bucketID, s3bkt.PolicyDocument{Version: s3bkt.Version2012, Statements: []s3bkt.Statement{
		{Effect: s3bkt.Allow, Principal: s3bkt.Only("user-1"), Actions: s3bkt.NewStringSet("s3:GetObject"), Resources: s3bkt.NewStringSet(s3bkt.BucketARN("tenant-1-bucket"), s3bkt.ObjectsARN("tenant-1-bucket"))},
	}})

	serviceKey, boundKey := testutil.RandomDID(t), testutil.RandomDID(t)
	env.keys = []did.DID{serviceKey, boundKey}
	require.NoError(t, accessKeys.Add(ctx, accesskeystore.Input{ID: serviceKey, Tenant: tenantID, Name: "k1", Permissions: []string{"s3:GetObject"}}))
	bound, err := accesskeystore.NewPrincipalKey(boundKey, tenantID, "k2", "user-1", nil)
	require.NoError(t, err)
	require.NoError(t, accessKeys.Add(ctx, bound))
	for _, k := range env.keys {
		held, err := grant.Issue(env.issuer, k, []did.DID{env.bucketID}, []string{"s3:GetObject"}, nil)
		require.NoError(t, err)
		require.NoError(t, delegations.PutBatch(ctx, held))
		for _, d := range held {
			env.grants = append(env.grants, d.Link())
		}
		path := vault.AccessKeyPath(tenantID, k)
		require.NoError(t, secrets.Write(ctx, path, []byte("secret of "+k.String())))
		env.vaultPaths = append(env.vaultPaths, path)
	}
	env.vaultPaths = append(env.vaultPaths, wrapPath, vault.TenantKeyPath(tenantID))

	env.owed = issueOwed(t, pool, env.issuer, revocationqueue.BatchSize+1)

	// The status is set once the keys exist: a disabled tenant takes no new
	// key. Set this way, the keys keep the grants a disabling task would
	// have withdrawn, so the deletion has those to revoke too.
	require.NoError(t, tenants.SetStatus(ctx, tenantID, status))

	env.swarf = &testutil.FakeSwarf{OnPublish: func() { ev.add(published) }}
	env.runner = testutil.StartServiceTasks(t, pool, secrets, env.swarf, append([]func(*tenantqueue.Deps){testutil.WithDirectory(plcClient)}, wrap...)...)
	env.svc = tenantsvc.New(zap.NewNop(), tenants, secrets, wrapKeys, plcClient, nil, env.runner)
	return env
}

// issueOwed records n delegations issued by the tenant as revocations it
// owes, and returns their CIDs.
func issueOwed(t *testing.T, pool *pgxpool.Pool, issuer ucan.Issuer, n int) []cid.Cid {
	t.Helper()
	var dels []ucan.Delegation
	for len(dels) < n {
		issued, err := grant.Issue(issuer, testutil.RandomDID(t), []did.DID{testutil.RandomDID(t)}, []string{"s3:GetObject"}, nil)
		require.NoError(t, err)
		dels = append(dels, issued...)
	}
	dels = dels[:n]
	require.NoError(t, revocationpostgres.New(pool).Add(t.Context(), issuer.DID(), dels))
	out := make([]cid.Cid, n)
	for i, d := range dels {
		out[i] = d.Link()
	}
	return out
}

// left counts, by table, the rows Hilt still holds for the tenant, its keys
// and its bucket. A table with none is left out.
func (e deleteEnv) left(t *testing.T) map[string]int {
	t.Helper()
	tenantID, keys, bucketID := e.tenantID.String(), []string{e.keys[0].String(), e.keys[1].String()}, e.bucketID.String()
	queries := map[string]struct {
		sql  string
		args []any
	}{
		"tenant":                  {`SELECT count(*) FROM tenant WHERE id = $1`, []any{tenantID}},
		"access_key":              {`SELECT count(*) FROM access_key WHERE tenant_id = $1 OR id = ANY($2)`, []any{tenantID, keys}},
		"principal":               {`SELECT count(*) FROM principal WHERE tenant_id = $1`, []any{tenantID}},
		"bucket":                  {`SELECT count(*) FROM bucket WHERE tenant_id = $1 OR id = $2`, []any{tenantID, bucketID}},
		"bucket_policy":           {`SELECT count(*) FROM bucket_policy WHERE bucket_id = $1`, []any{bucketID}},
		"bucket_policy_principal": {`SELECT count(*) FROM bucket_policy_principal WHERE tenant_id = $1 OR bucket_id = $2`, []any{tenantID, bucketID}},
		"delegation":              {`SELECT count(*) FROM delegation WHERE issuer = $1 OR audience = $1 OR audience = ANY($2) OR subject = $3`, []any{tenantID, keys, bucketID}},
		"wrap_key":                {`SELECT count(*) FROM wrap_key WHERE tenant_id = $1`, []any{tenantID}},
		"revocation_owed":         {`SELECT count(*) FROM revocation_owed WHERE tenant_id = $1`, []any{tenantID}},
		"deleted_bucket":          {`SELECT count(*) FROM deleted_bucket WHERE tenant_id = $1 OR id = $2`, []any{tenantID, bucketID}},
	}
	out := map[string]int{}
	for table, q := range queries {
		var n int
		require.NoError(t, e.pool.QueryRow(t.Context(), q.sql, q.args...).Scan(&n))
		if n > 0 {
			out[table] = n
		}
	}
	return out
}

// vaultLeft returns the vault entries of the tenant still there.
func (e deleteEnv) vaultLeft(t *testing.T) []string {
	t.Helper()
	var out []string
	for _, p := range e.vaultPaths {
		_, err := e.secrets.Read(t.Context(), p)
		if errors.Is(err, vault.ErrNotFound) {
			continue
		}
		require.NoError(t, err)
		out = append(out, p)
	}
	return out
}

// requireGone checks that nothing of the tenant is left, in the database or
// the vault.
func (e deleteEnv) requireGone(t *testing.T) {
	t.Helper()
	require.Empty(t, e.left(t), "rows left")
	require.Empty(t, e.vaultLeft(t), "vault entries left")
}

// requireIntact checks that every row and vault entry of the tenant is still
// there, as the setup left them.
func (e deleteEnv) requireIntact(t *testing.T) {
	t.Helper()
	require.Equal(t, map[string]int{
		"tenant":                  1,
		"access_key":              2,
		"principal":               2,
		"bucket":                  1,
		"bucket_policy":           1,
		"bucket_policy_principal": 1,
		"delegation":              len(e.grants) + 1,
		"wrap_key":                1,
		"revocation_owed":         len(e.owed),
	}, e.left(t))
	require.ElementsMatch(t, e.vaultPaths, e.vaultLeft(t))
}

// requirePublishedFirst checks that the revocation service took every grant
// the keys held and every revocation owed, and that every publish came
// before the one tombstone.
func (e deleteEnv) requirePublishedFirst(t *testing.T) {
	t.Helper()
	log := e.events.list()
	require.NotEmpty(t, log)
	require.Equal(t, deactivated, log[len(log)-1], "the tombstone came last")
	require.Equal(t, 1, e.directory.tombstones())
	for _, ev := range log[:len(log)-1] {
		require.Equal(t, published, ev)
	}
	for _, r := range e.swarf.Revocations() {
		require.Equal(t, e.tenantID, r.Revoker)
	}
	require.Subset(t, e.swarf.Revoked(), append(slices.Clone(e.owed), e.grants...))
}

func TestDelete(t *testing.T) {
	ctx := t.Context()

	t.Run("deletes a disabled tenant and everything Hilt holds for it", func(t *testing.T) {
		env := deleteSetup(t, tenant.Disabled)
		env.requireIntact(t)

		require.NoError(t, env.svc.Delete(ctx, "tenant-1"))

		env.requireGone(t)
		env.requirePublishedFirst(t)
		require.ElementsMatch(t, append(slices.Clone(env.owed), env.grants...), env.swarf.Revoked(), "each revocation once, and the bucket's root not at all")
	})

	t.Run("a second delete finds nothing and succeeds", func(t *testing.T) {
		env := deleteSetup(t, tenant.Disabled)
		require.NoError(t, env.svc.Delete(ctx, "tenant-1"))
		before := env.events.list()

		require.NoError(t, env.svc.Delete(ctx, "tenant-1"))
		require.Equal(t, before, env.events.list(), "nothing published or deactivated again")
		env.requireGone(t)
	})

	t.Run("a missing tenant is a no-op", func(t *testing.T) {
		env := deleteSetup(t, tenant.Disabled)
		require.NoError(t, env.svc.Delete(ctx, "missing"))
		require.Empty(t, env.events.list())
		env.requireIntact(t)
	})

	for _, status := range []tenant.Status{tenant.Active, tenant.WriteLocked} {
		t.Run("a "+string(status)+" tenant is refused and left as it is", func(t *testing.T) {
			env := deleteSetup(t, status)
			require.ErrorIs(t, env.svc.Delete(ctx, "tenant-1"), tenantsvc.ErrTenantNotDisabled)
			require.Empty(t, env.events.list())
			env.requireIntact(t)
		})
	}

	t.Run("a directory failure before the publish leaves everything, and a retry completes", func(t *testing.T) {
		env := deleteSetup(t, tenant.Disabled)
		env.directory.fail(http.StatusInternalServerError, 0)

		require.ErrorIs(t, env.svc.Delete(ctx, "tenant-1"), tenantsvc.ErrDIDDeactivation)
		require.Empty(t, env.events.list())
		env.requireIntact(t)

		env.directory.fail(0, 0)
		require.NoError(t, env.svc.Delete(ctx, "tenant-1"))
		env.requireGone(t)
		env.requirePublishedFirst(t)
	})

	t.Run("a publish failure leaves the DID live and everything in place, and a retry completes", func(t *testing.T) {
		env := deleteSetup(t, tenant.Disabled)
		env.swarf.Err = errors.New("swarf unreachable")

		err := env.svc.Delete(ctx, "tenant-1")
		require.ErrorContains(t, err, "swarf unreachable")
		require.ErrorContains(t, err, "revocations owed")
		require.Zero(t, env.directory.tombstones())
		env.requireIntact(t)

		env.swarf.Err = nil
		require.NoError(t, env.svc.Delete(ctx, "tenant-1"))
		env.requireGone(t)
		env.requirePublishedFirst(t)
	})

	t.Run("a failed deactivation after the publish leaves everything, and a retry publishes again first", func(t *testing.T) {
		env := deleteSetup(t, tenant.Disabled)
		env.directory.fail(0, http.StatusInternalServerError)

		require.ErrorIs(t, env.svc.Delete(ctx, "tenant-1"), tenantsvc.ErrDIDDeactivation)
		require.NotEmpty(t, env.swarf.Calls(), "the publish ran")
		require.Subset(t, env.swarf.Revoked(), append(slices.Clone(env.owed), env.grants...))
		require.Zero(t, env.directory.tombstones())
		env.requireIntact(t)

		env.directory.fail(0, 0)
		first := env.swarf.Calls()
		require.NoError(t, env.svc.Delete(ctx, "tenant-1"))
		require.Greater(t, env.swarf.Calls(), first, "the retry publishes again before it deactivates")
		env.requireGone(t)
		env.requirePublishedFirst(t)
	})

	t.Run("a commit that fails after the deactivation is retried: the rows go and nothing is published after the tombstone", func(t *testing.T) {
		failing := &failingTenantDelete{}
		env := deleteSetup(t, tenant.Disabled, func(d *tenantqueue.Deps) {
			failing.Store = d.Tenants
			d.Tenants = failing
		})

		require.NoError(t, env.svc.Delete(ctx, "tenant-1"))
		require.Equal(t, 2, failing.calls(), "the first commit failed and the task ran again")
		env.requireGone(t)
		env.requirePublishedFirst(t)
	})

	t.Run("a DID an earlier attempt deactivated: no publish, no tombstone, and the rows go without the vault entries", func(t *testing.T) {
		env := deleteSetup(t, tenant.Disabled)
		env.directory.setDeactivated()
		// The earlier attempt removed the vault entries before its commit
		// failed.
		for _, p := range env.vaultPaths {
			require.NoError(t, env.secrets.Delete(ctx, p))
		}

		require.NoError(t, env.svc.Delete(ctx, "tenant-1"))
		require.Empty(t, env.events.list())
		require.Zero(t, env.swarf.Calls())
		env.requireGone(t)
	})

	t.Run("a change queued behind a running deletion waits its turn and fails as the tenant is gone", func(t *testing.T) {
		entered, release := make(chan struct{}), make(chan struct{})
		var once sync.Once
		env := deleteSetup(t, tenant.Disabled)
		env.directory.beforeTombstone = func() {
			once.Do(func() { close(entered) })
			<-release
		}

		deleted := make(chan error, 1)
		go func() { deleted <- env.svc.Delete(context.Background(), "tenant-1") }()
		<-entered

		reactivated := make(chan error, 1)
		go func() { reactivated <- env.svc.SetStatus(context.Background(), "tenant-1", string(tenant.Active)) }()
		newKey := testutil.RandomDID(t)
		spec, err := tenantqueue.CreateKeySpec(accesskeystore.Input{ID: newKey, Tenant: env.tenantID, Name: "late", Permissions: []string{"s3:GetObject"}})
		require.NoError(t, err)
		created := make(chan error, 1)
		go func() {
			_, err := env.runner.Run(context.Background(), spec)
			created <- err
		}()
		require.Eventually(t, func() bool {
			pending, err := env.runner.PendingOn(ctx, tasks.QueueTenant, env.tenantID.String())
			require.NoError(t, err)
			return len(pending) == 3
		}, testutil.WaitTimeout, 10*time.Millisecond, "the reactivation and the key creation queue behind the deletion")
		select {
		case err := <-reactivated:
			t.Fatalf("the reactivation finished while the deletion ran: %v", err)
		case err := <-created:
			t.Fatalf("the key creation finished while the deletion ran: %v", err)
		default:
		}

		close(release)
		require.NoError(t, <-deleted)
		require.ErrorIs(t, <-reactivated, tenantsvc.ErrTenantNotFound)
		err = <-created
		require.ErrorIs(t, err, tenantqueue.ErrTenantNotFound)
		require.True(t, taskrunner.IsPermanent(err))
		env.requireGone(t)
		_, err = accesskeypostgres.New(env.pool).Get(ctx, newKey)
		require.ErrorIs(t, err, store.ErrRecordNotFound)
		env.requirePublishedFirst(t)
	})

	t.Run("every other change to a deleted tenant ends at once", func(t *testing.T) {
		env := deleteSetup(t, tenant.Disabled)
		require.NoError(t, env.svc.Delete(ctx, "tenant-1"))
		before := env.events.list()

		putPolicy, err := tenantqueue.PutPolicySpec(env.tenantID, env.bucketID, "tenant-1-bucket", s3bkt.PolicyDocument{Version: s3bkt.Version2012}, tenantqueue.PolicyCondition{})
		require.NoError(t, err)
		deletePolicy, err := tenantqueue.DeletePolicySpec(env.tenantID, env.bucketID, "tenant-1-bucket", nil)
		require.NoError(t, err)
		createKey, err := tenantqueue.CreateKeySpec(accesskeystore.Input{ID: testutil.RandomDID(t), Tenant: env.tenantID, Name: "late", Permissions: []string{"s3:GetObject"}})
		require.NoError(t, err)
		for name, c := range map[string]struct {
			spec taskrunner.Spec
			want error
		}{
			"set-status":       {tenantqueue.SetStatusSpec(env.tenantID, tenant.Active), tenantqueue.ErrTenantNotFound},
			"create-key":       {createKey, tenantqueue.ErrTenantNotFound},
			"put-policy":       {putPolicy, tenantqueue.ErrUnknownBucket},
			"delete-policy":    {deletePolicy, tenantqueue.ErrUnknownBucket},
			"delete-key":       {tenantqueue.DeleteKeySpec(env.tenantID, env.keys[0]), nil},
			"remove-principal": {tenantqueue.RemovePrincipalSpec(env.tenantID, "user-1"), nil},
			"delete-bucket":    {tenantqueue.DeleteBucketSpec(env.tenantID, env.bucketID), nil},
			"delete-tenant":    {tenantqueue.DeleteTenantSpec(env.tenantID), nil},
		} {
			runCtx, cancel := context.WithTimeout(ctx, testutil.WaitTimeout)
			_, err := env.runner.Run(runCtx, c.spec)
			cancel()
			if c.want == nil {
				require.NoError(t, err, name)
				continue
			}
			require.ErrorIs(t, err, c.want, name)
			require.True(t, taskrunner.IsPermanent(err), name)
		}
		require.Equal(t, before, env.events.list())
		env.requireGone(t)
	})

	t.Run("a revocation publish left queued for the tenant succeeds with nothing to do", func(t *testing.T) {
		env := deleteSetup(t, tenant.Disabled)
		later := time.Now().Add(time.Hour)
		spec := revocationqueue.PublishSpec(env.tenantID)
		spec.NotBefore = &later
		id, err := env.runner.Submit(ctx, spec)
		require.NoError(t, err)

		require.NoError(t, env.svc.Delete(ctx, "tenant-1"))
		before := env.events.list()

		_, err = env.runner.Expedite(ctx, tasks.QueueRevocation, env.tenantID.String(), tasks.ActionPublish)
		require.NoError(t, err)
		waitCtx, cancel := context.WithTimeout(ctx, testutil.WaitTimeout)
		defer cancel()
		_, err = env.runner.Wait(waitCtx, tasks.QueueRevocation, id)
		require.NoError(t, err)
		require.Equal(t, before, env.events.list(), "nothing was published after the deletion")
	})
}

// failingTenantDelete fails the commit of the first tenant deletion that
// reaches it, after every effect outside the database: the statement that
// deletes the tenant's row divides by zero the first time it is built.
type failingTenantDelete struct {
	tenant.Store

	mu sync.Mutex
	n  int
}

func (f *failingTenantDelete) DeleteStatement(id did.DID) store.Statement {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.n++
	if f.n == 1 {
		return store.Statement{SQL: `SELECT 1 / 0 WHERE $1::text IS NOT NULL`, Args: []any{id.String()}}
	}
	return f.Store.DeleteStatement(id)
}

func (f *failingTenantDelete) calls() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.n
}
