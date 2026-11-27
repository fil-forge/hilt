package rpc_test

import (
	"context"
	"errors"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	s3bkt "github.com/fil-forge/libforge/commands/s3/bucket"

	htestutil "github.com/fil-forge/hilt/internal/testutil"
	accesskeysvc "github.com/fil-forge/hilt/pkg/api/service/accesskey"
	bucketpolicysvc "github.com/fil-forge/hilt/pkg/api/service/bucketpolicy"
	tenantsvc "github.com/fil-forge/hilt/pkg/api/service/tenant"
	"github.com/fil-forge/hilt/pkg/client/upload"
	"github.com/fil-forge/hilt/pkg/rpc"
	"github.com/fil-forge/hilt/pkg/rpc/service/auth"
	bucketsvc "github.com/fil-forge/hilt/pkg/rpc/service/bucket"
	"github.com/fil-forge/hilt/pkg/s3perm"
	"github.com/fil-forge/hilt/pkg/store"
	accesskeypostgres "github.com/fil-forge/hilt/pkg/store/accesskey/postgres"
	bucketpostgres "github.com/fil-forge/hilt/pkg/store/bucket/postgres"
	bucketpolicypostgres "github.com/fil-forge/hilt/pkg/store/bucketpolicy/postgres"
	delegationstore "github.com/fil-forge/hilt/pkg/store/delegation"
	delegationpostgres "github.com/fil-forge/hilt/pkg/store/delegation/postgres"
	principalpostgres "github.com/fil-forge/hilt/pkg/store/principal/postgres"
	providerpostgres "github.com/fil-forge/hilt/pkg/store/provider/postgres"
	revocationpostgres "github.com/fil-forge/hilt/pkg/store/revocation/postgres"
	"github.com/fil-forge/hilt/pkg/store/tenant"
	tenantpostgres "github.com/fil-forge/hilt/pkg/store/tenant/postgres"
	wrapkeypostgres "github.com/fil-forge/hilt/pkg/store/wrapkey/postgres"
	"github.com/fil-forge/hilt/pkg/tasks/revocationqueue"
	"github.com/fil-forge/hilt/pkg/tasks/tenantqueue"
	"github.com/fil-forge/hilt/pkg/vault"
	vaultmemory "github.com/fil-forge/hilt/pkg/vault/memory"
	s3req "github.com/fil-forge/libforge/commands/s3/request"
	"github.com/fil-forge/libforge/taskrunner"
	"github.com/fil-forge/libforge/testutil"
	"github.com/fil-forge/ucantone/did"
	"github.com/fil-forge/ucantone/multikey"
	"github.com/fil-forge/ucantone/multikey/ed25519"
	"github.com/fil-forge/ucantone/multikey/secp256k1"
	"github.com/fil-forge/ucantone/ucan"
	"github.com/fil-forge/ucantone/ucan/command"
	"github.com/fil-forge/ucantone/ucan/delegation"
	"github.com/ipfs/go-cid"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

// gatedSwarf is a revocation service that refuses every publish while
// holding is set, so a test can look at the revocations owed before they are
// published.
type gatedSwarf struct {
	htestutil.FakeSwarf
	holding atomic.Bool
}

func (g *gatedSwarf) PublishBatch(ctx context.Context, revoker ucan.Issuer, revoked []ucan.Delegation) error {
	if g.holding.Load() {
		return errors.New("revocation service unavailable")
	}
	return g.FakeSwarf.PublishBatch(ctx, revoker, revoked)
}

// onList is the delegation store the bucket service reads through. It runs
// then, once, when a key's delegations are first listed, which lands a
// change after the service has authorized its request and before it reads
// the key's proof chains.
type onList struct {
	delegationstore.Store
	mu   sync.Mutex
	then func()
}

func (o *onList) ListByAudience(ctx context.Context, audience did.DID, opts ...store.PaginationOption) (store.Page[ucan.Delegation], error) {
	o.mu.Lock()
	then := o.then
	o.then = nil
	o.mu.Unlock()
	if then != nil {
		then()
	}
	return o.Store.ListByAudience(ctx, audience, opts...)
}

// stubSprue is an upload service that provisions every space and reports
// every space empty.
type stubSprue struct {
	// provisioned counts the spaces provisioned.
	provisioned atomic.Int64
}

func (s *stubSprue) ProvisionSpace(context.Context, ucan.Issuer, did.DID) (string, error) {
	s.provisioned.Add(1)
	return "sub-1", nil
}

func (s *stubSprue) SpaceEmpty(context.Context, did.DID, ...upload.MethodOption) (bool, error) {
	return true, nil
}

func (s *stubSprue) UseRoutingPolicy(context.Context, did.DID, *did.DID, ...upload.MethodOption) error {
	return nil
}

const (
	lockRegion    = "us-west-2"
	lockBucket    = "lock-bucket"
	lockPrincipal = "alice"
)

// The Forge commands of the keys in lockEnv, as held over the bucket: every
// command of an upload while the tenant is active, and the read alone while
// it is write-locked.
var (
	fullCommands   = []string{"/blob/abort", "/blob/add", "/blob/remove", "/content/retrieve", "/index/add"}
	lockedCommands = []string{"/content/retrieve"}
)

// lockEnv is an active tenant with one bucket, served by the real tenant,
// access-key and policy services, task runner, authorizer and bucket
// service. It has three keys:
//
//   - service may read and write the bucket's objects, and is scoped to it.
//   - bound is the key of a principal the bucket's policy lets read and write
//     its objects.
//   - admin reaches every bucket of the tenant, and may also create buckets,
//     list them and delete objects.
type lockEnv struct {
	tenants     *tenantpostgres.Store
	buckets     *bucketpostgres.Store
	delegations *delegationpostgres.Store
	owed        *revocationpostgres.Store
	secrets     *vaultmemory.Store
	swarf       *gatedSwarf
	sprue       *stubSprue
	svc         *tenantsvc.Service
	keys        *accesskeysvc.Service
	policies    *bucketpolicysvc.Service
	bucketSvc   *bucketsvc.Service
	authorizer  *auth.Authorizer
	// queueTenants is the store the queue's tasks read the tenant through.
	queueTenants *pausedTenants
	// authTenants is the store the authorizer reads the tenant through.
	authTenants *afterStatusRead
	// listed is the delegation store the bucket service reads through.
	listed   *onList
	provider did.DID
	tenant   did.DID
	bucket   did.DID
	service  ed25519.Signer
	bound    ed25519.Signer
	admin    ed25519.Signer
}

var adminPermissions = []string{"s3:CreateBucket", "s3:ListAllMyBuckets", "s3:GetObject", "s3:PutObject", "s3:DeleteObject"}

func setupLock(t *testing.T) *lockEnv {
	t.Helper()
	ctx := t.Context()
	pool := htestutil.PostgresOrSkip(t)
	tenants, accessKeys, buckets := tenantpostgres.New(pool), accesskeypostgres.New(pool), bucketpostgres.New(pool)
	providers, principals, policies := providerpostgres.New(pool), principalpostgres.New(pool), bucketpolicypostgres.New(pool)
	env := &lockEnv{
		tenants:      tenants,
		buckets:      buckets,
		delegations:  delegationpostgres.New(pool),
		owed:         revocationpostgres.New(pool),
		secrets:      vaultmemory.New(),
		swarf:        &gatedSwarf{},
		sprue:        &stubSprue{},
		queueTenants: &pausedTenants{Store: tenants},
		authTenants:  &afterStatusRead{Store: tenants},
		provider:     testutil.RandomDID(t),
	}
	env.listed = &onList{Store: env.delegations}

	signer, err := secp256k1.Generate()
	require.NoError(t, err)
	env.tenant = signer.KeyDID()
	require.NoError(t, providers.Add(ctx, env.provider, lockRegion, nil))
	require.NoError(t, tenants.Add(ctx, env.tenant, "tenant-1", tenant.Active))
	require.NoError(t, env.secrets.Write(ctx, vault.TenantKeyPath(env.tenant), signer.Bytes()))
	require.NoError(t, principals.Add(ctx, env.tenant, lockPrincipal))

	bucketSigner, err := ed25519.Generate()
	require.NoError(t, err)
	env.bucket = bucketSigner.KeyDID()
	require.NoError(t, buckets.Add(ctx, env.bucket, env.tenant, env.provider, lockBucket))
	root, err := delegation.Delegate(multikey.NewIssuer(env.bucket, bucketSigner), env.tenant, env.bucket, command.Top(), delegation.WithNoExpiration())
	require.NoError(t, err)
	require.NoError(t, env.delegations.PutBatch(ctx, []ucan.Delegation{root}))

	runner := htestutil.StartTaskRunner(t, pool, func(r *taskrunner.Runner) {
		_, err := tenantqueue.New(r, tenantqueue.Deps{
			Tenants: env.queueTenants, AccessKeys: accessKeys, Principals: principals, Buckets: buckets,
			Policies: policies, Delegations: env.delegations, Secrets: env.secrets,
		})
		require.NoError(t, err)
		_, err = revocationqueue.New(r, revocationqueue.Deps{
			Owed: env.owed, Secrets: env.secrets, Publisher: env.swarf,
			PublishRetry: taskrunner.RetryPolicy{First: 20 * time.Millisecond, Max: 50 * time.Millisecond, Multiplier: 2},
		})
		require.NoError(t, err)
	})
	env.keys = accesskeysvc.New(zap.NewNop(), tenants, accessKeys, principals, buckets, env.secrets, runner)
	env.policies = bucketpolicysvc.New(zap.NewNop(), tenants, buckets, principals, policies, runner)
	env.svc = tenantsvc.New(zap.NewNop(), tenants, buckets, accessKeys, principals, policies, env.delegations, env.secrets,
		wrapkeypostgres.New(pool), nil, nil, env.swarf, env.owed, runner)
	env.authorizer = auth.NewAuthorizer(zap.NewNop(), accessKeys, env.authTenants, providers, buckets, principals, policies, env.secrets,
		auth.WithTenantChanges(runner))
	env.bucketSvc = bucketsvc.New(zap.NewNop(), env.authorizer, buckets, env.listed, accessKeys, tenants, policies, providers,
		env.sprue, env.swarf, env.policies)

	env.writePolicy(t, "s3:GetObject", "s3:PutObject")
	who := lockPrincipal
	env.service = env.createKey(t, "service", []string{"s3:GetObject", "s3:PutObject"}, []string{lockBucket}, nil)
	env.bound = env.createKey(t, "bound", nil, nil, &who)
	env.admin = env.createKey(t, "admin", adminPermissions, nil, nil)
	return env
}

// writePolicy stores a policy that lets the principal do the actions on the
// bucket's objects, through the policy service.
func (e *lockEnv) writePolicy(t *testing.T, actions ...string) {
	t.Helper()
	_, _, err := e.policies.Write(t.Context(), e.tenant, e.bucket, lockBucket, s3bkt.PolicyDocument{
		Version: s3bkt.Version2012,
		Statements: []s3bkt.Statement{{
			Effect: s3bkt.Allow, Principal: s3bkt.Only(lockPrincipal), Actions: s3bkt.NewStringSet(actions...),
			Resources: s3bkt.NewStringSet(s3bkt.ObjectsARN(lockBucket)),
		}},
	})
	require.NoError(t, err)
}

// createKey creates an access key through the access-key service and
// returns its signer.
func (e *lockEnv) createKey(t *testing.T, name string, permissions, buckets []string, principalID *string) ed25519.Signer {
	t.Helper()
	rec, _, err := e.keys.Create(t.Context(), "tenant-1", name, permissions, buckets, principalID, nil)
	require.NoError(t, err)
	keyBytes, err := e.secrets.Read(t.Context(), vault.AccessKeyPath(e.tenant, rec.ID))
	require.NoError(t, err)
	signer, err := ed25519.Decode(keyBytes)
	require.NoError(t, err)
	return signer
}

func (e *lockEnv) setStatus(t *testing.T, status tenant.Status) {
	t.Helper()
	require.NoError(t, e.svc.SetStatus(t.Context(), "tenant-1", string(status)))
	rec, err := e.svc.Get(t.Context(), "tenant-1")
	require.NoError(t, err)
	require.Equal(t, status, rec.Status)
}

// held returns the delegations the key holds in the store.
func (e *lockEnv) held(t *testing.T, key ed25519.Signer) []ucan.Delegation {
	t.Helper()
	page, err := e.delegations.ListByAudience(t.Context(), key.KeyDID())
	require.NoError(t, err)
	require.Nil(t, page.Cursor, "one page holds everything a test stores")
	return page.Results
}

// commands returns the Forge commands the key holds over subject, sorted,
// after checking it holds nothing over any other subject and each was
// issued by the tenant.
func (e *lockEnv) commands(t *testing.T, key ed25519.Signer, subject did.DID) []string {
	t.Helper()
	var out []string
	for _, d := range e.held(t, key) {
		require.Equal(t, e.tenant, d.Issuer())
		require.Equal(t, subject, d.Subject())
		out = append(out, d.Command().String())
	}
	slices.Sort(out)
	return out
}

// owedLinks returns the CIDs of the revocations the tenant owes.
func (e *lockEnv) owedLinks(t *testing.T) []cid.Cid {
	t.Helper()
	dels, err := e.owed.Oldest(t.Context(), e.tenant, 10_000)
	require.NoError(t, err)
	return cids(dels)
}

// awaitPublished lets the revocation service take publishes and waits until
// the tenant owes nothing.
func (e *lockEnv) awaitPublished(t *testing.T) {
	t.Helper()
	e.swarf.holding.Store(false)
	require.Eventually(t, func() bool { return len(e.owedLinks(t)) == 0 }, htestutil.WaitTimeout, 10*time.Millisecond,
		"the revocations owed were not published")
}

func (e *lockEnv) authorize(t *testing.T, key ed25519.Signer, method, path string) (*s3req.AuthorizeOK, []ucan.Delegation, error) {
	t.Helper()
	return rpc.AuthorizeRequest(t.Context(), zap.NewNop(), e.authorizer, e.delegations, e.provider,
		signedArgs(t, key, method, "https://s3.fil.one"+path, lockRegion))
}

func names(cmds []ucan.Command) []string {
	out := make([]string, len(cmds))
	for i, c := range cmds {
		out[i] = c.String()
	}
	slices.Sort(out)
	return out
}

// Every change of status through the tenant service withdraws what the
// tenant's keys hold, as revocations owed and then published, and issues
// each key the grants of the new status.
func TestWriteLockThroughTheService(t *testing.T) {
	env := setupLock(t)
	keys := map[string]ed25519.Signer{"the service key": env.service, "the principal-bound key": env.bound}
	// all returns what the two keys hold, after requiring each holds cmds
	// over the bucket.
	all := func(t *testing.T, cmds []string) []ucan.Delegation {
		t.Helper()
		var out []ucan.Delegation
		for name, key := range keys {
			if cmds == nil {
				require.Empty(t, env.held(t, key), name)
				continue
			}
			require.Equal(t, cmds, env.commands(t, key, env.bucket), name)
			out = append(out, env.held(t, key)...)
		}
		return out
	}
	// owedOf returns the revocations owed that are among dels.
	owedOf := func(t *testing.T, dels []ucan.Delegation) []cid.Cid {
		t.Helper()
		var out []cid.Cid
		for _, link := range env.owedLinks(t) {
			if slices.Contains(cids(dels), link) {
				out = append(out, link)
			}
		}
		return out
	}
	original := all(t, fullCommands)

	// Active to write-locked: each key is left the read alone, and what it
	// held is owed a revocation, then published.
	env.swarf.holding.Store(true)
	env.setStatus(t, tenant.WriteLocked)
	narrowed := all(t, lockedCommands)
	require.ElementsMatch(t, cids(original), owedOf(t, original), "every grant the keys held is owed a revocation")
	require.Empty(t, owedOf(t, narrowed), "the grants just issued are not owed one")
	require.Empty(t, env.swarf.Revoked())
	env.awaitPublished(t)
	for _, d := range original {
		require.Contains(t, env.swarf.Revoked(), d.Link())
	}
	for _, d := range narrowed {
		require.NotContains(t, env.swarf.Revoked(), d.Link())
		require.NotContains(t, cids(original), d.Link())
	}

	// Write-locked to active: the full grants are back, issued afresh.
	env.swarf.holding.Store(true)
	env.setStatus(t, tenant.Active)
	restored := all(t, fullCommands)
	require.ElementsMatch(t, cids(narrowed), owedOf(t, narrowed))
	env.awaitPublished(t)
	for _, d := range narrowed {
		require.Contains(t, env.swarf.Revoked(), d.Link())
	}
	for _, d := range restored {
		require.NotContains(t, env.swarf.Revoked(), d.Link(), "a revoked grant is not issued again")
	}

	// Disabled to write-locked: the narrowed grants are issued.
	env.setStatus(t, tenant.Disabled)
	all(t, nil)
	env.setStatus(t, tenant.WriteLocked)
	narrowed = all(t, lockedCommands)
	env.awaitPublished(t)
	for _, d := range narrowed {
		require.NotContains(t, env.swarf.Revoked(), d.Link())
	}

	// Write-locked to disabled: none are left.
	env.swarf.holding.Store(true)
	env.setStatus(t, tenant.Disabled)
	all(t, nil)
	require.ElementsMatch(t, cids(narrowed), owedOf(t, narrowed))
	env.awaitPublished(t)
	for _, d := range narrowed {
		require.Contains(t, env.swarf.Revoked(), d.Link())
	}
}

// A key created, and a policy written, while the tenant is write-locked
// give the narrowed grants, and the full ones once the tenant is active.
func TestKeyAndPolicyForAWriteLockedTenant(t *testing.T) {
	env := setupLock(t)
	env.setStatus(t, tenant.WriteLocked)
	who := lockPrincipal

	// Keys created now hold the read alone, and one that may only upload
	// holds nothing.
	service := env.createKey(t, "service-2", []string{"s3:GetObject", "s3:PutObject"}, []string{lockBucket}, nil)
	bound := env.createKey(t, "bound-2", nil, nil, &who)
	uploader := env.createKey(t, "uploader", []string{"s3:PutObject"}, []string{lockBucket}, nil)
	require.Equal(t, lockedCommands, env.commands(t, service, env.bucket))
	require.Equal(t, lockedCommands, env.commands(t, bound, env.bucket))
	require.Empty(t, env.held(t, uploader))

	// A policy written now gives the principal's keys the grants of the
	// reads and deletions it allows, and none of the upload's alone.
	env.writePolicy(t, "s3:GetObject", "s3:PutObject", "s3:DeleteObject")
	kept := names(s3perm.CommandsFor("s3:GetObject", "s3:DeleteObject"))
	require.NotContains(t, kept, "/blob/abort")
	for _, key := range []ed25519.Signer{env.bound, bound} {
		require.Equal(t, kept, env.commands(t, key, env.bucket))
	}
	// A policy that allows the upload alone leaves them nothing.
	env.writePolicy(t, "s3:PutObject")
	for _, key := range []ed25519.Signer{env.bound, bound} {
		require.Empty(t, env.held(t, key))
	}
	env.writePolicy(t, "s3:GetObject", "s3:PutObject", "s3:DeleteObject")

	env.setStatus(t, tenant.Active)
	require.Equal(t, fullCommands, env.commands(t, service, env.bucket))
	require.Equal(t, fullCommands, env.commands(t, uploader, env.bucket))
	for _, key := range []ed25519.Signer{env.bound, bound} {
		require.Equal(t, fullCommands, env.commands(t, key, env.bucket))
	}
}

// A request that arrives while a write-lock is queued or running waits for
// it, and is answered as a write-locked tenant's.
func TestAuthorizeWhileAWriteLockIsPending(t *testing.T) {
	env := setupLock(t)
	ctx := t.Context()
	_, _, err := env.authorize(t, env.service, "PUT", "/"+lockBucket+"/object-key")
	require.NoError(t, err, "an active tenant uploads")

	entered, release := env.queueTenants.pause()
	changed := make(chan error, 1)
	go func() { changed <- env.svc.SetStatus(ctx, "tenant-1", "write-locked") }()
	select {
	case <-entered:
	case err := <-changed:
		t.Fatalf("the status change returned without running its task: %v", err)
	case <-time.After(htestutil.WaitTimeout):
		t.Fatal("the status change did not start")
	}

	type answer struct {
		ok  *s3req.AuthorizeOK
		err error
	}
	ask := func(method string) chan answer {
		out := make(chan answer, 1)
		go func() {
			ok, _, err := env.authorize(t, env.service, method, "/"+lockBucket+"/object-key")
			out <- answer{ok, err}
		}()
		return out
	}
	put, get := ask("PUT"), ask("GET")
	select {
	case a := <-put:
		t.Fatalf("the upload was answered while the change was pending: %v", a.err)
	case a := <-get:
		t.Fatalf("the read was answered while the change was pending: %v", a.err)
	case err := <-changed:
		t.Fatalf("the status change returned while its task was held: %v", err)
	case <-time.After(htestutil.MinBlock):
	}
	close(release)
	select {
	case err := <-changed:
		require.NoError(t, err)
	case <-time.After(htestutil.WaitTimeout):
		t.Fatal("the status change did not finish")
	}
	for name, asked := range map[string]chan answer{"PUT": put, "GET": get} {
		select {
		case a := <-asked:
			if name == "PUT" {
				require.ErrorIs(t, a.err, auth.ErrTenantWriteLocked)
				continue
			}
			require.NoError(t, a.err)
			require.Equal(t, []string{"s3:GetObject"}, a.ok.Permissions.Entries[env.service.KeyDID()])
		case <-time.After(htestutil.WaitTimeout):
			t.Fatalf("the %s was not answered once the change finished", name)
		}
	}
	require.Equal(t, lockedCommands, env.commands(t, env.service, env.bucket))
}

// The bucket commands report a key's permissions and hand the gateway its
// proof chains, so they answer for the tenant's status as authorization does.
func TestBucketCommandsUnderATenantStatus(t *testing.T) {
	kept := []string{"s3:ListAllMyBuckets", "s3:GetObject", "s3:DeleteObject"}
	create := func(t *testing.T, env *lockEnv, name string) (*s3req.AuthorizeOK, []ucan.Delegation, error) {
		t.Helper()
		return env.bucketSvc.Create(t.Context(), env.provider, &s3bkt.CreateArguments{
			Request: signedArgs(t, env.admin, "PUT", "https://s3.fil.one/"+name, lockRegion).Request,
		})
	}
	info := func(t *testing.T, env *lockEnv, key ed25519.Signer) (*s3bkt.InfoOK, error) {
		t.Helper()
		ok, _, err := env.bucketSvc.Info(t.Context(), env.provider, &s3bkt.InfoArguments{Name: lockBucket, AccessKey: key.KeyDID()})
		return ok, err
	}

	t.Run("a write-locked tenant creates no bucket", func(t *testing.T) {
		env := setupLock(t)
		env.setStatus(t, tenant.WriteLocked)

		_, _, err := create(t, env, "new-bucket")

		require.ErrorIs(t, err, auth.ErrTenantWriteLocked)
		_, err = env.buckets.GetByName(t.Context(), "new-bucket")
		require.ErrorIs(t, err, store.ErrRecordNotFound)
		require.Zero(t, env.sprue.provisioned.Load())

		env.setStatus(t, tenant.Active)
		ok, _, err := create(t, env, "new-bucket")
		require.NoError(t, err)
		require.Equal(t, adminPermissions, ok.Permissions.Entries[env.admin.KeyDID()])
	})

	t.Run("a write-locked tenant lists its buckets", func(t *testing.T) {
		env := setupLock(t)
		env.setStatus(t, tenant.WriteLocked)
		ok, err := env.bucketSvc.List(t.Context(), env.provider, &s3bkt.ListArguments{
			Request: signedArgs(t, env.admin, "GET", "https://s3.fil.one/", lockRegion).Request,
		})
		require.NoError(t, err)
		require.Len(t, ok.Buckets, 1)
	})

	t.Run("bucket info reports the permissions the status keeps", func(t *testing.T) {
		env := setupLock(t)
		ok, err := info(t, env, env.admin)
		require.NoError(t, err)
		require.Equal(t, adminPermissions, ok.Permissions.Entries[env.admin.KeyDID()])
		full := len(ok.Delegations.Entries)

		env.setStatus(t, tenant.WriteLocked)
		ok, err = info(t, env, env.admin)
		require.NoError(t, err)
		require.Equal(t, kept, ok.Permissions.Entries[env.admin.KeyDID()])
		// The admin key may delete, so its narrowed grants are a delete's:
		// every command of an upload but /blob/abort.
		require.Len(t, ok.Delegations.Entries, full-1)
		for name, key := range map[string]ed25519.Signer{"service": env.service, "bound": env.bound} {
			ok, err = info(t, env, key)
			require.NoError(t, err, name)
			require.Equal(t, []string{"s3:GetObject"}, ok.Permissions.Entries[key.KeyDID()], name)
			require.Len(t, ok.Delegations.Entries, 1, name)
		}

		env.setStatus(t, tenant.Disabled)
		ok, err = info(t, env, env.admin)
		require.NoError(t, err)
		require.Empty(t, ok.Permissions.Entries[env.admin.KeyDID()])
		require.Empty(t, ok.Delegations.Entries)

		env.setStatus(t, tenant.Active)
		ok, err = info(t, env, env.admin)
		require.NoError(t, err)
		require.Equal(t, adminPermissions, ok.Permissions.Entries[env.admin.KeyDID()])
		require.Len(t, ok.Delegations.Entries, full)
	})

	// A write-lock that commits while a bucket command is between its reads
	// never pairs the narrowed grants, which carry commands an upload uses
	// too, with the permissions of an active tenant.
	t.Run("bucket info that straddles a write-lock reports the kept permissions", func(t *testing.T) {
		env := setupLock(t)
		env.listed.then = func() { env.setStatus(t, tenant.WriteLocked) }
		ok, err := info(t, env, env.admin)
		require.NoError(t, err)
		require.Equal(t, kept, ok.Permissions.Entries[env.admin.KeyDID()])
	})

	t.Run("a bucket creation that straddles a write-lock reports the kept permissions", func(t *testing.T) {
		env := setupLock(t)
		env.listed.then = func() { env.setStatus(t, tenant.WriteLocked) }
		ok, _, err := create(t, env, "new-bucket")
		require.NoError(t, err, "the creation was authorized while the tenant was active")
		require.Equal(t, kept, ok.Permissions.Entries[env.admin.KeyDID()])
	})
}

// A write-lock, or its lifting, that commits between the authorizer's read
// of the status and the reads that follow it.
func TestAuthorizeAcrossAWriteLock(t *testing.T) {
	object := "/" + lockBucket + "/object-key"

	t.Run("read as write-locked, then active: answered as write-locked", func(t *testing.T) {
		env := setupLock(t)
		env.setStatus(t, tenant.WriteLocked)
		env.authTenants.then = func() { env.setStatus(t, tenant.Active) }

		_, _, err := env.authorize(t, env.service, "PUT", object)

		require.ErrorIs(t, err, auth.ErrTenantWriteLocked)
		_, _, err = env.authorize(t, env.service, "PUT", object)
		require.NoError(t, err, "the next request reads the new status")
	})

	t.Run("read as write-locked, then disabled: what the key delegates has no chain", func(t *testing.T) {
		env := setupLock(t)
		env.setStatus(t, tenant.WriteLocked)
		env.authTenants.then = func() { env.setStatus(t, tenant.Disabled) }

		ok, issued, err := env.authorize(t, env.service, "GET", object)

		require.NoError(t, err)
		require.Equal(t, []string{"s3:GetObject"}, ok.Permissions.Entries[env.service.KeyDID()])
		require.Empty(t, env.held(t, env.service))
		for _, d := range issuedBy(issued, env.service.KeyDID()) {
			chain, _, err := env.delegations.ProofChain(t.Context(), env.service.KeyDID(), d.Command(), env.bucket)
			require.NoError(t, err)
			require.Empty(t, chain)
		}
	})

	// The order of the reads does not narrow this one: the request is
	// answered as the active tenant's it was when its status was read, with
	// the full permission set, although the key's stored grants are the
	// narrowed ones by the time the answer leaves.
	t.Run("read as active, then write-locked: answered as active", func(t *testing.T) {
		env := setupLock(t)
		env.authTenants.then = func() { env.setStatus(t, tenant.WriteLocked) }

		ok, _, err := env.authorize(t, env.service, "PUT", object)

		require.NoError(t, err)
		require.Equal(t, []string{"s3:GetObject", "s3:PutObject"}, ok.Permissions.Entries[env.service.KeyDID()])
		require.Equal(t, lockedCommands, env.commands(t, env.service, env.bucket), "the change committed before the answer")

		_, _, err = env.authorize(t, env.service, "PUT", object)
		require.ErrorIs(t, err, auth.ErrTenantWriteLocked, "the next request reads the new status")
	})
}
