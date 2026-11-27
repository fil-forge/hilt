package accesskey_test

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	s3bkt "github.com/fil-forge/libforge/commands/s3/bucket"

	"github.com/fil-forge/hilt/internal/testutil"
	accesskeysvc "github.com/fil-forge/hilt/pkg/api/service/accesskey"
	"github.com/fil-forge/hilt/pkg/s3perm"
	"github.com/fil-forge/hilt/pkg/store"
	accesskeystore "github.com/fil-forge/hilt/pkg/store/accesskey"
	accesskeypostgres "github.com/fil-forge/hilt/pkg/store/accesskey/postgres"
	"github.com/fil-forge/hilt/pkg/store/bucket"
	bucketpostgres "github.com/fil-forge/hilt/pkg/store/bucket/postgres"
	delegationstore "github.com/fil-forge/hilt/pkg/store/delegation"
	delegationpostgres "github.com/fil-forge/hilt/pkg/store/delegation/postgres"
	"github.com/fil-forge/hilt/pkg/store/principal"
	principalpostgres "github.com/fil-forge/hilt/pkg/store/principal/postgres"
	providerpostgres "github.com/fil-forge/hilt/pkg/store/provider/postgres"
	"github.com/fil-forge/hilt/pkg/store/revocation"
	revocationpostgres "github.com/fil-forge/hilt/pkg/store/revocation/postgres"
	"github.com/fil-forge/hilt/pkg/store/tenant"
	tenantpostgres "github.com/fil-forge/hilt/pkg/store/tenant/postgres"
	"github.com/fil-forge/hilt/pkg/tasks"
	"github.com/fil-forge/hilt/pkg/tasks/tenantqueue"
	"github.com/fil-forge/hilt/pkg/vault"
	vaultmemory "github.com/fil-forge/hilt/pkg/vault/memory"
	"github.com/fil-forge/libforge/taskrunner"
	"github.com/fil-forge/ucantone/did"
	"github.com/fil-forge/ucantone/multikey"
	"github.com/fil-forge/ucantone/multikey/ed25519"
	"github.com/fil-forge/ucantone/multikey/secp256k1"
	"github.com/fil-forge/ucantone/ucan"
	"github.com/fil-forge/ucantone/ucan/command"
	"github.com/fil-forge/ucantone/ucan/delegation"
	"github.com/ipfs/go-cid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/multiformats/go-multibase"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

// heldSwarf is a revocation service that refuses every publish while holding
// is set, so a test can look at the revocations owed before they are
// published.
type heldSwarf struct {
	testutil.FakeSwarf
	holding atomic.Bool
}

func (h *heldSwarf) PublishBatch(ctx context.Context, revoker ucan.Issuer, revoked []ucan.Delegation) error {
	if h.holding.Load() {
		return errors.New("revocation service unavailable")
	}
	return h.FakeSwarf.PublishBatch(ctx, revoker, revoked)
}

// recordingVault records the access-key entries written to it, and runs
// onKeyWrite after each such write.
type recordingVault struct {
	vault.Vault
	onKeyWrite func()

	mu   sync.Mutex
	keys []string
}

func (v *recordingVault) Write(ctx context.Context, key string, value []byte) error {
	if err := v.Vault.Write(ctx, key, value); err != nil {
		return err
	}
	if strings.Contains(key, "/access-key/") {
		v.mu.Lock()
		v.keys = append(v.keys, key)
		v.mu.Unlock()
		if v.onKeyWrite != nil {
			v.onKeyWrite()
		}
	}
	return nil
}

// remaining returns the access-key entries written that the vault still
// holds.
func (v *recordingVault) remaining(t *testing.T) []string {
	t.Helper()
	v.mu.Lock()
	defer v.mu.Unlock()
	var out []string
	for _, key := range v.keys {
		_, err := v.Vault.Read(t.Context(), key)
		if errors.Is(err, vault.ErrNotFound) {
			continue
		}
		require.NoError(t, err)
		out = append(out, key)
	}
	return out
}

// disablingTenants disables each tenant right after it is looked up by its
// external ID, as the service does and the task does not, so the task finds
// the tenant disabled after the service's own check passed.
type disablingTenants struct{ tenant.Store }

func (s disablingTenants) GetByExternalID(ctx context.Context, externalID string) (tenant.Record, error) {
	rec, err := s.Store.GetByExternalID(ctx, externalID)
	if err == nil {
		err = s.SetStatus(ctx, rec.ID, tenant.Disabled)
	}
	return rec, err
}

// removingPrincipals removes each principal right after the service looks it
// up, so the task finds it gone.
type removingPrincipals struct {
	principal.Store
	pool *pgxpool.Pool
}

func (s removingPrincipals) Get(ctx context.Context, tenantID did.DID, id string) (principal.Record, error) {
	rec, err := s.Store.Get(ctx, tenantID, id)
	if err == nil {
		st := s.TombstoneStatement(tenantID, id)
		_, err = s.pool.Exec(ctx, st.SQL, st.Args...)
	}
	return rec, err
}

// deletingBuckets deletes each bucket the service resolves by name right
// after it is resolved, so the task finds it gone.
type deletingBuckets struct{ bucket.Store }

func (s deletingBuckets) ListByTenant(ctx context.Context, tenantID did.DID, opts ...bucket.ListOption) (store.Page[bucket.Record], error) {
	page, err := s.Store.ListByTenant(ctx, tenantID, opts...)
	if err != nil {
		return page, err
	}
	for _, rec := range page.Results {
		if err := s.Delete(ctx, rec.ID); err != nil {
			return page, err
		}
	}
	return page, nil
}

type deps struct {
	svc         *accesskeysvc.Service
	pool        *pgxpool.Pool
	runner      *taskrunner.Runner
	tenants     tenant.Store
	accessKeys  accesskeystore.Store
	principals  principal.Store
	delegations delegationstore.Store
	owed        revocation.Store
	buckets     bucket.Store
	secrets     *recordingVault
	swarf       *heldSwarf
	tenantID    did.DID
	bucketID    did.DID
	bucketRoot  ucan.Delegation
}

// setup is setupWith over a fresh database.
func setup(t *testing.T) deps {
	t.Helper()
	return setupWith(t, newBackend(t))
}

// newBackend builds the stores the service reads through over a fresh
// database, and registers the provider the tenant's bucket is placed with.
func newBackend(t *testing.T) backend {
	t.Helper()
	pool := testutil.PostgresOrSkip(t)
	providerID := testutil.RandomDID(t)
	require.NoError(t, providerpostgres.New(pool).Add(t.Context(), providerID, "region-1", nil))
	return backend{
		pool:    pool,
		tenants: tenantpostgres.New(pool), principals: principalpostgres.New(pool), buckets: bucketpostgres.New(pool),
		providerID: providerID,
	}
}

// backend is the database, the stores the service is built over, which a
// test may wrap, and the provider the tenant is placed with. The tasks the
// service submits always work through the plain stores, unless wrapQueue
// replaces one.
type backend struct {
	pool       *pgxpool.Pool
	tenants    tenant.Store
	principals principal.Store
	buckets    bucket.Store
	providerID did.DID
	// wrapQueue, when set, replaces what queue-tenant's handlers work
	// through.
	wrapQueue func(*tenantqueue.Deps)
}

// setupWith wires the service over b, with the task runner its creations and
// deletions run on, and one tenant ("tenant-1") whose secp256k1 key is in the
// vault, owning one bucket ("bucket-a") that has issued the tenant top
// authority over itself: the root of every proof chain through the bucket, as
// [bucket.Service.Create] would have stored it. Its audience is the tenant,
// not an access key, so it must never be revoked along with one. The tenant
// has one principal, "alice".
func setupWith(t *testing.T, b backend) deps {
	t.Helper()
	ctx := t.Context()
	pool := b.pool
	tenants, accessKeys, principals := tenantpostgres.New(pool), accesskeypostgres.New(pool), principalpostgres.New(pool)
	buckets, delegations := bucketpostgres.New(pool), delegationpostgres.New(pool)
	secrets := &recordingVault{Vault: vaultmemory.New()}

	signer, err := secp256k1.Generate()
	require.NoError(t, err)
	tenantID := signer.KeyDID()
	require.NoError(t, tenants.Add(ctx, tenantID, "tenant-1", tenant.Active))
	require.NoError(t, secrets.Write(ctx, vault.TenantKeyPath(tenantID), signer.Bytes()))
	require.NoError(t, principals.Add(ctx, tenantID, "alice"))

	// The bucket key is ephemeral: it signs the bucket→tenant root and is discarded.
	bucketSigner, err := ed25519.Generate()
	require.NoError(t, err)
	bucketID := bucketSigner.KeyDID()
	require.NoError(t, buckets.Add(ctx, bucketID, tenantID, b.providerID, "bucket-a"))
	root, err := delegation.Delegate(
		multikey.NewIssuer(bucketID, bucketSigner), tenantID, bucketID, command.Top(), delegation.WithNoExpiration())
	require.NoError(t, err)
	require.NoError(t, delegations.PutBatch(ctx, []ucan.Delegation{root}))
	// alice may read bucket-a; her keys hold the matching delegations.
	testutil.PutPolicy(t, pool, tenantID, bucketID, s3bkt.PolicyDocument{
		Version: s3bkt.Version2012, Statements: []s3bkt.Statement{{Effect: s3bkt.Allow, Principal: s3bkt.Only("alice"), Actions: s3bkt.NewStringSet("s3:GetObject"), Resources: s3bkt.NewStringSet(s3bkt.BucketARN("photos"), s3bkt.ObjectsARN("photos"))}},
	})

	swarf := &heldSwarf{}
	var wrap []func(*tenantqueue.Deps)
	if b.wrapQueue != nil {
		wrap = append(wrap, b.wrapQueue)
	}
	runner := testutil.StartServiceTasks(t, pool, secrets, swarf, wrap...)
	return deps{
		svc:         accesskeysvc.New(zap.NewNop(), b.tenants, accessKeys, b.principals, b.buckets, secrets, runner),
		pool:        pool,
		runner:      runner,
		tenants:     tenants,
		accessKeys:  accessKeys,
		principals:  principals,
		delegations: delegations,
		owed:        revocationpostgres.New(pool),
		buckets:     buckets,
		secrets:     secrets,
		swarf:       swarf,
		tenantID:    tenantID,
		bucketID:    bucketID,
		bucketRoot:  root,
	}
}

// held returns the delegations stored for the audience.
func (d deps) held(t *testing.T, audience did.DID) []ucan.Delegation {
	t.Helper()
	page, err := d.delegations.ListByAudience(t.Context(), audience)
	require.NoError(t, err)
	require.Nil(t, page.Cursor, "one page holds everything a test stores")
	return page.Results
}

// owedLinks returns the CIDs of the revocations the tenant owes.
func (d deps) owedLinks(t *testing.T) []cid.Cid {
	t.Helper()
	dels, err := d.owed.Oldest(t.Context(), d.tenantID, 10_000)
	require.NoError(t, err)
	return links(dels)
}

// requireNothingCreated requires that the tenant has no access key, that no
// delegation is stored for anything but the tenant's bucket root, and that
// the vault holds no access-key entry.
func (d deps) requireNothingCreated(t *testing.T) {
	t.Helper()
	keys, err := d.accessKeys.ListByTenant(t.Context(), d.tenantID)
	require.NoError(t, err)
	require.Empty(t, keys, "no access key record is left")
	var stored int
	require.NoError(t, d.pool.QueryRow(t.Context(), `SELECT count(*) FROM delegation WHERE audience <> $1`, d.tenantID.String()).Scan(&stored))
	require.Zero(t, stored, "no delegation is left")
	require.Empty(t, d.secrets.remaining(t), "no vault entry is left")
}

// taskArgs returns the stored arguments and result of every task queue-tenant
// has recorded for the action.
func (d deps) taskRows(t *testing.T, action string) [][2][]byte {
	t.Helper()
	rows, err := d.pool.Query(t.Context(), `SELECT args, result FROM `+taskrunner.TasksTable(tasks.Schema, tasks.QueueTenant)+` WHERE action = $1`, action)
	require.NoError(t, err)
	defer rows.Close()
	var out [][2][]byte
	for rows.Next() {
		var args, result []byte
		require.NoError(t, rows.Scan(&args, &result))
		out = append(out, [2][]byte{args, result})
	}
	require.NoError(t, rows.Err())
	return out
}

func links(dels []ucan.Delegation) []cid.Cid {
	out := make([]cid.Cid, len(dels))
	for i, d := range dels {
		out[i] = d.Link()
	}
	return out
}

func TestCreate(t *testing.T) {
	ctx := t.Context()

	t.Run("creates a bucket-scoped key", func(t *testing.T) {
		d := setup(t)
		before := time.Now()
		rec, secret, err := d.svc.Create(ctx, "tenant-1", "k1", []string{"s3:GetObject"}, []string{"bucket-a"}, nil, nil)
		require.NoError(t, err)
		require.NotEmpty(t, secret)
		require.Equal(t, "k1", rec.Name)
		require.Equal(t, []did.DID{d.bucketID}, rec.Buckets)
		require.WithinDuration(t, before, rec.CreatedAt, time.Minute)

		// The record returned is the one stored.
		stored, err := d.accessKeys.Get(ctx, rec.ID)
		require.NoError(t, err)
		require.True(t, rec.CreatedAt.Equal(stored.CreatedAt), "returned %s, stored %s", rec.CreatedAt, stored.CreatedAt)
		stored.CreatedAt = rec.CreatedAt
		require.Equal(t, rec, stored)

		// The secret returned is the key in the vault, and it is the key the
		// record names.
		raw, err := d.secrets.Read(ctx, vault.AccessKeyPath(d.tenantID, rec.ID))
		require.NoError(t, err)
		signer, err := ed25519.Decode(raw)
		require.NoError(t, err)
		require.Equal(t, rec.ID, signer.KeyDID())
		_, fromSecret, err := multibase.Decode(secret)
		require.NoError(t, err)
		require.Equal(t, raw, fromSecret)

		// It holds one tenant → key delegation per Forge command its
		// permission maps to, over its bucket.
		var got, want []string
		for _, dlg := range d.held(t, rec.ID) {
			require.Equal(t, d.tenantID, dlg.Issuer())
			require.Equal(t, d.bucketID, dlg.Subject())
			got = append(got, dlg.Command().String())
		}
		for _, cmd := range s3perm.CommandsFor("s3:GetObject") {
			want = append(want, cmd.String())
		}
		require.ElementsMatch(t, want, got)
		require.Empty(t, d.swarf.Revocations(), "a creation revokes nothing")
	})

	t.Run("rejects an empty name", func(t *testing.T) {
		d := setup(t)
		_, _, err := d.svc.Create(ctx, "tenant-1", "", []string{"s3:GetObject"}, nil, nil, nil)
		require.ErrorIs(t, err, accesskeysvc.ErrInvalidName)
		d.requireNothingCreated(t)
	})

	t.Run("rejects no permissions", func(t *testing.T) {
		d := setup(t)
		_, _, err := d.svc.Create(ctx, "tenant-1", "k1", nil, nil, nil, nil)
		require.ErrorIs(t, err, accesskeysvc.ErrNoPermissions)
		d.requireNothingCreated(t)
	})

	t.Run("rejects an unknown permission", func(t *testing.T) {
		d := setup(t)
		_, _, err := d.svc.Create(ctx, "tenant-1", "k1", []string{"s3:Bogus"}, nil, nil, nil)
		require.ErrorIs(t, err, accesskeysvc.ErrInvalidPermission)
		d.requireNothingCreated(t)
	})

	t.Run("rejects an unknown bucket", func(t *testing.T) {
		d := setup(t)
		_, _, err := d.svc.Create(ctx, "tenant-1", "k1", []string{"s3:GetObject"}, []string{"nope"}, nil, nil)
		require.ErrorIs(t, err, accesskeysvc.ErrUnknownBucket)
		d.requireNothingCreated(t)
	})

	t.Run("rejects an unknown tenant", func(t *testing.T) {
		d := setup(t)
		_, _, err := d.svc.Create(ctx, "missing", "k1", []string{"s3:GetObject"}, nil, nil, nil)
		require.ErrorIs(t, err, accesskeysvc.ErrTenantNotFound)
	})

	for _, key := range []struct {
		name      string
		perms     []string
		principal *string
	}{
		{"service key", []string{"s3:GetObject"}, nil},
		{"principal-bound key", nil, new("alice")},
	} {
		t.Run("refuses a "+key.name+" for a disabled tenant", func(t *testing.T) {
			d := setup(t)
			require.NoError(t, d.tenants.SetStatus(ctx, d.tenantID, tenant.Disabled))
			_, _, err := d.svc.Create(ctx, "tenant-1", "k1", key.perms, nil, key.principal, nil)
			require.ErrorIs(t, err, accesskeysvc.ErrTenantDisabled)
			d.requireNothingCreated(t)
		})

		t.Run("refuses a "+key.name+" for a tenant disabled after the lookup", func(t *testing.T) {
			// The service's own check passes, so the refusal is the task's.
			b := newBackend(t)
			b.tenants = disablingTenants{b.tenants}
			d := setupWith(t, b)
			_, _, err := d.svc.Create(ctx, "tenant-1", "k1", key.perms, nil, key.principal, nil)
			require.ErrorIs(t, err, accesskeysvc.ErrTenantDisabled)
			require.Len(t, d.secrets.keys, 1, "the secret was written before the task refused")
			d.requireNothingCreated(t)
		})
	}

	t.Run("rejects a bucket deleted after it was resolved, naming it", func(t *testing.T) {
		b := newBackend(t)
		b.buckets = deletingBuckets{b.buckets}
		d := setupWith(t, b)
		_, _, err := d.svc.Create(ctx, "tenant-1", "k1", []string{"s3:GetObject"}, []string{"bucket-a"}, nil, nil)
		require.ErrorIs(t, err, accesskeysvc.ErrUnknownBucket)
		require.ErrorContains(t, err, "bucket-a")
		require.Len(t, d.secrets.keys, 1, "the secret was written before the task refused")
		d.requireNothingCreated(t)
	})

	t.Run("rejects a duplicate name", func(t *testing.T) {
		d := setup(t)
		first, _, err := d.svc.Create(ctx, "tenant-1", "dup", []string{"s3:GetObject"}, nil, nil, nil)
		require.NoError(t, err)
		_, _, err = d.svc.Create(ctx, "tenant-1", "dup", []string{"s3:GetObject"}, nil, nil, nil)
		require.ErrorIs(t, err, accesskeysvc.ErrNameConflict)

		keys, err := d.accessKeys.ListByTenant(ctx, d.tenantID)
		require.NoError(t, err)
		require.Len(t, keys, 1)
		require.Equal(t, []string{vault.AccessKeyPath(d.tenantID, first.ID)}, d.secrets.remaining(t), "the refused key's secret is gone")
		var audiences int
		require.NoError(t, d.pool.QueryRow(ctx, `SELECT count(DISTINCT audience) FROM delegation WHERE audience <> $1`, d.tenantID.String()).Scan(&audiences))
		require.Equal(t, 1, audiences, "only the first key holds delegations")
	})

	t.Run("two creations of one name at once yield one key and one conflict", func(t *testing.T) {
		d := setup(t)
		const callers = 4
		errs := make(chan error, callers)
		for range callers {
			go func() {
				_, _, err := d.svc.Create(ctx, "tenant-1", "same", []string{"s3:GetObject"}, nil, nil, nil)
				errs <- err
			}()
		}
		var created int
		for range callers {
			if err := <-errs; err == nil {
				created++
			} else {
				require.ErrorIs(t, err, accesskeysvc.ErrNameConflict)
			}
		}
		require.Equal(t, 1, created)
		keys, err := d.accessKeys.ListByTenant(ctx, d.tenantID)
		require.NoError(t, err)
		require.Len(t, keys, 1)
		require.Equal(t, []string{vault.AccessKeyPath(d.tenantID, keys[0].ID)}, d.secrets.remaining(t))
		require.Len(t, d.held(t, keys[0].ID), len(s3perm.CommandsFor("s3:GetObject")))
	})

	t.Run("the task's stored arguments and result hold no secret", func(t *testing.T) {
		d := setup(t)
		exp := time.Now().Add(time.Hour)
		rec, secret, err := d.svc.Create(ctx, "tenant-1", "k1", []string{"s3:GetObject"}, []string{"bucket-a"}, nil, &exp)
		require.NoError(t, err)
		_, _, err = d.svc.Create(ctx, "tenant-1", "laptop", nil, nil, new("alice"), nil)
		require.NoError(t, err)
		raw, err := d.secrets.Read(ctx, vault.AccessKeyPath(d.tenantID, rec.ID))
		require.NoError(t, err)
		tenantKey, err := d.secrets.Read(ctx, vault.TenantKeyPath(d.tenantID))
		require.NoError(t, err)

		rows := d.taskRows(t, tasks.ActionCreateKey)
		require.Len(t, rows, 2)
		var sawKey bool
		for _, row := range rows {
			args, result := row[0], row[1]
			require.Empty(t, result)
			sawKey = sawKey || bytes.Contains(args, []byte(rec.ID.String()))
			for _, stored := range [][]byte{args, result} {
				require.NotContains(t, string(stored), secret)
				require.NotContains(t, string(stored), secret[1:], "the secret without its multibase prefix")
				require.False(t, bytes.Contains(stored, raw), "the key's private bytes")
				// The private key's seed is the tail of the stored bytes,
				// whatever prefix the encoding puts before it.
				require.False(t, bytes.Contains(stored, raw[len(raw)-32:]), "the key's seed")
				require.False(t, bytes.Contains(stored, tenantKey), "the tenant's private bytes")
			}
			// What the arguments do hold is the key as the handler reads it.
			key, err := tenantqueue.DecodeCreateKey(d.tenantID, args)
			require.NoError(t, err)
			require.Contains(t, []string{"k1", "laptop"}, key.Name)
		}
		require.True(t, sawKey, "the arguments name the key by its DID")
	})

	t.Run("a caller that goes away once the secret is written still gets a whole key", func(t *testing.T) {
		d := setup(t)
		gone, cancel := context.WithCancel(ctx)
		defer cancel()
		d.secrets.onKeyWrite = cancel
		rec, secret, err := d.svc.Create(gone, "tenant-1", "k1", []string{"s3:GetObject"}, nil, nil, nil)
		require.NoError(t, err)
		require.NotEmpty(t, secret)
		require.Error(t, gone.Err(), "the caller's context ended during the call")
		_, err = d.accessKeys.Get(ctx, rec.ID)
		require.NoError(t, err)
		require.NotEmpty(t, d.held(t, rec.ID))
		require.Equal(t, []string{vault.AccessKeyPath(d.tenantID, rec.ID)}, d.secrets.remaining(t))
	})

	t.Run("a creation still waiting at the caller's deadline is abandoned with nothing written", func(t *testing.T) {
		// The first creation holds the tenant's queue: its task blocks where
		// it reads the tenant.
		b := newBackend(t)
		entered, release := make(chan struct{}), make(chan struct{})
		b.wrapQueue = func(deps *tenantqueue.Deps) {
			deps.Tenants = &blockingTenants{Store: deps.Tenants, entered: entered, release: release}
		}
		d := setupWith(t, b)
		first := make(chan error, 1)
		go func() {
			_, _, err := d.svc.Create(ctx, "tenant-1", "first", []string{"s3:GetObject"}, nil, nil, nil)
			first <- err
		}()
		select {
		case <-entered:
		case err := <-first:
			t.Fatalf("the first creation returned before its task ran: %v", err)
		case <-time.After(testutil.WaitTimeout):
			t.Fatal("the first creation's task did not start")
		}

		short, cancel := context.WithTimeout(ctx, testutil.MinBlock)
		defer cancel()
		_, _, err := d.svc.Create(short, "tenant-1", "second", []string{"s3:GetObject"}, nil, nil, nil)
		require.ErrorIs(t, err, accesskeysvc.ErrConcurrentChange)

		close(release)
		require.NoError(t, <-first)
		keys, err := d.accessKeys.ListByTenant(ctx, d.tenantID)
		require.NoError(t, err)
		require.Len(t, keys, 1)
		require.Equal(t, "first", keys[0].Name)
		require.Equal(t, []string{vault.AccessKeyPath(d.tenantID, keys[0].ID)}, d.secrets.remaining(t), "the abandoned key's secret is gone")
	})
}

// blockingTenants blocks the first Get until release is closed, having
// closed entered.
type blockingTenants struct {
	tenant.Store
	entered chan struct{}
	release chan struct{}
	once    sync.Once
}

func (s *blockingTenants) Get(ctx context.Context, id did.DID) (tenant.Record, error) {
	s.once.Do(func() {
		close(s.entered)
		<-s.release
	})
	return s.Store.Get(ctx, id)
}

func TestCreatePrincipalBound(t *testing.T) {
	ctx := t.Context()

	t.Run("binds the key to the principal and issues what the policies grant it", func(t *testing.T) {
		d := setup(t)
		rec, secret, err := d.svc.Create(ctx, "tenant-1", "laptop", nil, nil, new("alice"), nil)
		require.NoError(t, err)
		require.NotEmpty(t, secret)
		require.Equal(t, "laptop", rec.Name)
		require.NotNil(t, rec.Principal)
		require.Equal(t, "alice", *rec.Principal)
		require.Empty(t, rec.Permissions)
		require.Empty(t, rec.Buckets)

		// The key holds one tenant → key delegation per Forge command the
		// policy's actions map to, over the bucket, living as long as the key.
		var got []string
		for _, m := range d.held(t, rec.ID) {
			require.Equal(t, d.tenantID, m.Issuer())
			require.Equal(t, rec.ID, m.Audience())
			require.Equal(t, d.bucketID, m.Subject())
			require.Nil(t, m.Expiration())
			got = append(got, m.Command().String())
		}
		var want []string
		for _, cmd := range s3perm.CommandsFor("s3:GetObject") {
			want = append(want, cmd.String())
		}
		require.ElementsMatch(t, want, got)
		// The key pair is stored where every access key's is.
		_, err = d.secrets.Read(ctx, vault.AccessKeyPath(d.tenantID, rec.ID))
		require.NoError(t, err)
	})

	t.Run("holds nothing when no policy names the principal", func(t *testing.T) {
		d := setup(t)
		require.NoError(t, d.principals.Add(ctx, d.tenantID, "bob"))
		rec, _, err := d.svc.Create(ctx, "tenant-1", "laptop", nil, nil, new("bob"), nil)
		require.NoError(t, err)
		issued, err := d.delegations.ListByAudience(ctx, rec.ID)
		require.NoError(t, err)
		require.Empty(t, issued.Results)
	})

	t.Run("persists an expiry", func(t *testing.T) {
		d := setup(t)
		exp := time.Now().Add(time.Hour).UTC().Truncate(time.Second)
		rec, _, err := d.svc.Create(ctx, "tenant-1", "laptop", nil, nil, new("alice"), &exp)
		require.NoError(t, err)
		require.NotNil(t, rec.ExpiresAt)
		require.True(t, exp.Equal(*rec.ExpiresAt))
		// The delegations expire with the key.
		issued, err := d.delegations.ListByAudience(ctx, rec.ID)
		require.NoError(t, err)
		require.NotEmpty(t, issued.Results)
		for _, m := range issued.Results {
			require.NotNil(t, m.Expiration())
			require.Equal(t, ucan.UnixTimestamp(exp.Unix()), *m.Expiration())
		}
	})

	t.Run("rejects permissions on a principal-bound key", func(t *testing.T) {
		d := setup(t)
		_, _, err := d.svc.Create(ctx, "tenant-1", "laptop", []string{"s3:GetObject"}, nil, new("alice"), nil)
		require.ErrorIs(t, err, accesskeysvc.ErrPrincipalScoped)
		d.requireNothingCreated(t)
	})

	t.Run("rejects buckets on a principal-bound key", func(t *testing.T) {
		d := setup(t)
		_, _, err := d.svc.Create(ctx, "tenant-1", "laptop", nil, []string{"bucket-a"}, new("alice"), nil)
		require.ErrorIs(t, err, accesskeysvc.ErrPrincipalScoped)
		d.requireNothingCreated(t)
	})

	t.Run("rejects an unknown principal", func(t *testing.T) {
		d := setup(t)
		_, _, err := d.svc.Create(ctx, "tenant-1", "laptop", nil, nil, new("ghost"), nil)
		require.ErrorIs(t, err, accesskeysvc.ErrUnknownPrincipal)
		d.requireNothingCreated(t)
	})

	t.Run("rejects a principal removed after the lookup", func(t *testing.T) {
		// The service's own check passes, so the refusal is the task's.
		b := newBackend(t)
		b.principals = removingPrincipals{Store: b.principals, pool: b.pool}
		d := setupWith(t, b)
		_, _, err := d.svc.Create(ctx, "tenant-1", "laptop", nil, nil, new("alice"), nil)
		require.ErrorIs(t, err, accesskeysvc.ErrUnknownPrincipal)
		require.Len(t, d.secrets.keys, 1, "the secret was written before the task refused")
		d.requireNothingCreated(t)
	})

	t.Run("rejects an empty name", func(t *testing.T) {
		d := setup(t)
		_, _, err := d.svc.Create(ctx, "tenant-1", "", nil, nil, new("alice"), nil)
		require.ErrorIs(t, err, accesskeysvc.ErrInvalidName)
	})

	t.Run("the name is unique within the principal and independent of service keys", func(t *testing.T) {
		d := setup(t)
		_, _, err := d.svc.Create(ctx, "tenant-1", "laptop", nil, nil, new("alice"), nil)
		require.NoError(t, err)
		_, _, err = d.svc.Create(ctx, "tenant-1", "laptop", nil, nil, new("alice"), nil)
		require.ErrorIs(t, err, accesskeysvc.ErrNameConflict)
		// A service key of the tenant may hold the same name.
		_, _, err = d.svc.Create(ctx, "tenant-1", "laptop", []string{"s3:GetObject"}, nil, nil, nil)
		require.NoError(t, err)
	})

	t.Run("delete removes the key and revokes its marker", func(t *testing.T) {
		d := setup(t)
		rec, _, err := d.svc.Create(ctx, "tenant-1", "laptop", nil, nil, new("alice"), nil)
		require.NoError(t, err)
		issued, err := d.delegations.ListByAudience(ctx, rec.ID)
		require.NoError(t, err)
		require.Len(t, issued.Results, 1)

		require.NoError(t, d.svc.Delete(ctx, "tenant-1", rec.ID.Identifier()))
		testutil.AwaitPublished(t, d.runner, d.tenantID)
		// The marker is the one delegation a revocation can name for the key.
		require.Len(t, d.swarf.Revocations(), 1)
		require.Equal(t, d.tenantID, d.swarf.Revocations()[0].Revoker)
		require.Equal(t, issued.Results[0].Link(), d.swarf.Revocations()[0].Revoked)
		remaining, err := d.delegations.ListByAudience(ctx, rec.ID)
		require.NoError(t, err)
		require.Empty(t, remaining.Results)
		_, _, err = d.svc.Get(ctx, "tenant-1", rec.ID.Identifier())
		require.ErrorIs(t, err, accesskeysvc.ErrAccessKeyNotFound)
		_, err = d.secrets.Read(ctx, vault.AccessKeyPath(d.tenantID, rec.ID))
		require.ErrorIs(t, err, vault.ErrNotFound)
	})

	t.Run("list and get return both kinds", func(t *testing.T) {
		d := setup(t)
		svcKey, _, err := d.svc.Create(ctx, "tenant-1", "ci", []string{"s3:GetObject"}, []string{"bucket-a"}, nil, nil)
		require.NoError(t, err)
		bound, _, err := d.svc.Create(ctx, "tenant-1", "laptop", nil, nil, new("alice"), nil)
		require.NoError(t, err)

		recs, names, err := d.svc.List(ctx, "tenant-1")
		require.NoError(t, err)
		require.Len(t, recs, 2)
		require.Equal(t, "bucket-a", names[d.bucketID])
		byID := map[string]*string{}
		for _, r := range recs {
			byID[r.ID.String()] = r.Principal
		}
		require.Nil(t, byID[svcKey.ID.String()])
		require.NotNil(t, byID[bound.ID.String()])

		got, _, err := d.svc.Get(ctx, "tenant-1", bound.ID.Identifier())
		require.NoError(t, err)
		require.Equal(t, "alice", *got.Principal)
	})
}

func TestListGetDelete(t *testing.T) {
	ctx := t.Context()

	t.Run("list returns the tenant's keys with bucket names", func(t *testing.T) {
		d := setup(t)
		_, _, err := d.svc.Create(ctx, "tenant-1", "k1", []string{"s3:GetObject"}, []string{"bucket-a"}, nil, nil)
		require.NoError(t, err)
		recs, names, err := d.svc.List(ctx, "tenant-1")
		require.NoError(t, err)
		require.Len(t, recs, 1)
		require.Equal(t, "bucket-a", names[d.bucketID])
	})

	t.Run("list rejects an unknown tenant", func(t *testing.T) {
		d := setup(t)
		_, _, err := d.svc.List(ctx, "missing")
		require.ErrorIs(t, err, accesskeysvc.ErrTenantNotFound)
	})

	t.Run("get returns a created key", func(t *testing.T) {
		d := setup(t)
		created, _, err := d.svc.Create(ctx, "tenant-1", "k1", []string{"s3:GetObject"}, nil, nil, nil)
		require.NoError(t, err)
		got, _, err := d.svc.Get(ctx, "tenant-1", created.ID.Identifier())
		require.NoError(t, err)
		require.Equal(t, created.ID, got.ID)
	})

	t.Run("get rejects an unknown access key", func(t *testing.T) {
		d := setup(t)
		_, _, err := d.svc.Get(ctx, "tenant-1", testutil.RandomDID(t).Identifier())
		require.ErrorIs(t, err, accesskeysvc.ErrAccessKeyNotFound)
	})

	t.Run("delete removes a key", func(t *testing.T) {
		d := setup(t)
		created, _, err := d.svc.Create(ctx, "tenant-1", "k1", []string{"s3:GetObject"}, nil, nil, nil)
		require.NoError(t, err)
		require.NoError(t, d.svc.Delete(ctx, "tenant-1", created.ID.Identifier()))
		_, _, err = d.svc.Get(ctx, "tenant-1", created.ID.Identifier())
		require.ErrorIs(t, err, accesskeysvc.ErrAccessKeyNotFound)
	})

	t.Run("a second delete finds no key and changes nothing", func(t *testing.T) {
		d := setup(t)
		created, _, err := d.svc.Create(ctx, "tenant-1", "k1", []string{"s3:GetObject"}, nil, nil, nil)
		require.NoError(t, err)
		other, _, err := d.svc.Create(ctx, "tenant-1", "k2", []string{"s3:GetObject"}, nil, nil, nil)
		require.NoError(t, err)
		require.NoError(t, d.svc.Delete(ctx, "tenant-1", created.ID.Identifier()))
		testutil.AwaitPublished(t, d.runner, d.tenantID)
		revoked := d.swarf.Revoked()

		require.ErrorIs(t, d.svc.Delete(ctx, "tenant-1", created.ID.Identifier()), accesskeysvc.ErrAccessKeyNotFound)
		testutil.AwaitPublished(t, d.runner, d.tenantID)
		require.Equal(t, revoked, d.swarf.Revoked())
		require.NotEmpty(t, d.held(t, other.ID), "the tenant's other key keeps its grants")
	})

	t.Run("delete rejects another tenant's access key", func(t *testing.T) {
		d := setup(t)
		created, _, err := d.svc.Create(ctx, "tenant-1", "k1", []string{"s3:GetObject"}, nil, nil, nil)
		require.NoError(t, err)
		require.NoError(t, d.tenants.Add(ctx, testutil.RandomDID(t), "tenant-2", tenant.Active))
		require.ErrorIs(t, d.svc.Delete(ctx, "tenant-2", created.ID.Identifier()), accesskeysvc.ErrAccessKeyNotFound)
		_, err = d.accessKeys.Get(ctx, created.ID)
		require.NoError(t, err)
	})

	t.Run("delete rejects an unknown access key", func(t *testing.T) {
		d := setup(t)
		err := d.svc.Delete(ctx, "tenant-1", testutil.RandomDID(t).Identifier())
		require.ErrorIs(t, err, accesskeysvc.ErrAccessKeyNotFound)
	})
}

func TestDeleteRevokes(t *testing.T) {
	ctx := t.Context()

	t.Run("revokes every bucket-scoped delegation in one request, with no witness path", func(t *testing.T) {
		d := setup(t)
		// s3:PutObject maps to several commands, so the key gets several delegations.
		created, _, err := d.svc.Create(ctx, "tenant-1", "k1", []string{"s3:PutObject"}, []string{"bucket-a"}, nil, nil)
		require.NoError(t, err)
		issued, err := d.delegations.ListByAudience(ctx, created.ID)
		require.NoError(t, err)
		require.Greater(t, len(issued.Results), 1)

		require.NoError(t, d.svc.Delete(ctx, "tenant-1", created.ID.Identifier()))
		testutil.AwaitPublished(t, d.runner, d.tenantID)

		require.Len(t, d.swarf.Revocations(), len(issued.Results))
		require.Equal(t, 1, d.swarf.Calls(), "every revocation goes in one request")
		revoked := map[cid.Cid]bool{}
		for _, r := range d.swarf.Revocations() {
			// The tenant issued the delegations, so the tenant revokes them directly:
			// no witness path is needed to prove its authority over them.
			require.Equal(t, d.tenantID, r.Revoker)
			revoked[r.Revoked] = true
		}
		for _, dlg := range issued.Results {
			require.True(t, revoked[dlg.Link()], "delegation %s was not revoked", dlg.Link())
		}
		// The bucket→tenant root is the tenant's own, not the access key's.
		require.False(t, revoked[d.bucketRoot.Link()], "the bucket root must not be revoked")
	})

	t.Run("revokes a powerline delegation", func(t *testing.T) {
		d := setup(t)
		created, _, err := d.svc.Create(ctx, "tenant-1", "k1", []string{"s3:GetObject"}, nil, nil, nil)
		require.NoError(t, err)
		issued, err := d.delegations.ListByAudience(ctx, created.ID)
		require.NoError(t, err)
		require.Len(t, issued.Results, 1)
		require.False(t, issued.Results[0].Subject().Defined(), "expected a powerline delegation")

		require.NoError(t, d.svc.Delete(ctx, "tenant-1", created.ID.Identifier()))
		testutil.AwaitPublished(t, d.runner, d.tenantID)

		require.Len(t, d.swarf.Revocations(), 1)
		r := d.swarf.Revocations()[0]
		require.Equal(t, d.tenantID, r.Revoker)
		require.Equal(t, issued.Results[0].Link(), r.Revoked)
	})

	t.Run("revokes a powerline delegation when the tenant owns no bucket", func(t *testing.T) {
		d := setup(t)
		created, _, err := d.svc.Create(ctx, "tenant-1", "k1", []string{"s3:GetObject"}, nil, nil, nil)
		require.NoError(t, err)
		// A subject-less delegation used to need one of the tenant's bucket roots to
		// witness it, so dropping the only bucket left it unrevoked. It no longer does.
		require.NoError(t, d.buckets.Delete(ctx, d.bucketID))

		require.NoError(t, d.svc.Delete(ctx, "tenant-1", created.ID.Identifier()))
		testutil.AwaitPublished(t, d.runner, d.tenantID)
		require.Len(t, d.swarf.Revocations(), 1)
		_, _, err = d.svc.Get(ctx, "tenant-1", created.ID.Identifier())
		require.ErrorIs(t, err, accesskeysvc.ErrAccessKeyNotFound)
	})

	t.Run("skips an already-expired delegation", func(t *testing.T) {
		d := setup(t)
		expired := time.Now().Add(-time.Hour)
		created, _, err := d.svc.Create(ctx, "tenant-1", "k1", []string{"s3:GetObject"}, nil, nil, &expired)
		require.NoError(t, err)

		// The revocation service rejects expired delegations, and they are unusable
		// anyway — so the key is still deleted, just with nothing published.
		require.NoError(t, d.svc.Delete(ctx, "tenant-1", created.ID.Identifier()))
		testutil.AwaitPublished(t, d.runner, d.tenantID)
		require.Empty(t, d.swarf.Revocations())
		_, _, err = d.svc.Get(ctx, "tenant-1", created.ID.Identifier())
		require.ErrorIs(t, err, accesskeysvc.ErrAccessKeyNotFound)
	})

	t.Run("deletes a key holding no delegations without the tenant key", func(t *testing.T) {
		d := setup(t)
		require.NoError(t, d.principals.Add(ctx, d.tenantID, "bob"))
		created, _, err := d.svc.Create(ctx, "tenant-1", "laptop", nil, nil, new("bob"), nil)
		require.NoError(t, err)
		// With nothing to revoke, the tenant's signing key is never needed.
		require.NoError(t, d.secrets.Delete(ctx, vault.TenantKeyPath(d.tenantID)))

		require.NoError(t, d.svc.Delete(ctx, "tenant-1", created.ID.Identifier()))
		testutil.AwaitPublished(t, d.runner, d.tenantID)
		require.Empty(t, d.swarf.Revocations())
		_, _, err = d.svc.Get(ctx, "tenant-1", created.ID.Identifier())
		require.ErrorIs(t, err, accesskeysvc.ErrAccessKeyNotFound)
	})

	t.Run("moves the key's grants to the revocations owed in the commit that deletes it, and publishes them after", func(t *testing.T) {
		d := setup(t)
		d.swarf.holding.Store(true)
		created, _, err := d.svc.Create(ctx, "tenant-1", "k1", []string{"s3:PutObject"}, []string{"bucket-a"}, nil, nil)
		require.NoError(t, err)
		other, _, err := d.svc.Create(ctx, "tenant-1", "laptop", nil, nil, new("alice"), nil)
		require.NoError(t, err)
		issued, kept := d.held(t, created.ID), d.held(t, other.ID)
		require.NotEmpty(t, issued)
		require.NotEmpty(t, kept)

		// The revocation service is down, and the deletion succeeds all the
		// same: the key, its grants and its secret are gone when it returns.
		require.NoError(t, d.svc.Delete(ctx, "tenant-1", created.ID.Identifier()))
		_, err = d.accessKeys.Get(ctx, created.ID)
		require.ErrorIs(t, err, store.ErrRecordNotFound)
		require.Empty(t, d.held(t, created.ID))
		_, err = d.secrets.Read(ctx, vault.AccessKeyPath(d.tenantID, created.ID))
		require.ErrorIs(t, err, vault.ErrNotFound)
		require.ElementsMatch(t, links(issued), d.owedLinks(t), "every grant of the key is owed a revocation")
		require.Empty(t, d.swarf.Revoked())
		// Nothing else of the tenant's was touched.
		require.Equal(t, links(kept), links(d.held(t, other.ID)))
		require.Equal(t, links([]ucan.Delegation{d.bucketRoot}), links(d.held(t, d.tenantID)))

		d.swarf.holding.Store(false)
		require.Eventually(t, func() bool { return len(d.owedLinks(t)) == 0 }, testutil.WaitTimeout, 10*time.Millisecond,
			"the revocations owed were not published")
		require.ElementsMatch(t, links(issued), d.swarf.Revoked())
		for _, r := range d.swarf.Revocations() {
			require.Equal(t, d.tenantID, r.Revoker)
		}
	})
}
