package tenantqueue_test

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	s3bkt "github.com/fil-forge/libforge/commands/s3/bucket"

	htestutil "github.com/fil-forge/hilt/internal/testutil"
	accesskeysvc "github.com/fil-forge/hilt/pkg/api/service/accesskey"
	"github.com/fil-forge/hilt/pkg/grant"
	"github.com/fil-forge/hilt/pkg/store"
	accesskeypostgres "github.com/fil-forge/hilt/pkg/store/accesskey/postgres"
	bucketpostgres "github.com/fil-forge/hilt/pkg/store/bucket/postgres"
	bucketpolicypostgres "github.com/fil-forge/hilt/pkg/store/bucketpolicy/postgres"
	delegationstore "github.com/fil-forge/hilt/pkg/store/delegation"
	delegationpostgres "github.com/fil-forge/hilt/pkg/store/delegation/postgres"
	principalpostgres "github.com/fil-forge/hilt/pkg/store/principal/postgres"
	providerpostgres "github.com/fil-forge/hilt/pkg/store/provider/postgres"
	revocationpostgres "github.com/fil-forge/hilt/pkg/store/revocation/postgres"
	tenantstore "github.com/fil-forge/hilt/pkg/store/tenant"
	tenantpostgres "github.com/fil-forge/hilt/pkg/store/tenant/postgres"
	"github.com/fil-forge/hilt/pkg/tasks"
	"github.com/fil-forge/hilt/pkg/tasks/revocationqueue"
	"github.com/fil-forge/hilt/pkg/tasks/tenantqueue"
	"github.com/fil-forge/hilt/pkg/vault"
	vaultmemory "github.com/fil-forge/hilt/pkg/vault/memory"
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
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

const (
	externalID = "tenant-1"
	bucketName = "bucket-a"
	principal  = "alice"
)

// heldSwarf is a revocation service that refuses every publish while holding
// is set, so a test can look at the revocations owed before they are
// published.
type heldSwarf struct {
	htestutil.FakeSwarf
	holding atomic.Bool
}

func (h *heldSwarf) PublishBatch(ctx context.Context, revoker ucan.Issuer, revoked []ucan.Delegation) error {
	if h.holding.Load() {
		return errors.New("revocation service unavailable")
	}
	return h.FakeSwarf.PublishBatch(ctx, revoker, revoked)
}

// hooks lets a test act at fixed points of the queue-tenant.set-status
// handler. Each runs once, on the handler's first pass.
type hooks struct {
	// afterStatusRead runs once the handler has read the tenant.
	afterStatusRead func()
	// beforeWrites runs once the handler has read everything it reads and
	// before it records its first write.
	beforeWrites func()

	statusOnce, writesOnce sync.Once
	// statusReads counts the handler's reads of the tenant, one per pass.
	statusReads atomic.Int64
}

// hookedTenants is the tenant store the handler reads through.
type hookedTenants struct {
	tenantstore.Store
	h *hooks
}

func (s hookedTenants) Get(ctx context.Context, id did.DID) (tenantstore.Record, error) {
	rec, err := s.Store.Get(ctx, id)
	s.h.statusReads.Add(1)
	if s.h.afterStatusRead != nil {
		s.h.statusOnce.Do(s.h.afterStatusRead)
	}
	return rec, err
}

// hookedDelegations is the delegation store the handler builds its writes
// with. Building the withdrawal is the first thing the handler does after
// its reads.
type hookedDelegations struct {
	delegationstore.Store
	h *hooks
}

func (s hookedDelegations) WithdrawKeyGrantsStatement(tenant did.DID) store.Statement {
	if s.h.beforeWrites != nil {
		s.h.writesOnce.Do(s.h.beforeWrites)
	}
	return s.Store.WithdrawKeyGrantsStatement(tenant)
}

// world is one active tenant with a bucket, a service key that may read and
// write the bucket, and a principal whose key the bucket's policy lets read
// it. Both keys were made by the access-key service, so each holds what its
// creation issues.
type world struct {
	pool        *pgxpool.Pool
	tenants     *tenantpostgres.Store
	accessKeys  *accesskeypostgres.Store
	policies    *bucketpolicypostgres.Store
	delegations *delegationpostgres.Store
	owed        *revocationpostgres.Store
	secrets     *vaultmemory.Store
	swarf       *heldSwarf
	keys        *accesskeysvc.Service
	runner      *taskrunner.Runner
	hooks       *hooks
	// tenant signs as the tenant.
	tenant ucan.Issuer
	bucket did.DID
	// root is the bucket's delegation of itself to the tenant.
	root         ucan.Delegation
	serviceKey   did.DID
	principalKey did.DID
}

func setup(t *testing.T) *world {
	t.Helper()
	ctx := t.Context()
	pool := htestutil.PostgresOrSkip(t)
	w := &world{
		pool:        pool,
		tenants:     tenantpostgres.New(pool),
		accessKeys:  accesskeypostgres.New(pool),
		policies:    bucketpolicypostgres.New(pool),
		delegations: delegationpostgres.New(pool),
		owed:        revocationpostgres.New(pool),
		secrets:     vaultmemory.New(),
		swarf:       &heldSwarf{},
		hooks:       &hooks{},
	}
	buckets, principals := bucketpostgres.New(pool), principalpostgres.New(pool)

	signer, err := secp256k1.Generate()
	require.NoError(t, err)
	w.tenant = multikey.NewIssuer(signer.KeyDID(), signer)
	providerID := testutil.RandomDID(t)
	require.NoError(t, providerpostgres.New(pool).Add(ctx, providerID, "region-1", nil))
	require.NoError(t, w.tenants.Add(ctx, w.tenant.DID(), externalID, tenantstore.Active))
	require.NoError(t, w.secrets.Write(ctx, vault.TenantKeyPath(w.tenant.DID()), signer.Bytes()))
	require.NoError(t, principals.Add(ctx, w.tenant.DID(), principal))

	bucketSigner, err := ed25519.Generate()
	require.NoError(t, err)
	w.bucket = bucketSigner.KeyDID()
	require.NoError(t, buckets.Add(ctx, w.bucket, w.tenant.DID(), providerID, bucketName))
	w.root, err = delegation.Delegate(multikey.NewIssuer(w.bucket, bucketSigner), w.tenant.DID(), w.bucket, command.Top(), delegation.WithNoExpiration())
	require.NoError(t, err)
	require.NoError(t, w.delegations.PutBatch(ctx, []ucan.Delegation{w.root}))
	w.putPolicy(t, "s3:GetObject")

	w.runner = htestutil.StartTaskRunner(t, pool, func(r *taskrunner.Runner) {
		_, err := tenantqueue.New(r, tenantqueue.Deps{
			Tenants:     hookedTenants{w.tenants, w.hooks},
			AccessKeys:  w.accessKeys,
			Principals:  principals,
			Buckets:     buckets,
			Policies:    w.policies,
			Delegations: hookedDelegations{w.delegations, w.hooks},
			Secrets:     w.secrets,
		})
		require.NoError(t, err)
		_, err = revocationqueue.New(r, revocationqueue.Deps{
			Owed:         w.owed,
			Secrets:      w.secrets,
			Publisher:    w.swarf,
			PublishRetry: taskrunner.RetryPolicy{First: 20 * time.Millisecond, Max: 50 * time.Millisecond, Multiplier: 2},
		})
		require.NoError(t, err)
	})

	w.keys = accesskeysvc.New(zap.NewNop(), w.tenants, w.accessKeys, principals, buckets, w.secrets, w.runner)
	w.serviceKey = w.createKey(t, "service", []string{"s3:GetObject", "s3:PutObject"}, []string{bucketName}, nil)
	who := principal
	w.principalKey = w.createKey(t, "bound", nil, nil, &who)
	// The creations read the tenant too; the count is of what a test does.
	w.hooks.statusReads.Store(0)
	return w
}

// putPolicy sets the bucket's policy to one that lets the principal do the
// actions, without rewriting any key's grants.
func (w *world) putPolicy(t *testing.T, actions ...string) {
	t.Helper()
	htestutil.PutPolicy(t, w.pool, w.tenant.DID(), w.bucket, s3bkt.PolicyDocument{
		Version: s3bkt.Version2012,
		Statements: []s3bkt.Statement{{
			Effect: s3bkt.Allow, Principal: s3bkt.Only(principal), Actions: s3bkt.NewStringSet(actions...),
			Resources: s3bkt.NewStringSet(s3bkt.BucketARN(bucketName), s3bkt.ObjectsARN(bucketName)),
		}},
	})
}

func (w *world) createKey(t *testing.T, name string, permissions, buckets []string, principalID *string) did.DID {
	t.Helper()
	rec, _, err := w.keys.Create(t.Context(), externalID, name, permissions, buckets, principalID, nil)
	require.NoError(t, err)
	return rec.ID
}

// setStatus runs queue-tenant.set-status for the tenant and waits for it.
func (w *world) setStatus(t *testing.T, status tenantstore.Status) error {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), htestutil.WaitTimeout)
	defer cancel()
	_, err := w.runner.Run(ctx, tenantqueue.SetStatusSpec(w.tenant.DID(), status))
	return err
}

func (w *world) status(t *testing.T) tenantstore.Status {
	t.Helper()
	rec, err := w.tenants.Get(t.Context(), w.tenant.DID())
	require.NoError(t, err)
	return rec.Status
}

// held returns the delegations stored for the audience.
func (w *world) held(t *testing.T, audience did.DID) []ucan.Delegation {
	t.Helper()
	page, err := w.delegations.ListByAudience(t.Context(), audience)
	require.NoError(t, err)
	require.Nil(t, page.Cursor, "one page holds everything a test stores")
	return page.Results
}

// owedLinks returns the CIDs of the revocations the tenant owes.
func (w *world) owedLinks(t *testing.T) []cid.Cid {
	t.Helper()
	dels, err := w.owed.Oldest(t.Context(), w.tenant.DID(), 10_000)
	require.NoError(t, err)
	return links(dels)
}

// awaitPublished waits until the tenant owes nothing.
func (w *world) awaitPublished(t *testing.T) {
	t.Helper()
	require.Eventually(t, func() bool { return len(w.owedLinks(t)) == 0 }, htestutil.WaitTimeout, 10*time.Millisecond,
		"the revocations owed were not published")
}

// stray stores a grant for the key that its creation did not issue, and
// returns it.
func (w *world) stray(t *testing.T, key did.DID) ucan.Delegation {
	t.Helper()
	dels, err := grant.Issue(w.tenant, key, []did.DID{w.bucket}, []string{"s3:DeleteObject"}, nil)
	require.NoError(t, err)
	require.NotEmpty(t, dels)
	require.NoError(t, w.delegations.PutBatch(t.Context(), dels[:1]))
	return dels[0]
}

func links(dels []ucan.Delegation) []cid.Cid {
	out := make([]cid.Cid, len(dels))
	for i, d := range dels {
		out[i] = d.Link()
	}
	return out
}

// shapes describes each delegation by what it grants and to whom, leaving out
// what differs between two issues of the same grant. The result is sorted, so
// two sets of grants are the same when their shapes are equal, a repeated
// grant included.
func shapes(dels []ucan.Delegation) []string {
	out := make([]string, len(dels))
	for i, d := range dels {
		exp := "never"
		if e := d.Expiration(); e != nil {
			exp = fmt.Sprint(*e)
		}
		out[i] = fmt.Sprintf("%s -> %s over %s may %s until %s", d.Issuer(), d.Audience(), d.Subject(), d.Command(), exp)
	}
	slices.Sort(out)
	return out
}

func TestDisabling(t *testing.T) {
	t.Run("withdraws every key's grants, records them as owed and publishes them", func(t *testing.T) {
		w := setup(t)
		w.swarf.holding.Store(true)
		before := append(w.held(t, w.serviceKey), w.held(t, w.principalKey)...)
		require.NotEmpty(t, w.held(t, w.serviceKey))
		require.NotEmpty(t, w.held(t, w.principalKey))

		require.NoError(t, w.setStatus(t, tenantstore.Disabled))

		require.Equal(t, tenantstore.Disabled, w.status(t))
		require.Empty(t, w.held(t, w.serviceKey))
		require.Empty(t, w.held(t, w.principalKey))
		require.ElementsMatch(t, links(before), w.owedLinks(t), "every grant is owed a revocation")
		require.Equal(t, links([]ucan.Delegation{w.root}), links(w.held(t, w.tenant.DID())), "the bucket's root delegation is not the tenant's to revoke")
		require.Empty(t, w.swarf.Revoked())

		w.swarf.holding.Store(false)
		w.awaitPublished(t)
		require.ElementsMatch(t, links(before), w.swarf.Revoked())
		for _, r := range w.swarf.Revocations() {
			require.Equal(t, w.tenant.DID(), r.Revoker)
		}
	})

	t.Run("a second run changes nothing more", func(t *testing.T) {
		w := setup(t)
		require.NoError(t, w.setStatus(t, tenantstore.Disabled))
		w.awaitPublished(t)
		revoked := w.swarf.Revoked()
		pending := func() []taskrunner.TaskID {
			subject := w.tenant.DID().String()
			ids, err := w.runner.Pending(t.Context(), tasks.QueueRevocation, []string{subject})
			require.NoError(t, err)
			return ids[subject]
		}
		require.Eventually(t, func() bool { return len(pending()) == 0 }, htestutil.WaitTimeout, 10*time.Millisecond)

		require.NoError(t, w.setStatus(t, tenantstore.Disabled))

		require.Equal(t, tenantstore.Disabled, w.status(t))
		require.Empty(t, w.held(t, w.serviceKey))
		require.Empty(t, w.owedLinks(t))
		require.Empty(t, pending(), "a run that changes nothing queues no publish")
		require.Equal(t, revoked, w.swarf.Revoked())
		require.Len(t, w.held(t, w.tenant.DID()), 1)
	})

	t.Run("from write-locked withdraws the grants too", func(t *testing.T) {
		w := setup(t)
		require.NoError(t, w.setStatus(t, tenantstore.WriteLocked))
		require.NotEmpty(t, w.held(t, w.serviceKey))

		require.NoError(t, w.setStatus(t, tenantstore.Disabled))
		require.Equal(t, tenantstore.Disabled, w.status(t))
		require.Empty(t, w.held(t, w.serviceKey))
		require.Empty(t, w.held(t, w.principalKey))
	})

	t.Run("withdraws a grant stored between the handler's reads and its commit", func(t *testing.T) {
		w := setup(t)
		var late ucan.Delegation
		w.hooks.beforeWrites = func() { late = w.stray(t, w.serviceKey) }

		require.NoError(t, w.setStatus(t, tenantstore.Disabled))

		require.NotNil(t, late, "the hook ran")
		require.Empty(t, w.held(t, w.serviceKey))
		w.awaitPublished(t)
		require.Contains(t, w.swarf.Revoked(), late.Link())
	})

	t.Run("runs again when the status changed under it", func(t *testing.T) {
		w := setup(t)
		w.hooks.afterStatusRead = func() {
			require.NoError(t, w.tenants.SetStatus(t.Context(), w.tenant.DID(), tenantstore.WriteLocked))
		}

		require.NoError(t, w.setStatus(t, tenantstore.Disabled))

		require.Equal(t, tenantstore.Disabled, w.status(t))
		require.Empty(t, w.held(t, w.serviceKey))
		require.EqualValues(t, 2, w.hooks.statusReads.Load(), "the first pass did not commit, and the second read the new status")
	})
}

func TestReactivating(t *testing.T) {
	t.Run("issues each key the grants its creation gave it", func(t *testing.T) {
		w := setup(t)
		service, bound := w.held(t, w.serviceKey), w.held(t, w.principalKey)
		require.NoError(t, w.setStatus(t, tenantstore.Disabled))
		w.awaitPublished(t)

		require.NoError(t, w.setStatus(t, tenantstore.Active))

		require.Equal(t, tenantstore.Active, w.status(t))
		freshService, freshBound := w.held(t, w.serviceKey), w.held(t, w.principalKey)
		require.Equal(t, shapes(service), shapes(freshService))
		require.Equal(t, shapes(bound), shapes(freshBound))
		// Each is a new delegation: the ones withdrawn are revoked, and
		// revoking them must not reach these.
		for _, d := range append(freshService, freshBound...) {
			require.NotContains(t, w.swarf.Revoked(), d.Link())
		}
		require.Len(t, w.held(t, w.tenant.DID()), 1)
	})

	t.Run("issues a principal-bound key's grants from the policies as they are now", func(t *testing.T) {
		w := setup(t)
		require.NoError(t, w.setStatus(t, tenantstore.Disabled))
		w.putPolicy(t, "s3:GetObject", "s3:ListBucket", "s3:DeleteObject")

		require.NoError(t, w.setStatus(t, tenantstore.Active))

		// A key created now is issued from the same policy.
		who := principal
		created := w.held(t, w.createKey(t, "bound-2", nil, nil, &who))
		reissued := w.held(t, w.principalKey)
		require.NotEmpty(t, created)
		grants := func(dels []ucan.Delegation) []string {
			out := make([]string, len(dels))
			for i, d := range dels {
				out[i] = d.Subject().String() + " " + d.Command().String()
			}
			slices.Sort(out)
			return out
		}
		require.Equal(t, grants(created), grants(reissued))
	})

	t.Run("a key holding grants while disabled ends with exactly one set", func(t *testing.T) {
		w := setup(t)
		bound := w.held(t, w.principalKey)
		require.NoError(t, w.setStatus(t, tenantstore.Disabled))
		w.awaitPublished(t)
		// What a policy write for the disabled tenant leaves the key with.
		existing, err := grant.Issue(w.tenant, w.principalKey, []did.DID{w.bucket}, []string{"s3:GetObject"}, nil)
		require.NoError(t, err)
		require.NoError(t, w.delegations.PutBatch(t.Context(), existing))

		require.NoError(t, w.setStatus(t, tenantstore.Active))

		require.Equal(t, shapes(bound), shapes(w.held(t, w.principalKey)), "one set, with no grant held twice")
		w.awaitPublished(t)
		for _, d := range existing {
			require.Contains(t, w.swarf.Revoked(), d.Link(), "what the key held before is revoked")
		}
	})

	t.Run("withdraws a grant stored between the handler's reads and its commit", func(t *testing.T) {
		w := setup(t)
		service := w.held(t, w.serviceKey)
		require.NoError(t, w.setStatus(t, tenantstore.Disabled))
		var late ucan.Delegation
		w.hooks.beforeWrites = func() { late = w.stray(t, w.serviceKey) }

		require.NoError(t, w.setStatus(t, tenantstore.Active))

		require.NotNil(t, late, "the hook ran")
		require.Equal(t, shapes(service), shapes(w.held(t, w.serviceKey)))
		require.NotContains(t, links(w.held(t, w.serviceKey)), late.Link())
		w.awaitPublished(t)
		require.Contains(t, w.swarf.Revoked(), late.Link())
	})

	t.Run("fails and stays disabled when the tenant's signing key is gone", func(t *testing.T) {
		w := setup(t)
		require.NoError(t, w.setStatus(t, tenantstore.Disabled))
		require.NoError(t, w.secrets.Delete(t.Context(), vault.TenantKeyPath(w.tenant.DID())))

		require.ErrorContains(t, w.setStatus(t, tenantstore.Active), "signing key is not in the vault")
		require.Equal(t, tenantstore.Disabled, w.status(t))
		require.Empty(t, w.held(t, w.serviceKey))
	})

	t.Run("needs no signing key when every key has expired", func(t *testing.T) {
		w := setup(t)
		require.NoError(t, w.setStatus(t, tenantstore.Disabled))
		_, err := w.pool.Exec(t.Context(), `UPDATE access_key SET expires_at = now() - interval '1 hour' WHERE tenant_id = $1`, w.tenant.DID().String())
		require.NoError(t, err)
		require.NoError(t, w.secrets.Delete(t.Context(), vault.TenantKeyPath(w.tenant.DID())))

		require.NoError(t, w.setStatus(t, tenantstore.Active))

		require.Equal(t, tenantstore.Active, w.status(t))
		require.Empty(t, w.held(t, w.serviceKey))
		require.Empty(t, w.held(t, w.principalKey))
	})
}

// wantGrants is what the world's two keys hold while the tenant has the
// status: what [grant.ForKey] issues each from the key's row and the
// bucket's policy as they are stored.
func (w *world) wantGrants(t *testing.T, status tenantstore.Status) (service, bound []string) {
	t.Helper()
	named, err := w.policies.ListByPrincipal(t.Context(), w.tenant.DID(), principal)
	require.NoError(t, err)
	for i, key := range []did.DID{w.serviceKey, w.principalKey} {
		rec, err := w.accessKeys.Get(t.Context(), key)
		require.NoError(t, err)
		dels, err := grant.ForKey(w.tenant, status, rec, named)
		require.NoError(t, err)
		if i == 0 {
			service = shapes(dels)
		} else {
			bound = shapes(dels)
		}
	}
	return service, bound
}

func TestWriteLocking(t *testing.T) {
	t.Run("leaves each key the grants of what it keeps, and withdraws what it held", func(t *testing.T) {
		w := setup(t)
		w.swarf.holding.Store(true)
		before := append(w.held(t, w.serviceKey), w.held(t, w.principalKey)...)
		full, _ := w.wantGrants(t, tenantstore.Active)

		require.NoError(t, w.setStatus(t, tenantstore.WriteLocked))

		require.Equal(t, tenantstore.WriteLocked, w.status(t))
		service, bound := w.wantGrants(t, tenantstore.WriteLocked)
		require.NotEmpty(t, service)
		require.Less(t, len(service), len(full), "the service key may upload, and its narrowed grants are fewer")
		require.Equal(t, service, shapes(w.held(t, w.serviceKey)))
		require.Equal(t, bound, shapes(w.held(t, w.principalKey)))
		require.ElementsMatch(t, links(before), w.owedLinks(t), "every grant the keys held is owed a revocation")
		require.Equal(t, links([]ucan.Delegation{w.root}), links(w.held(t, w.tenant.DID())))
		require.Empty(t, w.swarf.Revoked())

		w.swarf.holding.Store(false)
		w.awaitPublished(t)
		require.ElementsMatch(t, links(before), w.swarf.Revoked())
	})

	t.Run("returning to active issues the full grants afresh", func(t *testing.T) {
		w := setup(t)
		service, bound := w.wantGrants(t, tenantstore.Active)
		original := append(w.held(t, w.serviceKey), w.held(t, w.principalKey)...)
		require.NoError(t, w.setStatus(t, tenantstore.WriteLocked))
		narrowed := append(w.held(t, w.serviceKey), w.held(t, w.principalKey)...)

		require.NoError(t, w.setStatus(t, tenantstore.Active))

		require.Equal(t, service, shapes(w.held(t, w.serviceKey)))
		require.Equal(t, bound, shapes(w.held(t, w.principalKey)))
		w.awaitPublished(t)
		for _, d := range append(original, narrowed...) {
			require.Contains(t, w.swarf.Revoked(), d.Link())
		}
		for _, d := range append(w.held(t, w.serviceKey), w.held(t, w.principalKey)...) {
			require.NotContains(t, w.swarf.Revoked(), d.Link(), "a revoked grant is not issued again")
		}
	})

	t.Run("from disabled issues the narrowed grants", func(t *testing.T) {
		w := setup(t)
		require.NoError(t, w.setStatus(t, tenantstore.Disabled))
		w.awaitPublished(t)

		require.NoError(t, w.setStatus(t, tenantstore.WriteLocked))

		service, bound := w.wantGrants(t, tenantstore.WriteLocked)
		require.Equal(t, service, shapes(w.held(t, w.serviceKey)))
		require.Equal(t, bound, shapes(w.held(t, w.principalKey)))
		for _, d := range append(w.held(t, w.serviceKey), w.held(t, w.principalKey)...) {
			require.NotContains(t, w.swarf.Revoked(), d.Link())
		}
	})

	t.Run("a key created for a write-locked tenant holds the narrowed grants until the tenant is active", func(t *testing.T) {
		w := setup(t)
		require.NoError(t, w.setStatus(t, tenantstore.WriteLocked))
		key := w.serviceKeyInput(t, "ci", []did.DID{w.bucket}, "s3:GetObject", "s3:PutObject", "s3:PutObjectTagging")
		require.NoError(t, w.run(t, createSpec(t, key)))

		rec, err := w.accessKeys.Get(t.Context(), key.ID)
		require.NoError(t, err)
		require.Equal(t, key.Permissions, rec.Permissions, "the key keeps the permissions it was created with")
		reads, err := grant.Issue(w.tenant, key.ID, []did.DID{w.bucket}, []string{"s3:GetObject"}, nil)
		require.NoError(t, err)
		require.Equal(t, shapes(reads), shapes(w.held(t, key.ID)))

		require.NoError(t, w.setStatus(t, tenantstore.Active))
		all, err := grant.Issue(w.tenant, key.ID, []did.DID{w.bucket}, key.Permissions, nil)
		require.NoError(t, err)
		require.Equal(t, shapes(all), shapes(w.held(t, key.ID)))
	})

	t.Run("a policy written for a write-locked tenant gives the narrowed grants until the tenant is active", func(t *testing.T) {
		w := setup(t)
		require.NoError(t, w.setStatus(t, tenantstore.WriteLocked))
		spec, err := tenantqueue.PutPolicySpec(w.tenant.DID(), w.bucket, bucketName,
			policyOf("s3:GetObject", "s3:PutObject", "s3:DeleteObject"), tenantqueue.PolicyCondition{})
		require.NoError(t, err)
		require.NoError(t, w.run(t, spec))

		kept, err := grant.Issue(w.tenant, w.principalKey, []did.DID{w.bucket}, []string{"s3:GetObject", "s3:DeleteObject"}, nil)
		require.NoError(t, err)
		require.Equal(t, shapes(kept), shapes(w.held(t, w.principalKey)))

		require.NoError(t, w.setStatus(t, tenantstore.Active))
		all, err := grant.Issue(w.tenant, w.principalKey, []did.DID{w.bucket}, []string{"s3:GetObject", "s3:PutObject", "s3:DeleteObject"}, nil)
		require.NoError(t, err)
		require.Greater(t, len(all), len(kept))
		require.Equal(t, shapes(all), shapes(w.held(t, w.principalKey)))
	})

	t.Run("withdraws a grant stored between the handler's reads and its commit", func(t *testing.T) {
		w := setup(t)
		var late ucan.Delegation
		w.hooks.beforeWrites = func() { late = w.stray(t, w.serviceKey) }

		require.NoError(t, w.setStatus(t, tenantstore.WriteLocked))

		require.NotNil(t, late, "the hook ran")
		service, _ := w.wantGrants(t, tenantstore.WriteLocked)
		require.Equal(t, service, shapes(w.held(t, w.serviceKey)))
		w.awaitPublished(t)
		require.Contains(t, w.swarf.Revoked(), late.Link())
	})

}

func TestStatusAlone(t *testing.T) {
	t.Run("the status the tenant has already succeeds and writes nothing", func(t *testing.T) {
		for _, status := range []tenantstore.Status{tenantstore.Active, tenantstore.WriteLocked} {
			w := setup(t)
			require.NoError(t, w.setStatus(t, status))
			w.awaitPublished(t)
			before, err := w.tenants.Get(t.Context(), w.tenant.DID())
			require.NoError(t, err)
			service := links(w.held(t, w.serviceKey))
			revoked := w.swarf.Revoked()

			require.NoError(t, w.setStatus(t, status))

			after, err := w.tenants.Get(t.Context(), w.tenant.DID())
			require.NoError(t, err)
			require.Equal(t, before, after)
			require.ElementsMatch(t, service, links(w.held(t, w.serviceKey)))
			require.Empty(t, w.owedLinks(t))
			require.Equal(t, revoked, w.swarf.Revoked())
		}
	})

	t.Run("an unknown tenant fails", func(t *testing.T) {
		w := setup(t)
		ctx, cancel := context.WithTimeout(t.Context(), htestutil.WaitTimeout)
		defer cancel()
		_, err := w.runner.Run(ctx, tenantqueue.SetStatusSpec(testutil.RandomDID(t), tenantstore.Disabled))
		require.ErrorIs(t, err, tenantqueue.ErrTenantNotFound)
	})

	t.Run("a status that is not one fails", func(t *testing.T) {
		w := setup(t)
		require.ErrorContains(t, w.setStatus(t, tenantstore.Status("paused")), "invalid tenant status")
		require.Equal(t, tenantstore.Active, w.status(t))
	})
}

func TestSetStatusSpec(t *testing.T) {
	tenantID := testutil.RandomDID(t)
	require.Equal(t,
		taskrunner.Spec{Queue: "queue-tenant", Subject: tenantID.String(), Action: "set-status", Args: []byte("disabled")},
		tenantqueue.SetStatusSpec(tenantID, tenantstore.Disabled))
}
