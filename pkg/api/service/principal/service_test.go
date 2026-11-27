package principal_test

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	s3bkt "github.com/fil-forge/libforge/commands/s3/bucket"

	"github.com/fil-forge/hilt/internal/testutil"
	accesskeysvc "github.com/fil-forge/hilt/pkg/api/service/accesskey"
	bucketpolicysvc "github.com/fil-forge/hilt/pkg/api/service/bucketpolicy"
	principalsvc "github.com/fil-forge/hilt/pkg/api/service/principal"
	"github.com/fil-forge/hilt/pkg/grant"
	"github.com/fil-forge/hilt/pkg/store"
	accesskeystore "github.com/fil-forge/hilt/pkg/store/accesskey"
	accesskeypostgres "github.com/fil-forge/hilt/pkg/store/accesskey/postgres"
	bucketpostgres "github.com/fil-forge/hilt/pkg/store/bucket/postgres"
	bucketpolicypostgres "github.com/fil-forge/hilt/pkg/store/bucketpolicy/postgres"
	delegationpostgres "github.com/fil-forge/hilt/pkg/store/delegation/postgres"
	principalstore "github.com/fil-forge/hilt/pkg/store/principal"
	principalpostgres "github.com/fil-forge/hilt/pkg/store/principal/postgres"
	providerpostgres "github.com/fil-forge/hilt/pkg/store/provider/postgres"
	"github.com/fil-forge/hilt/pkg/store/revocation"
	revocationpostgres "github.com/fil-forge/hilt/pkg/store/revocation/postgres"
	"github.com/fil-forge/hilt/pkg/store/tenant"
	tenantpostgres "github.com/fil-forge/hilt/pkg/store/tenant/postgres"
	"github.com/fil-forge/hilt/pkg/tasks/tenantqueue"
	"github.com/fil-forge/hilt/pkg/vault"
	vaultmemory "github.com/fil-forge/hilt/pkg/vault/memory"
	"github.com/fil-forge/libforge/taskrunner"
	"github.com/fil-forge/ucantone/did"
	"github.com/fil-forge/ucantone/multikey"
	"github.com/fil-forge/ucantone/multikey/secp256k1"
	"github.com/fil-forge/ucantone/ucan"
	"github.com/ipfs/go-cid"
	"github.com/jackc/pgx/v5/pgxpool"
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

type deps struct {
	svc         *principalsvc.Service
	pool        *pgxpool.Pool
	tenants     *tenantpostgres.Store
	principals  *principalpostgres.Store
	policies    *bucketpolicypostgres.Store
	accessKeys  *accesskeypostgres.Store
	secrets     *vaultmemory.Store
	delegations *delegationpostgres.Store
	owed        *revocationpostgres.Store
	swarf       *heldSwarf
	runner      *taskrunner.Runner
	keys        *accesskeysvc.Service
	policySvc   *bucketpolicysvc.Service
	tenantID    did.DID
	tenant      ucan.Issuer
	otherTenant did.DID
	// providerID is the provider every bucket the tests create is placed with.
	providerID did.DID
}

// hook is what a test runs at one point of a queue-tenant handler's run.
// The zero hook does nothing.
type hook struct {
	mu sync.Mutex
	fn func()
}

func (h *hook) set(fn func()) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.fn = fn
}

// run runs and clears what was set, so it runs once.
func (h *hook) run() {
	h.mu.Lock()
	fn := h.fn
	h.fn = nil
	h.mu.Unlock()
	if fn != nil {
		fn()
	}
}

// setup wires the service over a fresh database with two tenants, "tenant-1"
// and the foreign "tenant-2", and a task runner with the service's handlers.
// beforeCommit runs once when a handler that writes a policy has read
// everything it reads for it (testutil.BeforePolicyCommit).
func setup(t *testing.T, beforeCommit *hook) deps {
	t.Helper()
	ctx := t.Context()
	pool := testutil.PostgresOrSkip(t)
	providerID := testutil.RandomDID(t)
	require.NoError(t, providerpostgres.New(pool).Add(ctx, providerID, "region-1", nil))
	tenants := tenantpostgres.New(pool)
	signer, err := secp256k1.Generate()
	require.NoError(t, err)
	tenantID, otherTenant := signer.KeyDID(), testutil.RandomDID(t)
	require.NoError(t, tenants.Add(ctx, tenantID, "tenant-1", tenant.Active))
	require.NoError(t, tenants.Add(ctx, otherTenant, "tenant-2", tenant.Active))

	principals := principalpostgres.New(pool)
	d := deps{
		pool:        pool,
		providerID:  providerID,
		tenants:     tenants,
		principals:  principals,
		policies:    bucketpolicypostgres.New(pool),
		accessKeys:  accesskeypostgres.New(pool),
		secrets:     vaultmemory.New(),
		delegations: delegationpostgres.New(pool),
		owed:        revocationpostgres.New(pool),
		swarf:       &heldSwarf{},
		tenantID:    tenantID,
		otherTenant: otherTenant,
	}
	// The tasks sign grants and revocations as the tenant.
	require.NoError(t, d.secrets.Write(ctx, vault.TenantKeyPath(tenantID), signer.Bytes()))
	d.tenant = multikey.NewIssuer(tenantID, signer)
	var wrap []func(*tenantqueue.Deps)
	if beforeCommit != nil {
		wrap = append(wrap, testutil.BeforePolicyCommit(beforeCommit.run))
	}
	d.runner = testutil.StartServiceTasks(t, pool, d.secrets, d.swarf, wrap...)
	d.svc = principalsvc.New(zap.NewNop(), d.tenants, d.principals, d.secrets, d.runner)
	d.keys = accesskeysvc.New(zap.NewNop(), d.tenants, d.accessKeys, d.principals, bucketpostgres.New(pool), d.secrets, d.runner)
	d.policySvc = bucketpolicysvc.New(zap.NewNop(), d.tenants, bucketpostgres.New(pool), d.principals, d.policies, d.runner)
	return d
}

// bucketNames numbers the buckets the tests create, whose names must differ.
var bucketNames atomic.Int64

// bucket creates a bucket of the tenant and returns it and its name.
func (d deps) bucket(t *testing.T, tenantID did.DID) (did.DID, string) {
	t.Helper()
	bucket := testutil.RandomDID(t)
	name := fmt.Sprintf("bucket-%d", bucketNames.Add(1))
	require.NoError(t, bucketpostgres.New(d.pool).Add(t.Context(), bucket, tenantID, d.providerID, name))
	return bucket, name
}

// writePolicy creates a bucket of tenant-1 and writes a policy of the
// statements on it through the policy service, which gives the keys of the
// principals it names their grants, and returns the bucket and its ETag.
// Every statement covers the bucket and its objects.
func (d deps) writePolicy(t *testing.T, statements ...s3bkt.Statement) (did.DID, string) {
	t.Helper()
	bucket, name := d.bucket(t, d.tenantID)
	for i := range statements {
		statements[i].Resources = s3bkt.NewStringSet(s3bkt.BucketARN(name), s3bkt.ObjectsARN(name))
	}
	etag, _, err := d.policySvc.Write(t.Context(), d.tenantID, bucket, name, s3bkt.PolicyDocument{Version: s3bkt.Version2012, Statements: statements})
	require.NoError(t, err)
	return bucket, etag
}

func allow(p s3bkt.Principal, actions ...string) s3bkt.Statement {
	return s3bkt.Statement{Effect: s3bkt.Allow, Principal: p, Actions: s3bkt.NewStringSet(actions...)}
}

func deny(p s3bkt.Principal, actions ...string) s3bkt.Statement {
	return s3bkt.Statement{Effect: s3bkt.Deny, Principal: p, Actions: s3bkt.NewStringSet(actions...)}
}

// principal creates a principal of tenant-1.
func (d deps) principal(t *testing.T, id string) {
	t.Helper()
	_, _, err := d.svc.Create(t.Context(), "tenant-1", id)
	require.NoError(t, err)
}

// addKey creates a key of tenant-1 bound to the principal through the
// access-key service, so it holds the grants the policies give the principal.
func (d deps) addKey(t *testing.T, principalID, name string) did.DID {
	t.Helper()
	rec, _, err := d.keys.Create(t.Context(), "tenant-1", name, nil, nil, &principalID, nil)
	require.NoError(t, err)
	return rec.ID
}

// held returns the delegations the key holds.
func (d deps) held(t *testing.T, key did.DID) []ucan.Delegation {
	t.Helper()
	page, err := d.delegations.ListByAudience(t.Context(), key)
	require.NoError(t, err)
	require.Nil(t, page.Cursor, "one page holds everything a test stores")
	return page.Results
}

// owedLinks returns the CIDs of the revocations tenant-1 owes.
func (d deps) owedLinks(t *testing.T) []cid.Cid {
	t.Helper()
	dels, _, err := d.owed.Oldest(t.Context(), d.tenantID, revocation.Cursor{}, 10_000)
	require.NoError(t, err)
	return links(dels)
}

// awaitPublished lets the revocation service take publishes and waits until
// tenant-1 owes nothing.
func (d deps) awaitPublished(t *testing.T) {
	t.Helper()
	d.swarf.holding.Store(false)
	require.Eventually(t, func() bool { return len(d.owedLinks(t)) == 0 }, testutil.WaitTimeout, 10*time.Millisecond,
		"the revocations owed were not published")
}

// requireGrantsOfPolicies requires that the key, bound to the principal,
// holds exactly the grants the tenant's policies give the principal now.
func (d deps) requireGrantsOfPolicies(t *testing.T, key did.DID) {
	t.Helper()
	rec, err := d.accessKeys.Get(t.Context(), key)
	require.NoError(t, err)
	named, err := d.policies.ListByPrincipal(t.Context(), d.tenantID, *rec.Principal)
	require.NoError(t, err)
	want, err := grant.ForKey(d.tenant, tenant.Active, rec, named)
	require.NoError(t, err)
	require.Equal(t, shapes(want), shapes(d.held(t, key)))
}

func links(dels []ucan.Delegation) []cid.Cid {
	out := make([]cid.Cid, len(dels))
	for i, d := range dels {
		out[i] = d.Link()
	}
	return out
}

// shapes describes each delegation by what it grants and to whom, leaving out
// what differs between two issues of the same grant. The result is sorted.
func shapes(dels []ucan.Delegation) []string {
	out := make([]string, len(dels))
	for i, d := range dels {
		out[i] = fmt.Sprintf("%s -> %s over %s may %s", d.Issuer(), d.Audience(), d.Subject(), d.Command())
	}
	slices.Sort(out)
	return out
}

func TestCreate(t *testing.T) {
	ctx := t.Context()

	t.Run("records the principal and repeats idempotently", func(t *testing.T) {
		d := setup(t, nil)
		rec, created, err := d.svc.Create(ctx, "tenant-1", "user-1")
		require.NoError(t, err)
		require.True(t, created)
		require.Equal(t, "user-1", rec.ExternalID)
		require.Equal(t, d.tenantID, rec.Tenant)

		again, created, err := d.svc.Create(ctx, "tenant-1", "user-1")
		require.NoError(t, err)
		require.False(t, created, "an existing principal is not created again")
		require.Equal(t, rec.CreatedAt, again.CreatedAt)
	})

	t.Run("the same principalId in another tenant is a separate principal", func(t *testing.T) {
		d := setup(t, nil)
		_, created, err := d.svc.Create(ctx, "tenant-1", "user-1")
		require.NoError(t, err)
		require.True(t, created)
		rec, created, err := d.svc.Create(ctx, "tenant-2", "user-1")
		require.NoError(t, err)
		require.True(t, created)
		require.Equal(t, d.otherTenant, rec.Tenant)
	})

	t.Run("rejects an unknown tenant", func(t *testing.T) {
		d := setup(t, nil)
		_, _, err := d.svc.Create(ctx, "missing", "user-1")
		require.ErrorIs(t, err, principalsvc.ErrTenantNotFound)
	})

	t.Run("rejects an empty or oversized principalId", func(t *testing.T) {
		d := setup(t, nil)
		_, _, err := d.svc.Create(ctx, "tenant-1", "")
		require.ErrorIs(t, err, principalsvc.ErrInvalidPrincipalID)
		_, _, err = d.svc.Create(ctx, "tenant-1", strings.Repeat("u", 256))
		require.ErrorIs(t, err, principalsvc.ErrInvalidPrincipalID)
		// The limit is bytes, and the refusal says so.
		_, _, err = d.svc.Create(ctx, "tenant-1", strings.Repeat("é", 128))
		require.ErrorIs(t, err, principalsvc.ErrInvalidPrincipalID)
		require.Contains(t, err.Error(), "255 bytes")
	})

	t.Run("rejects a principalId that is not valid UTF-8 or holds a NUL", func(t *testing.T) {
		d := setup(t, nil)
		for _, id := range []string{"a\x00b", "\xff"} {
			_, _, err := d.svc.Create(ctx, "tenant-1", id)
			require.ErrorIs(t, err, principalsvc.ErrInvalidPrincipalID, "%q", id)
		}
	})

	t.Run("a removal landing between the record and its read is a retryable conflict", func(t *testing.T) {
		d := setup(t, nil)
		principals := &vanishingPrincipals{Store: d.principals, remove: func() {
			require.NoError(t, d.svc.Delete(ctx, "tenant-1", "user-1"))
		}}
		svc := principalsvc.New(zap.NewNop(), d.tenants, principals, d.secrets, d.runner)
		_, _, err := svc.Create(ctx, "tenant-1", "user-1")
		require.ErrorIs(t, err, principalsvc.ErrConcurrentChange)
	})

	t.Run("rejects the reserved policy wildcard", func(t *testing.T) {
		d := setup(t, nil)
		_, _, err := d.svc.Create(ctx, "tenant-1", s3bkt.Wildcard)
		require.ErrorIs(t, err, principalsvc.ErrInvalidPrincipalID)
		recs, err := d.principals.ListByTenant(ctx, d.tenantID)
		require.NoError(t, err)
		require.Empty(t, recs)
	})
}

func TestListGet(t *testing.T) {
	ctx := t.Context()

	t.Run("lists the tenant's principals by principalId", func(t *testing.T) {
		d := setup(t, nil)
		for _, id := range []string{"user-2", "user-1"} {
			_, _, err := d.svc.Create(ctx, "tenant-1", id)
			require.NoError(t, err)
		}
		_, _, err := d.svc.Create(ctx, "tenant-2", "user-3")
		require.NoError(t, err)

		recs, err := d.svc.List(ctx, "tenant-1")
		require.NoError(t, err)
		var ids []string
		for _, rec := range recs {
			ids = append(ids, rec.ExternalID)
		}
		require.Equal(t, []string{"user-1", "user-2"}, ids)
	})

	t.Run("gets one principal", func(t *testing.T) {
		d := setup(t, nil)
		_, _, err := d.svc.Create(ctx, "tenant-1", "user-1")
		require.NoError(t, err)
		rec, err := d.svc.Get(ctx, "tenant-1", "user-1")
		require.NoError(t, err)
		require.Equal(t, "user-1", rec.ExternalID)
	})

	t.Run("another tenant's principal is not found", func(t *testing.T) {
		d := setup(t, nil)
		_, _, err := d.svc.Create(ctx, "tenant-2", "user-1")
		require.NoError(t, err)
		_, err = d.svc.Get(ctx, "tenant-1", "user-1")
		require.ErrorIs(t, err, principalsvc.ErrPrincipalNotFound)
	})

	t.Run("rejects an unknown tenant", func(t *testing.T) {
		d := setup(t, nil)
		_, err := d.svc.List(ctx, "missing")
		require.ErrorIs(t, err, principalsvc.ErrTenantNotFound)
		_, err = d.svc.Get(ctx, "missing", "user-1")
		require.ErrorIs(t, err, principalsvc.ErrTenantNotFound)
	})
}

func TestDelete(t *testing.T) {
	ctx := t.Context()

	t.Run("removes the principal's keys and their grants and strips it from the policies naming it", func(t *testing.T) {
		d := setup(t, nil)
		d.principal(t, "user-1")
		d.principal(t, "user-2")

		// A policy the principal shares, one it holds alone, and one that
		// reaches it only through the wildcard.
		shared, _ := d.writePolicy(t,
			allow(s3bkt.Only("user-1", "user-2"), "s3:GetObject", "s3:PutObject"),
			deny(s3bkt.Only("user-1"), "s3:PutObject"),
		)
		alone, _ := d.writePolicy(t, allow(s3bkt.Only("user-1"), "s3:PutObject"))
		everyone, everyoneETag := d.writePolicy(t, allow(s3bkt.Everyone(), "s3:ListBucket"))

		removed := []did.DID{d.addKey(t, "user-1", "laptop"), d.addKey(t, "user-1", "phone")}
		kept := d.addKey(t, "user-2", "desktop")
		var revoked []ucan.Delegation
		for _, key := range removed {
			held := d.held(t, key)
			require.NotEmpty(t, held)
			revoked = append(revoked, held...)
		}
		keptBefore := d.held(t, kept)
		require.NotEmpty(t, keptBefore)

		d.swarf.holding.Store(true)
		require.NoError(t, d.svc.Delete(ctx, "tenant-1", "user-1"))

		_, err := d.svc.Get(ctx, "tenant-1", "user-1")
		require.ErrorIs(t, err, principalsvc.ErrPrincipalNotFound)

		// Its keys, their grants and their vault entries are gone, and every
		// grant they held is owed.
		for _, key := range removed {
			_, err = d.accessKeys.Get(ctx, key)
			require.ErrorIs(t, err, store.ErrRecordNotFound)
			require.Empty(t, d.held(t, key))
			_, err = d.secrets.Read(ctx, vault.AccessKeyPath(d.tenantID, key))
			require.ErrorIs(t, err, vault.ErrNotFound)
		}
		require.ElementsMatch(t, links(revoked), d.owedLinks(t))

		// The shared policy keeps the other principal and loses the statement
		// the removed one held alone.
		rec, err := d.policies.Get(ctx, shared)
		require.NoError(t, err)
		require.Len(t, rec.Policy.Statements, 1)
		require.Equal(t, s3bkt.Only("user-2"), rec.Policy.Statements[0].Principal)
		require.Equal(t, s3bkt.NewStringSet("s3:GetObject", "s3:PutObject"), rec.Policy.Statements[0].Actions)
		// The policy naming it alone is removed with its last statement.
		_, err = d.policies.Get(ctx, alone)
		require.ErrorIs(t, err, store.ErrRecordNotFound)
		// The wildcard policy is untouched: it names the tenant's principals,
		// and this one is no longer among them.
		rec, err = d.policies.Get(ctx, everyone)
		require.NoError(t, err)
		require.Equal(t, everyoneETag, rec.ETag)
		listed, err := d.policies.ListByPrincipal(ctx, d.tenantID, "user-1")
		require.NoError(t, err)
		require.Len(t, listed, 1, "only the wildcard policy reaches the removed principal's id")

		// The other principal's key holds exactly the grants of the policies
		// as they are now, which the removal left as they were.
		d.requireGrantsOfPolicies(t, kept)
		require.ElementsMatch(t, links(keptBefore), links(d.held(t, kept)))

		// The revocations are published once the revocation service is back.
		d.awaitPublished(t)
		require.ElementsMatch(t, links(revoked), d.swarf.Revoked())
	})

	t.Run("removing twice is a no-op the second time", func(t *testing.T) {
		d := setup(t, nil)
		d.principal(t, "user-1")
		d.writePolicy(t, allow(s3bkt.Only("user-1"), "s3:GetObject"))
		d.addKey(t, "user-1", "laptop")
		require.NoError(t, d.svc.Delete(ctx, "tenant-1", "user-1"))
		d.awaitPublished(t)
		revoked := d.swarf.Revoked()
		require.NotEmpty(t, revoked)

		require.NoError(t, d.svc.Delete(ctx, "tenant-1", "user-1"))
		testutil.AwaitPublished(t, d.runner, d.tenantID)
		require.Empty(t, d.owedLinks(t))
		require.Equal(t, revoked, d.swarf.Revoked(), "nothing more is revoked")
	})

	t.Run("a principal that never existed is a no-op", func(t *testing.T) {
		d := setup(t, nil)
		require.NoError(t, d.svc.Delete(ctx, "tenant-1", "user-1"))
		require.Empty(t, d.owedLinks(t))
		require.Empty(t, d.swarf.Revoked(), "nothing to revoke")
	})

	t.Run("a removed principal is revived by Create with nothing attached", func(t *testing.T) {
		d := setup(t, nil)
		d.principal(t, "user-1")
		alone, _ := d.writePolicy(t, allow(s3bkt.Only("user-1"), "s3:GetObject"))
		d.addKey(t, "user-1", "laptop")
		require.NoError(t, d.svc.Delete(ctx, "tenant-1", "user-1"))

		rec, created, err := d.svc.Create(ctx, "tenant-1", "user-1")
		require.NoError(t, err)
		require.True(t, created, "a revive is reported as a create")
		require.Equal(t, "user-1", rec.ExternalID)

		keys, err := d.accessKeys.ListByTenant(ctx, d.tenantID, accesskeystore.WithPrincipal("user-1"))
		require.NoError(t, err)
		require.Empty(t, keys, "the old keys are gone")
		_, err = d.policies.Get(ctx, alone)
		require.ErrorIs(t, err, store.ErrRecordNotFound, "no statement survives to restore the old access")
	})

	t.Run("succeeds while the revocation service is down", func(t *testing.T) {
		d := setup(t, nil)
		d.principal(t, "user-1")
		d.writePolicy(t, allow(s3bkt.Only("user-1"), "s3:GetObject"))
		key := d.addKey(t, "user-1", "laptop")
		held := d.held(t, key)
		require.NotEmpty(t, held)
		d.swarf.holding.Store(true)

		require.NoError(t, d.svc.Delete(ctx, "tenant-1", "user-1"))
		_, err := d.accessKeys.Get(ctx, key)
		require.ErrorIs(t, err, store.ErrRecordNotFound)
		require.ElementsMatch(t, links(held), d.owedLinks(t))
		require.Empty(t, d.swarf.Revoked())

		d.awaitPublished(t)
		require.ElementsMatch(t, links(held), d.swarf.Revoked())
	})

	t.Run("rejects an unknown tenant", func(t *testing.T) {
		d := setup(t, nil)
		require.ErrorIs(t, d.svc.Delete(ctx, "missing", "user-1"), principalsvc.ErrTenantNotFound)
	})
}

// A policy write and a removal of a principal it names, issued together, both
// succeed one after the other, whichever goes first, and leave no policy
// naming the removed principal and every other key the grants of the
// policies as they end.
func TestDeleteAndPolicyWriteTogether(t *testing.T) {
	ctx := t.Context()
	statements := func(name string) []s3bkt.Statement {
		return []s3bkt.Statement{
			{Effect: s3bkt.Allow, Principal: s3bkt.Only("user-1", "user-2"), Actions: s3bkt.NewStringSet("s3:GetObject"),
				Resources: s3bkt.NewStringSet(s3bkt.BucketARN(name), s3bkt.ObjectsARN(name))},
			{Effect: s3bkt.Allow, Principal: s3bkt.Only("user-2"), Actions: s3bkt.NewStringSet("s3:PutObject"),
				Resources: s3bkt.NewStringSet(s3bkt.BucketARN(name), s3bkt.ObjectsARN(name))},
		}
	}

	t.Run("the write first: the removal waits for it and strips what it wrote", func(t *testing.T) {
		before := &hook{}
		d := setup(t, before)
		d.principal(t, "user-1")
		d.principal(t, "user-2")
		removedKey := d.addKey(t, "user-1", "laptop")
		keptKey := d.addKey(t, "user-2", "desktop")
		bucket, name := d.bucket(t, d.tenantID)

		removed := make(chan error, 1)
		before.set(func() {
			// The write has read everything and committed nothing: a removal
			// issued now waits for it.
			go func() { removed <- d.svc.Delete(context.Background(), "tenant-1", "user-1") }()
			select {
			case err := <-removed:
				t.Errorf("the removal finished while the write was running: %v", err)
			case <-time.After(testutil.MinBlock):
			}
		})
		_, _, err := d.policySvc.Write(ctx, d.tenantID, bucket, name, s3bkt.PolicyDocument{Version: s3bkt.Version2012, Statements: statements(name)})
		require.NoError(t, err)
		select {
		case err := <-removed:
			require.NoError(t, err)
		case <-time.After(testutil.WaitTimeout):
			t.Fatal("the removal did not finish")
		}

		rec, err := d.policies.Get(ctx, bucket)
		require.NoError(t, err)
		for _, st := range rec.Policy.Statements {
			require.NotContains(t, st.Principal, "user-1")
		}
		_, err = d.accessKeys.Get(ctx, removedKey)
		require.ErrorIs(t, err, store.ErrRecordNotFound)
		require.Empty(t, d.held(t, removedKey))
		d.requireGrantsOfPolicies(t, keptKey)
		require.NotEmpty(t, d.held(t, keptKey))
	})

	t.Run("the removal first: the write waits for it and is refused for naming it", func(t *testing.T) {
		before := &hook{}
		d := setup(t, before)
		d.principal(t, "user-1")
		d.principal(t, "user-2")
		// A policy naming the principal, so the removal rewrites one and the
		// hook runs inside it.
		d.writePolicy(t, allow(s3bkt.Only("user-1", "user-2"), "s3:ListBucket"))
		keptKey := d.addKey(t, "user-2", "desktop")
		bucket, name := d.bucket(t, d.tenantID)

		written := make(chan error, 1)
		before.set(func() {
			go func() {
				_, _, err := d.policySvc.Write(context.Background(), d.tenantID, bucket, name, s3bkt.PolicyDocument{Version: s3bkt.Version2012, Statements: statements(name)})
				written <- err
			}()
			select {
			case err := <-written:
				// The service validates against the principals before it
				// submits, and the principal is still live, so a refusal here
				// would be the task's, which cannot run yet.
				t.Errorf("the write finished while the removal was running: %v", err)
			case <-time.After(testutil.MinBlock):
			}
		})
		require.NoError(t, d.svc.Delete(ctx, "tenant-1", "user-1"))
		select {
		case err := <-written:
			require.ErrorIs(t, err, s3bkt.ErrInvalidPolicy, "the write names a principal the tenant no longer has")
		case <-time.After(testutil.WaitTimeout):
			t.Fatal("the write did not finish")
		}

		_, err := d.policies.Get(ctx, bucket)
		require.ErrorIs(t, err, store.ErrRecordNotFound, "the refused write stored nothing")
		d.requireGrantsOfPolicies(t, keptKey)
	})
}

// A key creation or deletion issued while a removal of its principal runs
// waits for the removal, and then decides from what it left.
func TestDeleteDuringKeyChanges(t *testing.T) {
	ctx := t.Context()

	t.Run("a key creation for the principal is refused", func(t *testing.T) {
		before := &hook{}
		d := setup(t, before)
		d.principal(t, "user-1")
		d.writePolicy(t, allow(s3bkt.Only("user-1"), "s3:GetObject"))
		d.addKey(t, "user-1", "phone")

		created := make(chan error, 1)
		before.set(func() {
			go func() {
				_, _, err := d.keys.Create(context.Background(), "tenant-1", "laptop", nil, nil, new("user-1"), nil)
				created <- err
			}()
			select {
			case err := <-created:
				t.Errorf("the creation finished while the removal was running: %v", err)
			case <-time.After(testutil.MinBlock):
			}
		})
		require.NoError(t, d.svc.Delete(ctx, "tenant-1", "user-1"))
		select {
		case err := <-created:
			require.ErrorIs(t, err, accesskeysvc.ErrUnknownPrincipal)
		case <-time.After(testutil.WaitTimeout):
			t.Fatal("the creation did not finish")
		}

		recs, err := d.accessKeys.ListByTenant(ctx, d.tenantID)
		require.NoError(t, err)
		require.Empty(t, recs, "no key of the removed principal is left")
		var stored int
		require.NoError(t, d.pool.QueryRow(ctx, `SELECT count(*) FROM delegation`).Scan(&stored))
		require.Zero(t, stored, "no delegation outlives the keys")
	})

	t.Run("a key deletion finds the key gone and succeeds", func(t *testing.T) {
		before := &hook{}
		d := setup(t, before)
		d.principal(t, "user-1")
		d.writePolicy(t, allow(s3bkt.Only("user-1"), "s3:GetObject"))
		key := d.addKey(t, "user-1", "phone")
		held := d.held(t, key)
		require.NotEmpty(t, held)

		deleted := make(chan error, 1)
		before.set(func() {
			go func() { deleted <- d.keys.Delete(context.Background(), "tenant-1", key.Identifier()) }()
			select {
			case err := <-deleted:
				t.Errorf("the deletion finished while the removal was running: %v", err)
			case <-time.After(testutil.MinBlock):
			}
		})
		require.NoError(t, d.svc.Delete(ctx, "tenant-1", "user-1"))
		select {
		case err := <-deleted:
			// The key's row was gone by the time the service looked it up, or
			// its task found it gone: either way it no longer exists.
			if err != nil {
				require.ErrorIs(t, err, accesskeysvc.ErrAccessKeyNotFound)
			}
		case <-time.After(testutil.WaitTimeout):
			t.Fatal("the deletion did not finish")
		}

		_, err := d.accessKeys.Get(ctx, key)
		require.ErrorIs(t, err, store.ErrRecordNotFound)
		d.awaitPublished(t)
		require.ElementsMatch(t, links(held), d.swarf.Revoked(), "each grant is revoked once")
	})
}

// vanishingPrincipals runs remove before the first Get, standing in for a
// removal that commits between a create's record and its read.
type vanishingPrincipals struct {
	principalstore.Store
	remove func()
}

func (v *vanishingPrincipals) Get(ctx context.Context, tenant did.DID, externalID string) (principalstore.Record, error) {
	if v.remove != nil {
		remove := v.remove
		v.remove = nil
		remove()
	}
	return v.Store.Get(ctx, tenant, externalID)
}
