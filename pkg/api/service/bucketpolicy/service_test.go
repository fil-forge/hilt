package bucketpolicy_test

import (
	"context"
	"errors"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/fil-forge/hilt/internal/testutil"
	bucketpolicysvc "github.com/fil-forge/hilt/pkg/api/service/bucketpolicy"
	"github.com/fil-forge/hilt/pkg/bucketpolicy"
	"github.com/fil-forge/hilt/pkg/invalidation"
	"github.com/fil-forge/hilt/pkg/store"
	bucketmemory "github.com/fil-forge/hilt/pkg/store/bucket/memory"
	bucketpolicymemory "github.com/fil-forge/hilt/pkg/store/bucketpolicy/memory"
	principalstore "github.com/fil-forge/hilt/pkg/store/principal"
	principalmemory "github.com/fil-forge/hilt/pkg/store/principal/memory"
	"github.com/fil-forge/hilt/pkg/store/tenant"
	tenantmemory "github.com/fil-forge/hilt/pkg/store/tenant/memory"
	"github.com/fil-forge/ucantone/did"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

// fakeInvalidations records the principals it was asked to invalidate, and
// fails every publish once err is set. A write publishes its batch
// concurrently, so the record is kept in sorted order rather than arrival
// order.
type fakeInvalidations struct {
	mu         sync.Mutex
	err        error
	principals []string
}

func (f *fakeInvalidations) Invalidate(_ context.Context, _ did.DID, principal string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return f.err
	}
	f.principals = append(f.principals, principal)
	slices.Sort(f.principals)
	return nil
}

// blockingInvalidations never answers a publish: it blocks until the context
// is done and reports why, standing in for a revocation service that hangs.
type blockingInvalidations struct{}

func (blockingInvalidations) Invalidate(ctx context.Context, _ did.DID, _ string) error {
	<-ctx.Done()
	return ctx.Err()
}

// growingPrincipals records a new principal for the tenant right after the
// first ListByTenant answers, so the list a write takes before the bucket lock
// and the one its store callback takes differ: it stands in for a principal
// created in that gap.
type growingPrincipals struct {
	principalstore.Store
	late   string
	listed bool
}

func (g *growingPrincipals) ListByTenant(ctx context.Context, tenant did.DID) ([]principalstore.Record, error) {
	recs, err := g.Store.ListByTenant(ctx, tenant)
	if err != nil || g.listed {
		return recs, err
	}
	g.listed = true
	if err := g.Store.Add(ctx, tenant, g.late); err != nil {
		return nil, err
	}
	return recs, nil
}

type deps struct {
	svc           *bucketpolicysvc.Service
	buckets       *bucketmemory.Store
	policies      *bucketpolicymemory.Store
	principals    *principalmemory.Store
	invalidations *fakeInvalidations
	tenantID      did.DID
	otherTenant   did.DID
}

// setup wires the service over memory stores with two tenants and one bucket,
// "photos", owned by "tenant-1". wrapPrincipals, when given, wraps the memory
// principal store the service is built over.
func setup(t *testing.T, wrapPrincipals ...func(principalstore.Store) principalstore.Store) deps {
	t.Helper()
	ctx := t.Context()
	tenants := tenantmemory.New()
	tenantID, otherTenant := testutil.RandomDID(t), testutil.RandomDID(t)
	require.NoError(t, tenants.Add(ctx, tenantID, "tenant-1", testutil.RandomDID(t), tenant.Active))
	require.NoError(t, tenants.Add(ctx, otherTenant, "tenant-2", testutil.RandomDID(t), tenant.Active))

	d := deps{
		buckets:       bucketmemory.New(),
		policies:      bucketpolicymemory.New(),
		principals:    principalmemory.New(),
		invalidations: &fakeInvalidations{},
		tenantID:      tenantID,
		otherTenant:   otherTenant,
	}
	require.NoError(t, d.buckets.Add(ctx, testutil.RandomDID(t), tenantID, "photos"))
	var principals principalstore.Store = d.principals
	for _, wrap := range wrapPrincipals {
		principals = wrap(principals)
	}
	d.svc = bucketpolicysvc.New(zap.NewNop(), tenants, d.buckets, principals, d.policies, d.invalidations)
	return d
}

func (d deps) principal(t *testing.T, ids ...string) {
	t.Helper()
	for _, id := range ids {
		require.NoError(t, d.principals.Add(t.Context(), d.tenantID, id))
	}
}

func allow(principals []string, actions ...string) bucketpolicy.Statement {
	return bucketpolicy.Statement{Effect: bucketpolicy.Allow, Principals: principals, Actions: actions}
}

func deny(principals []string, actions ...string) bucketpolicy.Statement {
	return bucketpolicy.Statement{Effect: bucketpolicy.Deny, Principals: principals, Actions: actions}
}

func doc(statements ...bucketpolicy.Statement) bucketpolicy.Policy {
	return bucketpolicy.Policy{Statements: statements}
}

func TestPutAndGet(t *testing.T) {
	ctx := t.Context()

	t.Run("creates the first policy and reads it back with its ETag", func(t *testing.T) {
		d := setup(t)
		d.principal(t, "user-1")
		document := doc(allow([]string{"user-1"}, "s3:GetObject"))

		etag, created, err := d.svc.Put(ctx, "tenant-1", "photos", document, nil)
		require.NoError(t, err)
		require.True(t, created)
		require.Equal(t, bucketpolicy.ETag(document), etag)

		rec, err := d.svc.Get(ctx, "tenant-1", "photos")
		require.NoError(t, err)
		require.Equal(t, etag, rec.ETag)
		require.Equal(t, document, rec.Policy)
		require.Equal(t, "photos", rec.BucketName)
	})

	t.Run("a create over an existing policy fails and writes nothing", func(t *testing.T) {
		d := setup(t)
		d.principal(t, "user-1")
		first := doc(allow([]string{"user-1"}, "s3:GetObject"))
		etag, _, err := d.svc.Put(ctx, "tenant-1", "photos", first, nil)
		require.NoError(t, err)

		_, _, err = d.svc.Put(ctx, "tenant-1", "photos", doc(allow([]string{"user-1"}, "s3:PutObject")), nil)
		require.ErrorIs(t, err, bucketpolicysvc.ErrPreconditionFailed)

		rec, err := d.svc.Get(ctx, "tenant-1", "photos")
		require.NoError(t, err)
		require.Equal(t, etag, rec.ETag)
	})

	t.Run("a replace with a stale ETag fails and writes nothing", func(t *testing.T) {
		d := setup(t)
		d.principal(t, "user-1")
		etag, _, err := d.svc.Put(ctx, "tenant-1", "photos", doc(allow([]string{"user-1"}, "s3:GetObject")), nil)
		require.NoError(t, err)

		stale := `"deadbeef"`
		_, _, err = d.svc.Put(ctx, "tenant-1", "photos", doc(allow([]string{"user-1"}, "s3:PutObject")), &stale)
		require.ErrorIs(t, err, bucketpolicysvc.ErrPreconditionFailed)

		rec, err := d.svc.Get(ctx, "tenant-1", "photos")
		require.NoError(t, err)
		require.Equal(t, etag, rec.ETag)
	})

	t.Run("a replace with the current ETag replaces the document", func(t *testing.T) {
		d := setup(t)
		d.principal(t, "user-1")
		etag, _, err := d.svc.Put(ctx, "tenant-1", "photos", doc(allow([]string{"user-1"}, "s3:GetObject")), nil)
		require.NoError(t, err)

		next := doc(allow([]string{"user-1"}, "s3:GetObject", "s3:PutObject"))
		newETag, created, err := d.svc.Put(ctx, "tenant-1", "photos", next, &etag)
		require.NoError(t, err)
		require.False(t, created)
		require.NotEqual(t, etag, newETag)

		rec, err := d.svc.Get(ctx, "tenant-1", "photos")
		require.NoError(t, err)
		require.Equal(t, next, rec.Policy)
	})

	t.Run("rejects a document the caller may not store", func(t *testing.T) {
		d := setup(t)
		d.principal(t, "user-1")

		_, _, err := d.svc.Put(ctx, "tenant-1", "photos", doc(allow([]string{"ghost"}, "s3:GetObject")), nil)
		require.ErrorIs(t, err, bucketpolicy.ErrInvalidPolicy)

		_, _, err = d.svc.Put(ctx, "tenant-1", "photos", doc(allow([]string{"user-1"}, "s3:CreateBucket")), nil)
		require.ErrorIs(t, err, bucketpolicy.ErrInvalidPolicy)

		_, _, err = d.svc.Put(ctx, "tenant-1", "photos", bucketpolicy.Policy{}, nil)
		require.ErrorIs(t, err, bucketpolicy.ErrInvalidPolicy)

		_, err = d.svc.Get(ctx, "tenant-1", "photos")
		require.ErrorIs(t, err, bucketpolicysvc.ErrPolicyNotFound)
	})

	t.Run("an unknown tenant, bucket or policy is not found", func(t *testing.T) {
		d := setup(t)
		_, err := d.svc.Get(ctx, "missing", "photos")
		require.ErrorIs(t, err, bucketpolicysvc.ErrTenantNotFound)

		_, err = d.svc.Get(ctx, "tenant-1", "nope")
		require.ErrorIs(t, err, bucketpolicysvc.ErrBucketNotFound)

		// Another tenant's bucket is reported as missing, not as forbidden.
		_, err = d.svc.Get(ctx, "tenant-2", "photos")
		require.ErrorIs(t, err, bucketpolicysvc.ErrBucketNotFound)

		_, err = d.svc.Get(ctx, "tenant-1", "photos")
		require.ErrorIs(t, err, bucketpolicysvc.ErrPolicyNotFound)
	})
}

func TestInvalidations(t *testing.T) {
	ctx := t.Context()

	t.Run("a create invalidates the principals it grants", func(t *testing.T) {
		d := setup(t)
		d.principal(t, "user-1", "user-2", "user-3")

		_, _, err := d.svc.Put(ctx, "tenant-1", "photos",
			doc(allow([]string{"user-1", "user-2"}, "s3:GetObject")), nil)
		require.NoError(t, err)
		require.Equal(t, []string{"user-1", "user-2"}, d.invalidations.principals)
	})

	t.Run("a replace invalidates only the principals whose actions changed", func(t *testing.T) {
		d := setup(t)
		d.principal(t, "user-1", "user-2", "user-3")
		etag, _, err := d.svc.Put(ctx, "tenant-1", "photos",
			doc(allow([]string{"user-1", "user-2"}, "s3:GetObject")), nil)
		require.NoError(t, err)
		d.invalidations.principals = nil

		// user-1 keeps GetObject, user-2 gains PutObject, user-3 gains nothing.
		_, _, err = d.svc.Put(ctx, "tenant-1", "photos", doc(
			allow([]string{"user-1"}, "s3:GetObject"),
			allow([]string{"user-2"}, "s3:GetObject", "s3:PutObject"),
		), &etag)
		require.NoError(t, err)
		require.Equal(t, []string{"user-2"}, d.invalidations.principals)
	})

	t.Run("the wildcard fans out to every principal of the tenant", func(t *testing.T) {
		d := setup(t)
		d.principal(t, "user-1", "user-2", "user-3")

		_, _, err := d.svc.Put(ctx, "tenant-1", "photos",
			doc(allow([]string{bucketpolicy.Wildcard}, "s3:ListBucket")), nil)
		require.NoError(t, err)
		require.Equal(t, []string{"user-1", "user-2", "user-3"}, d.invalidations.principals)
	})

	t.Run("the wildcard reaches a principal created while the write was under way", func(t *testing.T) {
		// "user-2" appears after the pre-lock list and before the write commits.
		// Its first authorize waits on the bucket lock this write holds, so the
		// invalidation published from inside the lock still reaches it in time.
		d := setup(t, func(s principalstore.Store) principalstore.Store {
			return &growingPrincipals{Store: s, late: "user-2"}
		})
		d.principal(t, "user-1")

		_, _, err := d.svc.Put(ctx, "tenant-1", "photos",
			doc(allow([]string{bucketpolicy.Wildcard}, "s3:ListBucket")), nil)
		require.NoError(t, err)
		require.Equal(t, []string{"user-1", "user-2"}, d.invalidations.principals)
	})

	t.Run("a Deny narrowing the wildcard invalidates only the denied principal", func(t *testing.T) {
		d := setup(t)
		d.principal(t, "user-1", "user-2", "user-3")
		etag, _, err := d.svc.Put(ctx, "tenant-1", "photos",
			doc(allow([]string{bucketpolicy.Wildcard}, "s3:ListBucket")), nil)
		require.NoError(t, err)
		d.invalidations.principals = nil

		_, _, err = d.svc.Put(ctx, "tenant-1", "photos", doc(
			allow([]string{bucketpolicy.Wildcard}, "s3:ListBucket"),
			deny([]string{"user-2"}, "s3:ListBucket"),
		), &etag)
		require.NoError(t, err)
		require.Equal(t, []string{"user-2"}, d.invalidations.principals)
	})

	t.Run("a delete invalidates every principal the policy reached", func(t *testing.T) {
		d := setup(t)
		d.principal(t, "user-1", "user-2")
		etag, _, err := d.svc.Put(ctx, "tenant-1", "photos",
			doc(allow([]string{"user-1", "user-2"}, "s3:GetObject")), nil)
		require.NoError(t, err)
		d.invalidations.principals = nil

		require.NoError(t, d.svc.Delete(ctx, "tenant-1", "photos", etag))
		require.Equal(t, []string{"user-1", "user-2"}, d.invalidations.principals)

		_, err = d.svc.Get(ctx, "tenant-1", "photos")
		require.ErrorIs(t, err, bucketpolicysvc.ErrPolicyNotFound)
	})

	t.Run("a delete with a stale ETag fails, publishes nothing and keeps the policy", func(t *testing.T) {
		d := setup(t)
		d.principal(t, "user-1")
		etag, _, err := d.svc.Put(ctx, "tenant-1", "photos", doc(allow([]string{"user-1"}, "s3:GetObject")), nil)
		require.NoError(t, err)
		d.invalidations.principals = nil

		require.ErrorIs(t, d.svc.Delete(ctx, "tenant-1", "photos", `"stale"`), bucketpolicysvc.ErrPreconditionFailed)
		require.Empty(t, d.invalidations.principals)

		rec, err := d.svc.Get(ctx, "tenant-1", "photos")
		require.NoError(t, err)
		require.Equal(t, etag, rec.ETag)
	})

	t.Run("a publish failure leaves the old document in place", func(t *testing.T) {
		d := setup(t)
		d.principal(t, "user-1", "user-2")
		etag, _, err := d.svc.Put(ctx, "tenant-1", "photos", doc(allow([]string{"user-1"}, "s3:GetObject")), nil)
		require.NoError(t, err)
		d.invalidations.err = errors.New("swarf unreachable")

		_, _, err = d.svc.Put(ctx, "tenant-1", "photos",
			doc(allow([]string{"user-1", "user-2"}, "s3:GetObject", "s3:PutObject")), &etag)
		require.ErrorContains(t, err, "swarf unreachable")

		rec, err := d.svc.Get(ctx, "tenant-1", "photos")
		require.NoError(t, err)
		require.Equal(t, etag, rec.ETag, "the old document must survive")
		require.Equal(t, doc(allow([]string{"user-1"}, "s3:GetObject")), rec.Policy)

		require.ErrorContains(t, d.svc.Delete(ctx, "tenant-1", "photos", etag), "swarf unreachable")
		_, err = d.svc.Get(ctx, "tenant-1", "photos")
		require.NoError(t, err, "a failed delete must leave the policy")
	})

	t.Run("a batch of publishes that never answer fails the write at the batch deadline", func(t *testing.T) {
		d := setup(t)
		// More principals than are published at once, so a per-publish deadline
		// would take several times longer than the batch deadline.
		d.principal(t, "user-1", "user-2", "user-3", "user-4", "user-5", "user-6")
		old := doc(allow([]string{"user-1"}, "s3:GetObject"))
		etag, _, err := d.svc.Put(ctx, "tenant-1", "photos", old, nil)
		require.NoError(t, err)

		tenants := tenantmemory.New()
		require.NoError(t, tenants.Add(ctx, d.tenantID, "tenant-1", testutil.RandomDID(t), tenant.Active))
		svc := bucketpolicysvc.New(zap.NewNop(), tenants, d.buckets, d.principals, d.policies, blockingInvalidations{})

		start := time.Now()
		_, _, err = svc.Put(ctx, "tenant-1", "photos", doc(allow([]string{"*"}, "s3:GetObject")), &etag)
		elapsed := time.Since(start)
		require.ErrorIs(t, err, context.DeadlineExceeded)
		require.Less(t, elapsed, invalidation.BatchTimeout+2*time.Second,
			"the write must give up at the batch deadline, not one publish deadline per principal")
		require.Less(t, elapsed, store.LockTimeout, "the write must release the bucket before a reader gives up")

		rec, err := d.svc.Get(ctx, "tenant-1", "photos")
		require.NoError(t, err)
		require.Equal(t, old, rec.Policy, "the old document must survive")
		require.Equal(t, etag, rec.ETag)
	})

	t.Run("a create whose first publish fails writes no policy", func(t *testing.T) {
		d := setup(t)
		d.principal(t, "user-1")
		d.invalidations.err = errors.New("swarf unreachable")

		_, _, err := d.svc.Put(ctx, "tenant-1", "photos", doc(allow([]string{"user-1"}, "s3:GetObject")), nil)
		require.ErrorContains(t, err, "swarf unreachable")

		_, err = d.svc.Get(ctx, "tenant-1", "photos")
		require.ErrorIs(t, err, bucketpolicysvc.ErrPolicyNotFound)
	})
}

func TestPrincipalReads(t *testing.T) {
	ctx := t.Context()

	// twoBuckets adds a second bucket, "backups", and a policy on each: photos
	// names user-1 explicitly, backups names the wildcard and denies user-2.
	twoBuckets := func(t *testing.T) deps {
		d := setup(t)
		d.principal(t, "user-1", "user-2")
		require.NoError(t, d.buckets.Add(ctx, testutil.RandomDID(t), d.tenantID, "backups"))
		_, _, err := d.svc.Put(ctx, "tenant-1", "photos", doc(allow([]string{"user-1"}, "s3:GetObject")), nil)
		require.NoError(t, err)
		_, _, err = d.svc.Put(ctx, "tenant-1", "backups", doc(
			allow([]string{bucketpolicy.Wildcard}, "s3:ListBucket"),
			deny([]string{"user-2"}, "s3:ListBucket"),
		), nil)
		require.NoError(t, err)
		return d
	}

	t.Run("lists the policies naming the principal or the wildcard, by bucket", func(t *testing.T) {
		d := twoBuckets(t)

		recs, err := d.svc.ListByPrincipal(ctx, "tenant-1", "user-1")
		require.NoError(t, err)
		require.Len(t, recs, 2)
		require.Equal(t, "backups", recs[0].BucketName)
		require.Equal(t, "photos", recs[1].BucketName)

		// user-2 is named by the wildcard on backups only.
		recs, err = d.svc.ListByPrincipal(ctx, "tenant-1", "user-2")
		require.NoError(t, err)
		require.Len(t, recs, 1)
		require.Equal(t, "backups", recs[0].BucketName)
	})

	t.Run("reports the effective actions per bucket and omits the empty ones", func(t *testing.T) {
		d := twoBuckets(t)

		access, err := d.svc.Access(ctx, "tenant-1", "user-1")
		require.NoError(t, err)
		require.Equal(t, []bucketpolicysvc.Access{
			{BucketName: "backups", Actions: []string{"s3:ListBucket"}},
			{BucketName: "photos", Actions: []string{"s3:GetObject"}},
		}, access)

		// The Deny empties user-2's set on backups, its only policy.
		access, err = d.svc.Access(ctx, "tenant-1", "user-2")
		require.NoError(t, err)
		require.Empty(t, access)
	})

	t.Run("an unknown tenant or principal is not found", func(t *testing.T) {
		d := twoBuckets(t)
		_, err := d.svc.ListByPrincipal(ctx, "missing", "user-1")
		require.ErrorIs(t, err, bucketpolicysvc.ErrTenantNotFound)
		_, err = d.svc.ListByPrincipal(ctx, "tenant-1", "ghost")
		require.ErrorIs(t, err, bucketpolicysvc.ErrPrincipalNotFound)
		_, err = d.svc.Access(ctx, "tenant-1", "ghost")
		require.ErrorIs(t, err, bucketpolicysvc.ErrPrincipalNotFound)
	})
}
