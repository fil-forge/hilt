package bucketpolicy_test

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/fil-forge/hilt/internal/testutil"
	bucketpolicysvc "github.com/fil-forge/hilt/pkg/api/service/bucketpolicy"
	"github.com/fil-forge/hilt/pkg/bucketpolicy"
	"github.com/fil-forge/hilt/pkg/marker"
	"github.com/fil-forge/hilt/pkg/store"
	accesskeystore "github.com/fil-forge/hilt/pkg/store/accesskey"
	accesskeymemory "github.com/fil-forge/hilt/pkg/store/accesskey/memory"
	bucketmemory "github.com/fil-forge/hilt/pkg/store/bucket/memory"
	bucketpolicystore "github.com/fil-forge/hilt/pkg/store/bucketpolicy"
	bucketpolicymemory "github.com/fil-forge/hilt/pkg/store/bucketpolicy/memory"
	delegationmemory "github.com/fil-forge/hilt/pkg/store/delegation/memory"
	principalstore "github.com/fil-forge/hilt/pkg/store/principal"
	principalmemory "github.com/fil-forge/hilt/pkg/store/principal/memory"
	"github.com/fil-forge/hilt/pkg/store/tenant"
	tenantmemory "github.com/fil-forge/hilt/pkg/store/tenant/memory"
	"github.com/fil-forge/hilt/pkg/vault"
	vaultmemory "github.com/fil-forge/hilt/pkg/vault/memory"
	swarfclient "github.com/fil-forge/swarf/pkg/client"
	"github.com/fil-forge/ucantone/did"
	"github.com/fil-forge/ucantone/multikey"
	"github.com/fil-forge/ucantone/multikey/ed25519"
	"github.com/fil-forge/ucantone/multikey/secp256k1"
	"github.com/fil-forge/ucantone/ucan"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

// fakeSwarf records the delegations it was asked to revoke, and fails every
// publish once err is set. A write publishes its batch concurrently, so the
// record is guarded.
type fakeSwarf struct {
	mu      sync.Mutex
	err     error
	revoked []ucan.Delegation
}

func (f *fakeSwarf) Publish(_ context.Context, _ ucan.Issuer, revoked ucan.Delegation, _ ...swarfclient.PublishOption) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return f.err
	}
	f.revoked = append(f.revoked, revoked)
	return nil
}

func (f *fakeSwarf) reset() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.revoked = nil
}

// blockingSwarf never answers a publish: it blocks until the context is done
// and reports why, standing in for a revocation service that hangs.
type blockingSwarf struct{}

func (blockingSwarf) Publish(ctx context.Context, _ ucan.Issuer, _ ucan.Delegation, _ ...swarfclient.PublishOption) error {
	<-ctx.Done()
	return ctx.Err()
}

// rejectingPolicies fails every Put with err, standing in for the store
// refusing the document.
type rejectingPolicies struct {
	bucketpolicystore.Store
	err error
}

func (r *rejectingPolicies) Put(context.Context, bucketpolicystore.Input, func(context.Context, *bucketpolicystore.Record) error) (string, error) {
	return "", r.err
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
	svc         *bucketpolicysvc.Service
	buckets     *bucketmemory.Store
	policies    *bucketpolicymemory.Store
	principals  *principalmemory.Store
	accessKeys  *accesskeymemory.Store
	delegations *delegationmemory.Store
	secrets     *vaultmemory.Store
	swarf       *fakeSwarf
	tenantID    did.DID
	tenant      ucan.Issuer
	otherTenant did.DID
	// keys maps each principal-bound key to its principal.
	keys map[did.DID]string
}

// setup wires the service over memory stores with two tenants and one bucket,
// "photos", owned by "tenant-1", whose key is in the vault so the marker
// rotator can sign as it. wrapPrincipals, when given, wraps the memory
// principal store the service is built over.
func setup(t *testing.T, wrapPrincipals ...func(principalstore.Store) principalstore.Store) deps {
	t.Helper()
	ctx := t.Context()
	tenants := tenantmemory.New()
	tenantID, otherTenant := testutil.RandomDID(t), testutil.RandomDID(t)
	require.NoError(t, tenants.Add(ctx, tenantID, "tenant-1", testutil.RandomDID(t), tenant.Active))
	require.NoError(t, tenants.Add(ctx, otherTenant, "tenant-2", testutil.RandomDID(t), tenant.Active))

	d := deps{
		buckets:     bucketmemory.New(),
		policies:    bucketpolicymemory.New(),
		principals:  principalmemory.New(),
		accessKeys:  accesskeymemory.New(),
		delegations: delegationmemory.New(),
		secrets:     vaultmemory.New(),
		swarf:       &fakeSwarf{},
		tenantID:    tenantID,
		otherTenant: otherTenant,
		keys:        map[did.DID]string{},
	}
	signer, err := secp256k1.Generate()
	require.NoError(t, err)
	require.NoError(t, d.secrets.Write(ctx, vault.TenantKeyPath(tenantID), signer.Bytes()))
	d.tenant = multikey.NewIssuer(tenantID, signer)
	require.NoError(t, d.buckets.Add(ctx, testutil.RandomDID(t), tenantID, "photos"))
	var principals principalstore.Store = d.principals
	for _, wrap := range wrapPrincipals {
		principals = wrap(principals)
	}
	d.svc = bucketpolicysvc.New(zap.NewNop(), tenants, d.buckets, principals, d.policies, d.rotator(d.swarf))
	return d
}

// rotator builds a marker rotator over the stores publishing to swarf.
func (d deps) rotator(swarf marker.RevocationPublisher) *marker.Rotator {
	return marker.NewRotator(zap.NewNop(), d.delegations, d.accessKeys, d.secrets, swarf)
}

// principal records the principals, each with one key holding its marker, so
// a rotation of the principal is observable.
func (d deps) principal(t *testing.T, ids ...string) {
	t.Helper()
	for _, id := range ids {
		require.NoError(t, d.principals.Add(t.Context(), d.tenantID, id))
		d.key(t, id)
	}
}

// key stores a key bound to the principal and its marker.
func (d deps) key(t *testing.T, principal string) did.DID {
	t.Helper()
	ctx := t.Context()
	signer, err := ed25519.Generate()
	require.NoError(t, err)
	id := signer.KeyDID()
	require.NoError(t, d.accessKeys.Add(ctx, accesskeystore.Input{
		ID: id, Tenant: d.tenantID, Name: fmt.Sprintf("key-%d", len(d.keys)), Principal: &principal,
	}))
	m, err := marker.Issue(d.tenant, id, d.tenantID, nil)
	require.NoError(t, err)
	require.NoError(t, d.delegations.PutBatch(ctx, []ucan.Delegation{m}))
	d.keys[id] = principal
	return id
}

// rotated returns the principals whose keys' markers were revoked, sorted.
func (d deps) rotated() []string {
	d.swarf.mu.Lock()
	defer d.swarf.mu.Unlock()
	var out []string
	for _, r := range d.swarf.revoked {
		out = append(out, d.keys[r.Audience()])
	}
	slices.Sort(out)
	return slices.Compact(out)
}

// held returns the delegations the key holds.
func (d deps) held(t *testing.T, key did.DID) []ucan.Delegation {
	t.Helper()
	page, err := d.delegations.ListByAudience(t.Context(), key)
	require.NoError(t, err)
	return page.Results
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

func TestRotations(t *testing.T) {
	ctx := t.Context()

	t.Run("a create rotates the markers of the principals it grants", func(t *testing.T) {
		d := setup(t)
		d.principal(t, "user-1", "user-2", "user-3")

		_, _, err := d.svc.Put(ctx, "tenant-1", "photos",
			doc(allow([]string{"user-1", "user-2"}, "s3:GetObject")), nil)
		require.NoError(t, err)
		require.Equal(t, []string{"user-1", "user-2"}, d.rotated())

		// Each rotated key holds a fresh marker; the other key keeps its own.
		revoked := map[did.DID]ucan.Delegation{}
		for _, r := range d.swarf.revoked {
			revoked[r.Audience()] = r
		}
		for key, principal := range d.keys {
			held := d.held(t, key)
			require.Len(t, held, 1)
			require.Equal(t, marker.Command, held[0].Command())
			if principal == "user-3" {
				require.NotContains(t, revoked, key)
				continue
			}
			require.NotEqual(t, revoked[key].Link(), held[0].Link(), "%s holds a fresh marker", principal)
		}
	})

	t.Run("a principal with several keys has each rotated", func(t *testing.T) {
		d := setup(t)
		d.principal(t, "user-1", "user-2")
		second := d.key(t, "user-1")

		_, _, err := d.svc.Put(ctx, "tenant-1", "photos", doc(allow([]string{"user-1"}, "s3:GetObject")), nil)
		require.NoError(t, err)

		require.Len(t, d.swarf.revoked, 2)
		require.Equal(t, []string{"user-1"}, d.rotated())
		require.Len(t, d.held(t, second), 1)
	})

	t.Run("a replace rotates only the principals whose actions changed", func(t *testing.T) {
		d := setup(t)
		d.principal(t, "user-1", "user-2", "user-3")
		etag, _, err := d.svc.Put(ctx, "tenant-1", "photos",
			doc(allow([]string{"user-1", "user-2"}, "s3:GetObject")), nil)
		require.NoError(t, err)
		d.swarf.reset()

		// user-1 keeps GetObject, user-2 gains PutObject, user-3 gains nothing.
		_, _, err = d.svc.Put(ctx, "tenant-1", "photos", doc(
			allow([]string{"user-1"}, "s3:GetObject"),
			allow([]string{"user-2"}, "s3:GetObject", "s3:PutObject"),
		), &etag)
		require.NoError(t, err)
		require.Equal(t, []string{"user-2"}, d.rotated())
	})

	t.Run("the wildcard fans out to every principal of the tenant", func(t *testing.T) {
		d := setup(t)
		d.principal(t, "user-1", "user-2", "user-3")

		_, _, err := d.svc.Put(ctx, "tenant-1", "photos",
			doc(allow([]string{bucketpolicy.Wildcard}, "s3:ListBucket")), nil)
		require.NoError(t, err)
		require.Equal(t, []string{"user-1", "user-2", "user-3"}, d.rotated())
	})

	t.Run("the wildcard reaches a principal created while the write was under way", func(t *testing.T) {
		// "user-2" appears after the pre-lock list and before the write commits.
		// Its first authorize waits on the bucket lock this write holds, so the
		// rotation from inside the lock still reaches it in time.
		d := setup(t, func(s principalstore.Store) principalstore.Store {
			return &growingPrincipals{Store: s, late: "user-2"}
		})
		d.principal(t, "user-1")
		// user-2's key is there for the rotation to find once the principal is.
		d.key(t, "user-2")

		_, _, err := d.svc.Put(ctx, "tenant-1", "photos",
			doc(allow([]string{bucketpolicy.Wildcard}, "s3:ListBucket")), nil)
		require.NoError(t, err)
		require.Equal(t, []string{"user-1", "user-2"}, d.rotated())
	})

	t.Run("a Deny narrowing the wildcard rotates only the denied principal", func(t *testing.T) {
		d := setup(t)
		d.principal(t, "user-1", "user-2", "user-3")
		etag, _, err := d.svc.Put(ctx, "tenant-1", "photos",
			doc(allow([]string{bucketpolicy.Wildcard}, "s3:ListBucket")), nil)
		require.NoError(t, err)
		d.swarf.reset()

		_, _, err = d.svc.Put(ctx, "tenant-1", "photos", doc(
			allow([]string{bucketpolicy.Wildcard}, "s3:ListBucket"),
			deny([]string{"user-2"}, "s3:ListBucket"),
		), &etag)
		require.NoError(t, err)
		require.Equal(t, []string{"user-2"}, d.rotated())
	})

	t.Run("a delete rotates every principal the policy reached", func(t *testing.T) {
		d := setup(t)
		d.principal(t, "user-1", "user-2")
		etag, _, err := d.svc.Put(ctx, "tenant-1", "photos",
			doc(allow([]string{"user-1", "user-2"}, "s3:GetObject")), nil)
		require.NoError(t, err)
		d.swarf.reset()

		require.NoError(t, d.svc.Delete(ctx, "tenant-1", "photos", etag))
		require.Equal(t, []string{"user-1", "user-2"}, d.rotated())

		_, err = d.svc.Get(ctx, "tenant-1", "photos")
		require.ErrorIs(t, err, bucketpolicysvc.ErrPolicyNotFound)
	})

	t.Run("a delete with a stale ETag fails, publishes nothing and keeps the policy", func(t *testing.T) {
		d := setup(t)
		d.principal(t, "user-1")
		etag, _, err := d.svc.Put(ctx, "tenant-1", "photos", doc(allow([]string{"user-1"}, "s3:GetObject")), nil)
		require.NoError(t, err)
		d.swarf.reset()

		require.ErrorIs(t, d.svc.Delete(ctx, "tenant-1", "photos", `"stale"`), bucketpolicysvc.ErrPreconditionFailed)
		require.Empty(t, d.rotated())

		rec, err := d.svc.Get(ctx, "tenant-1", "photos")
		require.NoError(t, err)
		require.Equal(t, etag, rec.ETag)
	})

	t.Run("a publish failure leaves the old document and the markers in place", func(t *testing.T) {
		d := setup(t)
		d.principal(t, "user-1", "user-2")
		etag, _, err := d.svc.Put(ctx, "tenant-1", "photos", doc(allow([]string{"user-1"}, "s3:GetObject")), nil)
		require.NoError(t, err)
		before := map[did.DID]ucan.Delegation{}
		for key := range d.keys {
			before[key] = d.held(t, key)[0]
		}
		d.swarf.err = errors.New("swarf unreachable")

		_, _, err = d.svc.Put(ctx, "tenant-1", "photos",
			doc(allow([]string{"user-1", "user-2"}, "s3:GetObject", "s3:PutObject")), &etag)
		require.ErrorContains(t, err, "swarf unreachable")

		rec, err := d.svc.Get(ctx, "tenant-1", "photos")
		require.NoError(t, err)
		require.Equal(t, etag, rec.ETag, "the old document must survive")
		require.Equal(t, doc(allow([]string{"user-1"}, "s3:GetObject")), rec.Policy)
		for key, m := range before {
			held := d.held(t, key)
			require.Len(t, held, 1)
			require.Equal(t, m.Link(), held[0].Link(), "the marker must survive")
		}

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
		svc := bucketpolicysvc.New(zap.NewNop(), tenants, d.buckets, d.principals, d.policies, d.rotator(blockingSwarf{}))

		start := time.Now()
		_, _, err = svc.Put(ctx, "tenant-1", "photos", doc(allow([]string{"*"}, "s3:GetObject")), &etag)
		elapsed := time.Since(start)
		// The batch deadline is reported as the retryable conflict the lock
		// timeout it runs under would be.
		require.ErrorIs(t, err, bucketpolicysvc.ErrConcurrentChange)
		require.Less(t, elapsed, marker.BatchTimeout+2*time.Second,
			"the write must give up at the batch deadline, not one publish deadline per principal")
		require.Less(t, elapsed, store.LockTimeout, "the write must release the bucket before a reader gives up")

		rec, err := d.svc.Get(ctx, "tenant-1", "photos")
		require.NoError(t, err)
		require.Equal(t, old, rec.Policy, "the old document must survive")
		require.Equal(t, etag, rec.ETag)
	})

	t.Run("a principal removed between validation and the write is an invalid policy", func(t *testing.T) {
		d := setup(t)
		d.principal(t, "user-1")
		tenants := tenantmemory.New()
		require.NoError(t, tenants.Add(ctx, d.tenantID, "tenant-1", testutil.RandomDID(t), tenant.Active))
		// The store's index foreign key refuses a document naming a principal
		// that is gone; the memory store does not check it, so stand in for it.
		policies := &rejectingPolicies{Store: d.policies, err: store.ErrInvalidArgument}
		svc := bucketpolicysvc.New(zap.NewNop(), tenants, d.buckets, d.principals, policies, d.rotator(d.swarf))

		_, _, err := svc.Put(ctx, "tenant-1", "photos", doc(allow([]string{"user-1"}, "s3:GetObject")), nil)
		require.ErrorIs(t, err, bucketpolicy.ErrInvalidPolicy)
	})

	t.Run("a create whose first publish fails writes no policy", func(t *testing.T) {
		d := setup(t)
		d.principal(t, "user-1")
		d.swarf.err = errors.New("swarf unreachable")

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
