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
	principalsvc "github.com/fil-forge/hilt/pkg/api/service/principal"
	"github.com/fil-forge/hilt/pkg/bucketpolicy"
	"github.com/fil-forge/hilt/pkg/grant"
	"github.com/fil-forge/hilt/pkg/s3perm"
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
	"github.com/fil-forge/ucantone/did"
	"github.com/fil-forge/ucantone/multikey"
	"github.com/fil-forge/ucantone/multikey/ed25519"
	"github.com/fil-forge/ucantone/multikey/secp256k1"
	"github.com/fil-forge/ucantone/ucan"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

// fakeSwarf records the delegations it was asked to revoke and the requests
// that carried them, and fails every publish once err is set.
type fakeSwarf struct {
	mu      sync.Mutex
	err     error
	calls   int
	revoked []ucan.Delegation
}

func (f *fakeSwarf) PublishBatch(_ context.Context, _ ucan.Issuer, revoked []ucan.Delegation) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return f.err
	}
	f.calls++
	f.revoked = append(f.revoked, revoked...)
	return nil
}

func (f *fakeSwarf) reset() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls, f.revoked = 0, nil
}

// blockingSwarf never answers a publish: it blocks until the context is done
// and reports why, standing in for a revocation service that hangs.
type blockingSwarf struct{}

func (blockingSwarf) PublishBatch(ctx context.Context, _ ucan.Issuer, _ []ucan.Delegation) error {
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

// gatedPrincipals holds the nth ListByTenant until resume is closed, closing
// reached when it gets there. A policy write makes that call from inside the
// policy store's write, so the gate parks the write holding one store and
// about to read the other.
type gatedPrincipals struct {
	principalstore.Store
	mu      sync.Mutex
	calls   int
	nth     int
	reached chan struct{}
	resume  chan struct{}
}

func (g *gatedPrincipals) ListByTenant(ctx context.Context, tenant did.DID) ([]principalstore.Record, error) {
	g.mu.Lock()
	hold := false
	g.calls++
	if g.calls == g.nth {
		hold = true
	}
	g.mu.Unlock()
	if hold {
		close(g.reached)
		<-g.resume
	}
	return g.Store.ListByTenant(ctx, tenant)
}

// signalingSwarf reports the first publish it is asked for. A principal
// removal revokes its keys' delegations first, so the signal says the removal
// is inside the principal store's write.
type signalingSwarf struct {
	*fakeSwarf
	once    sync.Once
	started chan struct{}
}

func (s *signalingSwarf) PublishBatch(ctx context.Context, issuer ucan.Issuer, revoked []ucan.Delegation) error {
	s.once.Do(func() { close(s.started) })
	return s.fakeSwarf.PublishBatch(ctx, issuer, revoked)
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
	// photos is the tenant's bucket; archive is a bucket every key holds a
	// delegation over, so a removal always has something to revoke.
	photos, archive did.DID
	// keys maps each principal-bound key to its principal.
	keys map[did.DID]string
}

// setup wires the service over memory stores with two tenants and one bucket,
// "photos", owned by "tenant-1", whose key is in the vault so the grant
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
		photos:      testutil.RandomDID(t),
		archive:     testutil.RandomDID(t),
		keys:        map[did.DID]string{},
	}
	signer, err := secp256k1.Generate()
	require.NoError(t, err)
	require.NoError(t, d.secrets.Write(ctx, vault.TenantKeyPath(tenantID), signer.Bytes()))
	d.tenant = multikey.NewIssuer(tenantID, signer)
	require.NoError(t, d.buckets.Add(ctx, d.photos, tenantID, "photos"))
	var principals principalstore.Store = d.principals
	for _, wrap := range wrapPrincipals {
		principals = wrap(principals)
	}
	d.svc = bucketpolicysvc.New(zap.NewNop(), tenants, d.buckets, principals, d.policies, d.rotator(d.swarf))
	return d
}

// rotator builds a grant rotator over the stores publishing to swarf.
func (d deps) rotator(swarf grant.RevocationPublisher) *grant.Rotator {
	return grant.NewRotator(zap.NewNop(), d.delegations, d.accessKeys, d.secrets, swarf)
}

// principal records the principals, each with one key, so a rotation of the
// principal is observable.
func (d deps) principal(t *testing.T, ids ...string) {
	t.Helper()
	for _, id := range ids {
		require.NoError(t, d.principals.Add(t.Context(), d.tenantID, id))
		d.key(t, id)
	}
}

// key stores a key bound to the principal, holding one delegation over
// archive and nothing over photos.
func (d deps) key(t *testing.T, principal string) did.DID {
	t.Helper()
	ctx := t.Context()
	signer, err := ed25519.Generate()
	require.NoError(t, err)
	id := signer.KeyDID()
	require.NoError(t, d.accessKeys.Add(ctx, accesskeystore.Input{
		ID: id, Tenant: d.tenantID, Name: fmt.Sprintf("key-%d", len(d.keys)), Principal: &principal,
	}))
	dels, err := grant.Issue(d.tenant, id, []did.DID{d.archive}, []string{"s3:GetObject"}, nil)
	require.NoError(t, err)
	require.NoError(t, d.delegations.PutBatch(ctx, dels))
	d.keys[id] = principal
	return id
}

// over returns the commands the key holds over the bucket, sorted.
func (d deps) over(t *testing.T, key, bucket did.DID) []string {
	t.Helper()
	var out []string
	for _, dlg := range d.held(t, key) {
		if dlg.Subject() == bucket {
			out = append(out, dlg.Command().String())
		}
	}
	slices.Sort(out)
	return out
}

// granted returns the principals whose keys hold something over photos, sorted.
func (d deps) granted(t *testing.T) []string {
	t.Helper()
	var out []string
	for key, principal := range d.keys {
		if len(d.over(t, key, d.photos)) > 0 {
			out = append(out, principal)
		}
	}
	slices.Sort(out)
	return slices.Compact(out)
}

// commandsFor returns the Forge commands the actions map to, sorted.
func commandsFor(actions ...string) []string {
	var out []string
	for _, c := range s3perm.CommandsFor(actions...) {
		out = append(out, c.String())
	}
	slices.Sort(out)
	return out
}

// rotated returns the principals whose keys' delegations were revoked, sorted.
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

var everyone = bucketpolicy.Everyone()

func only(ids ...string) bucketpolicy.Principal { return bucketpolicy.Only(ids...) }

func allow(p bucketpolicy.Principal, actions ...string) bucketpolicy.Statement {
	return bucketpolicy.Statement{Effect: bucketpolicy.Allow, Principal: p, Actions: actions}
}

func deny(p bucketpolicy.Principal, actions ...string) bucketpolicy.Statement {
	return bucketpolicy.Statement{Effect: bucketpolicy.Deny, Principal: p, Actions: actions}
}

func doc(statements ...bucketpolicy.Statement) bucketpolicy.Policy {
	return bucketpolicy.Policy{Statements: statements}
}

func TestPutAndGet(t *testing.T) {
	ctx := t.Context()

	t.Run("creates the first policy and reads it back with its ETag", func(t *testing.T) {
		d := setup(t)
		d.principal(t, "user-1")
		document := doc(allow(only("user-1"), "s3:GetObject"))

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
		first := doc(allow(only("user-1"), "s3:GetObject"))
		etag, _, err := d.svc.Put(ctx, "tenant-1", "photos", first, nil)
		require.NoError(t, err)

		_, _, err = d.svc.Put(ctx, "tenant-1", "photos", doc(allow(only("user-1"), "s3:PutObject")), nil)
		require.ErrorIs(t, err, bucketpolicysvc.ErrPreconditionFailed)

		rec, err := d.svc.Get(ctx, "tenant-1", "photos")
		require.NoError(t, err)
		require.Equal(t, etag, rec.ETag)
	})

	t.Run("a replace with a stale ETag fails and writes nothing", func(t *testing.T) {
		d := setup(t)
		d.principal(t, "user-1")
		etag, _, err := d.svc.Put(ctx, "tenant-1", "photos", doc(allow(only("user-1"), "s3:GetObject")), nil)
		require.NoError(t, err)

		stale := `"deadbeef"`
		_, _, err = d.svc.Put(ctx, "tenant-1", "photos", doc(allow(only("user-1"), "s3:PutObject")), &stale)
		require.ErrorIs(t, err, bucketpolicysvc.ErrPreconditionFailed)

		rec, err := d.svc.Get(ctx, "tenant-1", "photos")
		require.NoError(t, err)
		require.Equal(t, etag, rec.ETag)
	})

	t.Run("a replace with the current ETag replaces the document", func(t *testing.T) {
		d := setup(t)
		d.principal(t, "user-1")
		etag, _, err := d.svc.Put(ctx, "tenant-1", "photos", doc(allow(only("user-1"), "s3:GetObject")), nil)
		require.NoError(t, err)

		next := doc(allow(only("user-1"), "s3:GetObject", "s3:PutObject"))
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

		_, _, err := d.svc.Put(ctx, "tenant-1", "photos", doc(allow(only("ghost"), "s3:GetObject")), nil)
		require.ErrorIs(t, err, bucketpolicy.ErrInvalidPolicy)

		_, _, err = d.svc.Put(ctx, "tenant-1", "photos", doc(allow(only("user-1"), "s3:CreateBucket")), nil)
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

	t.Run("a create issues the granted principals' keys their delegations and publishes nothing", func(t *testing.T) {
		d := setup(t)
		d.principal(t, "user-1", "user-2", "user-3")

		_, _, err := d.svc.Put(ctx, "tenant-1", "photos",
			doc(allow(only("user-1", "user-2"), "s3:GetObject")), nil)
		require.NoError(t, err)
		require.Empty(t, d.swarf.revoked, "a first grant over the bucket revokes nothing")
		require.Equal(t, []string{"user-1", "user-2"}, d.granted(t))

		for key, principal := range d.keys {
			if principal == "user-3" {
				require.Empty(t, d.over(t, key, d.photos))
				continue
			}
			require.Equal(t, commandsFor("s3:GetObject"), d.over(t, key, d.photos))
			require.Equal(t, commandsFor("s3:GetObject"), d.over(t, key, d.archive), "other buckets are untouched")
		}
	})

	t.Run("a principal with several keys has each rotated", func(t *testing.T) {
		d := setup(t)
		d.principal(t, "user-1", "user-2")
		second := d.key(t, "user-1")

		etag, _, err := d.svc.Put(ctx, "tenant-1", "photos", doc(allow(only("user-1"), "s3:GetObject")), nil)
		require.NoError(t, err)
		require.Equal(t, commandsFor("s3:GetObject"), d.over(t, second, d.photos))

		_, _, err = d.svc.Put(ctx, "tenant-1", "photos", doc(allow(only("user-1"), "s3:PutObject")), &etag)
		require.NoError(t, err)
		require.Len(t, d.swarf.revoked, 2, "one revocation per key over the bucket")
		require.Equal(t, 1, d.swarf.calls, "every revocation of one write goes in one request")
		require.Equal(t, []string{"user-1"}, d.rotated())
		require.Equal(t, commandsFor("s3:PutObject"), d.over(t, second, d.photos))
	})

	t.Run("a replace rotates only the principals whose actions changed", func(t *testing.T) {
		d := setup(t)
		d.principal(t, "user-1", "user-2", "user-3")
		etag, _, err := d.svc.Put(ctx, "tenant-1", "photos",
			doc(allow(only("user-1", "user-2"), "s3:GetObject")), nil)
		require.NoError(t, err)
		d.swarf.reset()

		// user-1 keeps GetObject, user-2 gains PutObject, user-3 gains nothing.
		_, _, err = d.svc.Put(ctx, "tenant-1", "photos", doc(
			allow(only("user-1"), "s3:GetObject"),
			allow(only("user-2"), "s3:GetObject", "s3:PutObject"),
		), &etag)
		require.NoError(t, err)
		require.Equal(t, []string{"user-2"}, d.rotated())
		for key, principal := range d.keys {
			switch principal {
			case "user-1":
				require.Equal(t, commandsFor("s3:GetObject"), d.over(t, key, d.photos))
			case "user-2":
				require.Equal(t, commandsFor("s3:GetObject", "s3:PutObject"), d.over(t, key, d.photos))
			default:
				require.Empty(t, d.over(t, key, d.photos))
			}
		}
	})

	t.Run("the wildcard fans out to every principal of the tenant", func(t *testing.T) {
		d := setup(t)
		d.principal(t, "user-1", "user-2", "user-3")

		_, _, err := d.svc.Put(ctx, "tenant-1", "photos",
			doc(allow(everyone, "s3:ListBucket")), nil)
		require.NoError(t, err)
		require.Equal(t, []string{"user-1", "user-2", "user-3"}, d.granted(t))
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
			doc(allow(everyone, "s3:ListBucket")), nil)
		require.NoError(t, err)
		require.Equal(t, []string{"user-1", "user-2"}, d.granted(t))
	})

	t.Run("a Deny narrowing the wildcard rotates only the denied principal", func(t *testing.T) {
		d := setup(t)
		d.principal(t, "user-1", "user-2", "user-3")
		etag, _, err := d.svc.Put(ctx, "tenant-1", "photos",
			doc(allow(everyone, "s3:ListBucket")), nil)
		require.NoError(t, err)
		d.swarf.reset()

		_, _, err = d.svc.Put(ctx, "tenant-1", "photos", doc(
			allow(everyone, "s3:ListBucket"),
			deny(only("user-2"), "s3:ListBucket"),
		), &etag)
		require.NoError(t, err)
		require.Equal(t, []string{"user-2"}, d.rotated())
		require.Equal(t, []string{"user-1", "user-3"}, d.granted(t))
	})

	t.Run("a delete rotates every principal the policy reached", func(t *testing.T) {
		d := setup(t)
		d.principal(t, "user-1", "user-2")
		etag, _, err := d.svc.Put(ctx, "tenant-1", "photos",
			doc(allow(only("user-1", "user-2"), "s3:GetObject")), nil)
		require.NoError(t, err)
		d.swarf.reset()

		require.NoError(t, d.svc.Delete(ctx, "tenant-1", "photos", etag))
		require.Equal(t, []string{"user-1", "user-2"}, d.rotated())
		require.Equal(t, 1, d.swarf.calls)
		require.Empty(t, d.granted(t))

		_, err = d.svc.Get(ctx, "tenant-1", "photos")
		require.ErrorIs(t, err, bucketpolicysvc.ErrPolicyNotFound)
	})

	t.Run("a delete with a stale ETag fails, publishes nothing and keeps the policy", func(t *testing.T) {
		d := setup(t)
		d.principal(t, "user-1")
		etag, _, err := d.svc.Put(ctx, "tenant-1", "photos", doc(allow(only("user-1"), "s3:GetObject")), nil)
		require.NoError(t, err)
		d.swarf.reset()

		require.ErrorIs(t, d.svc.Delete(ctx, "tenant-1", "photos", `"stale"`), bucketpolicysvc.ErrPreconditionFailed)
		require.Empty(t, d.rotated())

		rec, err := d.svc.Get(ctx, "tenant-1", "photos")
		require.NoError(t, err)
		require.Equal(t, etag, rec.ETag)
	})

	t.Run("a publish failure leaves the old document and the delegations in place", func(t *testing.T) {
		d := setup(t)
		d.principal(t, "user-1", "user-2")
		etag, _, err := d.svc.Put(ctx, "tenant-1", "photos", doc(allow(only("user-1"), "s3:GetObject")), nil)
		require.NoError(t, err)
		before := map[did.DID][]string{}
		for key := range d.keys {
			before[key] = links(d.held(t, key))
		}
		d.swarf.err = errors.New("swarf unreachable")

		_, _, err = d.svc.Put(ctx, "tenant-1", "photos",
			doc(allow(only("user-1", "user-2"), "s3:GetObject", "s3:PutObject")), &etag)
		require.ErrorContains(t, err, "swarf unreachable")

		rec, err := d.svc.Get(ctx, "tenant-1", "photos")
		require.NoError(t, err)
		require.Equal(t, etag, rec.ETag, "the old document must survive")
		require.Equal(t, doc(allow(only("user-1"), "s3:GetObject")), rec.Policy)
		for key, want := range before {
			require.Equal(t, want, links(d.held(t, key)), "the delegations must survive")
		}

		require.ErrorContains(t, d.svc.Delete(ctx, "tenant-1", "photos", etag), "swarf unreachable")
		_, err = d.svc.Get(ctx, "tenant-1", "photos")
		require.NoError(t, err, "a failed delete must leave the policy")
	})

	t.Run("a batch of publishes that never answer fails the write at the batch deadline", func(t *testing.T) {
		d := setup(t)
		d.principal(t, "user-1", "user-2", "user-3")
		old := doc(allow(only("user-1"), "s3:GetObject"))
		etag, _, err := d.svc.Put(ctx, "tenant-1", "photos", old, nil)
		require.NoError(t, err)

		tenants := tenantmemory.New()
		require.NoError(t, tenants.Add(ctx, d.tenantID, "tenant-1", testutil.RandomDID(t), tenant.Active))
		svc := bucketpolicysvc.New(zap.NewNop(), tenants, d.buckets, d.principals, d.policies, d.rotator(blockingSwarf{}))

		start := time.Now()
		// user-1's actions change, so the write has revocations to publish.
		_, _, err = svc.Put(ctx, "tenant-1", "photos", doc(allow(everyone, "s3:PutObject")), &etag)
		elapsed := time.Since(start)
		// The batch deadline is reported as the retryable conflict the lock
		// timeout it runs under would be.
		require.ErrorIs(t, err, bucketpolicysvc.ErrConcurrentChange)
		require.Less(t, elapsed, grant.BatchTimeout+2*time.Second,
			"the write must give up at the batch deadline")
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

		_, _, err := svc.Put(ctx, "tenant-1", "photos", doc(allow(only("user-1"), "s3:GetObject")), nil)
		require.ErrorIs(t, err, bucketpolicy.ErrInvalidPolicy)
	})

	t.Run("a replace whose publish fails writes nothing", func(t *testing.T) {
		d := setup(t)
		d.principal(t, "user-1")
		old := doc(allow(only("user-1"), "s3:GetObject"))
		etag, _, err := d.svc.Put(ctx, "tenant-1", "photos", old, nil)
		require.NoError(t, err)
		d.swarf.err = errors.New("swarf unreachable")

		_, _, err = d.svc.Put(ctx, "tenant-1", "photos", doc(allow(only("user-1"), "s3:PutObject")), &etag)
		require.ErrorContains(t, err, "swarf unreachable")

		rec, err := d.svc.Get(ctx, "tenant-1", "photos")
		require.NoError(t, err)
		require.Equal(t, old, rec.Policy)
		for key := range d.keys {
			require.Equal(t, commandsFor("s3:GetObject"), d.over(t, key, d.photos))
		}
	})
}

// TestConcurrentPolicyWriteAndPrincipalRemoval pins the two writes against
// each other in the order that used to wedge the memory backends: the policy
// write holds the policy store and reads the principals, the removal holds the
// principal store and rewrites the policies. Neither store holds a lock across
// its callback that the other write needs, so both finish.
func TestConcurrentPolicyWriteAndPrincipalRemoval(t *testing.T) {
	reached, resume := make(chan struct{}), make(chan struct{})
	d := setup(t, func(s principalstore.Store) principalstore.Store {
		// The second list is the one the policy store's callback makes; the
		// first runs before the write takes the bucket.
		return &gatedPrincipals{Store: s, nth: 2, reached: reached, resume: resume}
	})
	d.principal(t, "user-1")

	tenants := tenantmemory.New()
	require.NoError(t, tenants.Add(t.Context(), d.tenantID, "tenant-1", testutil.RandomDID(t), tenant.Active))
	started := make(chan struct{})
	swarf := &signalingSwarf{fakeSwarf: d.swarf, started: started}
	principals := principalsvc.New(zap.NewNop(), tenants, d.principals, d.policies,
		d.accessKeys, d.secrets, d.rotator(swarf))

	put := make(chan error, 1)
	go func() {
		_, _, err := d.svc.Put(context.Background(), "tenant-1", "photos",
			doc(allow(only("user-1"), "s3:GetObject")), nil)
		put <- err
	}()
	<-reached // the write holds the policy store and is about to read the principals

	del := make(chan error, 1)
	go func() { del <- principals.Delete(context.Background(), "tenant-1", "user-1") }()
	<-started // the removal holds the principal store and is about to read the policies

	close(resume)

	deadline := time.After(30 * time.Second)
	for range 2 {
		select {
		case err := <-put:
			require.NoError(t, err)
		case err := <-del:
			require.NoError(t, err)
		case <-deadline:
			t.Fatal("the policy write and the principal removal deadlocked")
		}
	}

	// The removal ran last and took the policy with it: its only statement
	// named the principal that is gone.
	_, err := d.svc.Get(t.Context(), "tenant-1", "photos")
	require.ErrorIs(t, err, bucketpolicysvc.ErrPolicyNotFound)
}

func TestPrincipalReads(t *testing.T) {
	ctx := t.Context()

	// twoBuckets adds a second bucket, "backups", and a policy on each: photos
	// names user-1 explicitly, backups names the wildcard and denies user-2.
	twoBuckets := func(t *testing.T) deps {
		d := setup(t)
		d.principal(t, "user-1", "user-2")
		require.NoError(t, d.buckets.Add(ctx, testutil.RandomDID(t), d.tenantID, "backups"))
		_, _, err := d.svc.Put(ctx, "tenant-1", "photos", doc(allow(only("user-1"), "s3:GetObject")), nil)
		require.NoError(t, err)
		_, _, err = d.svc.Put(ctx, "tenant-1", "backups", doc(
			allow(everyone, "s3:ListBucket"),
			deny(only("user-2"), "s3:ListBucket"),
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

// links returns the CIDs of the delegations, sorted.
func links(dels []ucan.Delegation) []string {
	var out []string
	for _, d := range dels {
		out = append(out, d.Link().String())
	}
	slices.Sort(out)
	return out
}
