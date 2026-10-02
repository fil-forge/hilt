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
	accesskeysvc "github.com/fil-forge/hilt/pkg/api/service/accesskey"
	bucketpolicysvc "github.com/fil-forge/hilt/pkg/api/service/bucketpolicy"
	principalsvc "github.com/fil-forge/hilt/pkg/api/service/principal"
	"github.com/fil-forge/hilt/pkg/bucketpolicy"
	"github.com/fil-forge/hilt/pkg/grant"
	"github.com/fil-forge/hilt/pkg/s3perm"
	"github.com/fil-forge/hilt/pkg/store"
	accesskeystore "github.com/fil-forge/hilt/pkg/store/accesskey"
	accesskeymemory "github.com/fil-forge/hilt/pkg/store/accesskey/memory"
	accesskeypostgres "github.com/fil-forge/hilt/pkg/store/accesskey/postgres"
	bucketmemory "github.com/fil-forge/hilt/pkg/store/bucket/memory"
	bucketpostgres "github.com/fil-forge/hilt/pkg/store/bucket/postgres"
	bucketpolicystore "github.com/fil-forge/hilt/pkg/store/bucketpolicy"
	bucketpolicymemory "github.com/fil-forge/hilt/pkg/store/bucketpolicy/memory"
	bucketpolicypostgres "github.com/fil-forge/hilt/pkg/store/bucketpolicy/postgres"
	delegationmemory "github.com/fil-forge/hilt/pkg/store/delegation/memory"
	delegationpostgres "github.com/fil-forge/hilt/pkg/store/delegation/postgres"
	principalstore "github.com/fil-forge/hilt/pkg/store/principal"
	principalmemory "github.com/fil-forge/hilt/pkg/store/principal/memory"
	principalpostgres "github.com/fil-forge/hilt/pkg/store/principal/postgres"
	providerpostgres "github.com/fil-forge/hilt/pkg/store/provider/postgres"
	"github.com/fil-forge/hilt/pkg/store/tenant"
	tenantmemory "github.com/fil-forge/hilt/pkg/store/tenant/memory"
	tenantpostgres "github.com/fil-forge/hilt/pkg/store/tenant/postgres"
	"github.com/fil-forge/hilt/pkg/vault"
	vaultmemory "github.com/fil-forge/hilt/pkg/vault/memory"
	"github.com/fil-forge/ucantone/did"
	"github.com/fil-forge/ucantone/multikey"
	"github.com/fil-forge/ucantone/multikey/ed25519"
	"github.com/fil-forge/ucantone/multikey/secp256k1"
	"github.com/fil-forge/ucantone/ucan"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

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

// parkedPolicies holds Put until resume is closed, closing reached when it
// gets there. It parks before the wrapped store takes its lock, so the write
// has validated its document and holds nothing.
type parkedPolicies struct {
	bucketpolicystore.Store
	reached chan struct{}
	resume  chan struct{}
}

func (p *parkedPolicies) Put(ctx context.Context, in bucketpolicystore.Input, beforeCommit func(context.Context, *bucketpolicystore.Record) error) (string, error) {
	close(p.reached)
	<-p.resume
	return p.Store.Put(ctx, in, beforeCommit)
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
// reached when it gets there; with after set it holds once that call has
// returned. A policy write makes that call from inside the policy store's
// write, so the gate parks the write holding one store and about to read the
// other, or having read it.
type gatedPrincipals struct {
	principalstore.Store
	mu      sync.Mutex
	calls   int
	nth     int
	after   bool
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
	if hold && !g.after {
		close(g.reached)
		<-g.resume
	}
	recs, err := g.Store.ListByTenant(ctx, tenant)
	if hold && g.after {
		close(g.reached)
		<-g.resume
	}
	return recs, err
}

type deps struct {
	svc         *bucketpolicysvc.Service
	buckets     *bucketmemory.Store
	policies    *bucketpolicymemory.Store
	principals  *principalmemory.Store
	accessKeys  *accesskeymemory.Store
	delegations *delegationmemory.Store
	secrets     *vaultmemory.Store
	swarf       *testutil.FakeSwarf
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
		swarf:       &testutil.FakeSwarf{},
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
	var out []string
	for _, r := range d.swarf.Revocations() {
		out = append(out, d.keys[r.Delegation.Audience()])
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

	t.Run("an unconditional put creates or replaces without a tag", func(t *testing.T) {
		d := setup(t)
		d.principal(t, "user-1")
		first := doc(allow(only("user-1"), "s3:GetObject"))
		etag, created, err := d.svc.Put(ctx, "tenant-1", "photos", first, nil, bucketpolicysvc.Unconditional())
		require.NoError(t, err)
		require.True(t, created)
		require.Equal(t, bucketpolicy.ETag(first), etag)

		second := doc(allow(only("user-1"), "s3:PutObject"))
		stale := `"stale"`
		etag, created, err = d.svc.Put(ctx, "tenant-1", "photos", second, &stale, bucketpolicysvc.Unconditional())
		require.NoError(t, err, "the tag is ignored")
		require.False(t, created)
		require.Equal(t, bucketpolicy.ETag(second), etag)
		rec, err := d.svc.Get(ctx, "tenant-1", "photos")
		require.NoError(t, err)
		require.Equal(t, second, rec.Policy)
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
		require.Empty(t, d.swarf.Revocations(), "a first grant over the bucket revokes nothing")
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
		require.Len(t, d.swarf.Revocations(), 2, "one revocation per key over the bucket")
		require.Equal(t, 1, d.swarf.Calls(), "every revocation of one write goes in one request")
		require.Equal(t, []string{"user-1"}, d.rotated())
		require.Equal(t, commandsFor("s3:PutObject"), d.over(t, second, d.photos))
	})

	t.Run("a replace rotates only the principals whose actions changed", func(t *testing.T) {
		d := setup(t)
		d.principal(t, "user-1", "user-2", "user-3")
		etag, _, err := d.svc.Put(ctx, "tenant-1", "photos",
			doc(allow(only("user-1", "user-2"), "s3:GetObject")), nil)
		require.NoError(t, err)
		d.swarf.Reset()

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
		d.swarf.Reset()

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
		d.swarf.Reset()

		require.NoError(t, d.svc.Delete(ctx, "tenant-1", "photos", etag))
		require.Equal(t, []string{"user-1", "user-2"}, d.rotated())
		require.Equal(t, 1, d.swarf.Calls())
		require.Empty(t, d.granted(t))

		_, err = d.svc.Get(ctx, "tenant-1", "photos")
		require.ErrorIs(t, err, bucketpolicysvc.ErrPolicyNotFound)
	})

	t.Run("a delete with a stale ETag fails, publishes nothing and keeps the policy", func(t *testing.T) {
		d := setup(t)
		d.principal(t, "user-1")
		etag, _, err := d.svc.Put(ctx, "tenant-1", "photos", doc(allow(only("user-1"), "s3:GetObject")), nil)
		require.NoError(t, err)
		d.swarf.Reset()

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
		d.swarf.Err = errors.New("swarf unreachable")

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
		d.swarf.Err = errors.New("swarf unreachable")

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

// TestConcurrentPolicyWriteAndPrincipalRemoval runs a policy write against the
// removal of a principal it names: the write holds the bucket while it reads
// and locks the principals, and the removal rewrites that bucket's policy. The
// removal strips its policies before it locks the principal, so neither waits
// on what the other holds and both finish.
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
	// A principal removal revokes its keys' delegations first, so the first
	// publish says the removal has started and is about to strip its policies.
	d.swarf.OnPublish = sync.OnceFunc(func() { close(started) })
	principals := principalsvc.New(zap.NewNop(), tenants, d.principals, d.policies,
		d.accessKeys, d.delegations, d.secrets, d.swarf, d.rotator(d.swarf))

	put := make(chan error, 1)
	go func() {
		_, _, err := d.svc.Put(context.Background(), "tenant-1", "photos",
			doc(allow(only("user-1"), "s3:GetObject")), nil)
		put <- err
	}()
	<-reached // the write holds the policy store and is about to read the principals

	del := make(chan error, 1)
	go func() { del <- principals.Delete(context.Background(), "tenant-1", "user-1") }()
	<-started // the removal has revoked and is about to read the policies

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

// TestPolicyWriteAfterPrincipalRemoval removes a principal after a policy
// write naming it has validated its document and before the write reaches the
// store. The write must fail, so a principal revived under the same id starts
// named in no statement.
func TestPolicyWriteAfterPrincipalRemoval(t *testing.T) {
	ctx := t.Context()
	d := setup(t)
	d.principal(t, "user-1")
	tenants := tenantmemory.New()
	require.NoError(t, tenants.Add(ctx, d.tenantID, "tenant-1", testutil.RandomDID(t), tenant.Active))
	policies := &parkedPolicies{Store: d.policies, reached: make(chan struct{}), resume: make(chan struct{})}
	svc := bucketpolicysvc.New(zap.NewNop(), tenants, d.buckets, d.principals, policies, d.rotator(d.swarf))
	principals := principalsvc.New(zap.NewNop(), tenants, d.principals, d.policies,
		d.accessKeys, d.delegations, d.secrets, d.swarf, d.rotator(d.swarf))

	put := make(chan error, 1)
	go func() {
		_, _, err := svc.Put(context.Background(), "tenant-1", "photos",
			doc(allow(only("user-1"), "s3:GetObject")), nil)
		put <- err
	}()
	<-policies.reached
	require.NoError(t, principals.Delete(ctx, "tenant-1", "user-1"))
	close(policies.resume)
	require.ErrorIs(t, <-put, bucketpolicy.ErrInvalidPolicy)

	_, created, err := principals.Create(ctx, "tenant-1", "user-1")
	require.NoError(t, err)
	require.True(t, created)
	access, err := svc.Access(ctx, "tenant-1", "user-1")
	require.NoError(t, err)
	require.Empty(t, access, "a revived principal is named in no statement")
}

// TestPrincipalAddedDuringPolicyWritePostgres adds a principal while a policy
// write granting the wildcard is parked after its callback listed the
// tenant's principals, so the write cannot rotate the new principal's keys.
// The add waits for the write to commit, and the key created for the
// principal afterwards reads the committed policy and holds its grants.
func TestPrincipalAddedDuringPolicyWritePostgres(t *testing.T) {
	pool := testutil.PostgresOrSkip(t)
	ctx := t.Context()
	d := setup(t)
	// The rows the policy tables reference, under the memory setup's DIDs.
	providerID := testutil.RandomDID(t)
	require.NoError(t, providerpostgres.New(pool).Add(ctx, providerID, "us-east-1", nil))
	require.NoError(t, tenantpostgres.New(pool).Add(ctx, d.tenantID, "tenant-1", providerID, tenant.Active))
	require.NoError(t, bucketpostgres.New(pool).Add(ctx, d.photos, d.tenantID, "photos"))
	tenants := tenantmemory.New()
	require.NoError(t, tenants.Add(ctx, d.tenantID, "tenant-1", providerID, tenant.Active))
	principals := principalpostgres.New(pool)
	policies := bucketpolicypostgres.New(pool)

	// The second list is the one the policy store's callback makes.
	reached, resume := make(chan struct{}), make(chan struct{})
	gated := &gatedPrincipals{Store: principals, nth: 2, after: true, reached: reached, resume: resume}
	svc := bucketpolicysvc.New(zap.NewNop(), tenants, d.buckets, gated, policies, d.rotator(d.swarf))
	keys := accesskeysvc.New(zap.NewNop(), tenants, d.accessKeys, principals, d.buckets, policies, d.delegations, d.secrets, d.swarf)

	written, added := testutil.RequireWaitsForWriter(t,
		func(entered chan<- struct{}, release <-chan struct{}) error {
			go func() { <-reached; close(entered) }()
			go func() { <-release; close(resume) }()
			_, _, err := svc.Put(context.Background(), "tenant-1", "photos", doc(allow(everyone, "s3:GetObject")), nil)
			return err
		},
		func() error {
			return principals.Add(context.Background(), d.tenantID, "user-2")
		})
	require.NoError(t, written)
	require.NoError(t, added)

	rec, _, err := keys.Create(ctx, "tenant-1", "key", nil, nil, "user-2", nil)
	require.NoError(t, err)
	require.Equal(t, commandsFor("s3:GetObject"), d.over(t, rec.ID, d.photos), "the key is created from the committed policy")
}

// postgresDeps is the memory setup's world on Postgres: the rows the policy
// tables reference under the setup's DIDs, and the stores a write's callback
// joins the transaction of.
type postgresDeps struct {
	tenants     *tenantmemory.Store
	principals  *principalpostgres.Store
	policies    *bucketpolicypostgres.Store
	accessKeys  *accesskeypostgres.Store
	delegations *delegationpostgres.Store
}

func (d deps) postgres(t *testing.T, pool *pgxpool.Pool) postgresDeps {
	t.Helper()
	ctx := t.Context()
	providerID := testutil.RandomDID(t)
	require.NoError(t, providerpostgres.New(pool).Add(ctx, providerID, "us-east-1", nil))
	require.NoError(t, tenantpostgres.New(pool).Add(ctx, d.tenantID, "tenant-1", providerID, tenant.Active))
	require.NoError(t, bucketpostgres.New(pool).Add(ctx, d.photos, d.tenantID, "photos"))
	tenants := tenantmemory.New()
	require.NoError(t, tenants.Add(ctx, d.tenantID, "tenant-1", providerID, tenant.Active))
	return postgresDeps{
		tenants:     tenants,
		principals:  principalpostgres.New(pool),
		policies:    bucketpolicypostgres.New(pool),
		accessKeys:  accesskeypostgres.New(pool),
		delegations: delegationpostgres.New(pool),
	}
}

// over returns the commands the key holds over the bucket in the Postgres
// delegation store, sorted.
func (p postgresDeps) over(t *testing.T, key, bucket did.DID) []string {
	t.Helper()
	page, err := p.delegations.ListByAudience(t.Context(), key)
	require.NoError(t, err)
	var out []string
	for _, dlg := range page.Results {
		if dlg.Subject() == bucket {
			out = append(out, dlg.Command().String())
		}
	}
	slices.Sort(out)
	return out
}

// afterLock calls after once, when the first Lock returns: under a policy
// write that is after the rotation and before the document is written, with
// the write's transaction still open.
type afterLock struct {
	principalstore.Store
	after func()
}

func (a *afterLock) Lock(ctx context.Context, tenant did.DID, ids []string, fn func(context.Context) error) error {
	err := a.Store.Lock(ctx, tenant, ids, fn)
	if a.after != nil {
		after := a.after
		a.after = nil
		after()
	}
	return err
}

// TestPolicyWriteCancelledAfterRotationPostgres cancels a policy write once
// its rotation has run and its principal lock call has returned, before the
// document is written. The rotation's delegation writes joined the policy
// transaction, so the old policy stays with its own grants: a principal is
// never left with the grants of a policy that was not stored.
func TestPolicyWriteCancelledAfterRotationPostgres(t *testing.T) {
	pool := testutil.PostgresOrSkip(t)
	ctx := t.Context()
	d := setup(t)
	pg := d.postgres(t, pool)
	require.NoError(t, pg.principals.Add(ctx, d.tenantID, "user-1"))
	key := testutil.RandomDID(t)
	user := "user-1"
	require.NoError(t, pg.accessKeys.Add(ctx, accesskeystore.Input{ID: key, Tenant: d.tenantID, Name: "laptop", Principal: &user}))

	rotator := grant.NewRotator(zap.NewNop(), pg.delegations, pg.accessKeys, d.secrets, d.swarf)
	svc := bucketpolicysvc.New(zap.NewNop(), pg.tenants, d.buckets, pg.principals, pg.policies, rotator)
	etagA, _, err := svc.Put(ctx, "tenant-1", "photos", doc(allow(only("user-1"), "s3:GetObject", "s3:ListBucket")), nil)
	require.NoError(t, err)
	require.Equal(t, commandsFor("s3:GetObject", "s3:ListBucket"), pg.over(t, key, d.photos))

	writeCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	principals := &afterLock{Store: pg.principals, after: cancel}
	cancelling := bucketpolicysvc.New(zap.NewNop(), pg.tenants, d.buckets, principals, pg.policies, rotator)
	_, _, err = cancelling.Put(writeCtx, "tenant-1", "photos", doc(allow(only("user-1"), "s3:ListBucket")), &etagA)
	require.ErrorIs(t, err, context.Canceled)
	require.Nil(t, principals.after, "the rotation ran")

	rec, err := pg.policies.Get(ctx, d.photos)
	require.NoError(t, err)
	require.Equal(t, etagA, rec.ETag, "the document was not replaced")
	require.Equal(t, commandsFor("s3:GetObject", "s3:ListBucket"), pg.over(t, key, d.photos), "and the key keeps the stored policy's grants")
}

// TestKeyCreatedDuringPolicyCreatePostgres creates a key for an existing
// principal while the first policy naming it is being written, parked once
// its principal lock call has returned. The write holds the principal's row
// until it commits, so the creation waits and then reads the committed policy,
// and the key holds its grants.
func TestKeyCreatedDuringPolicyCreatePostgres(t *testing.T) {
	pool := testutil.PostgresOrSkip(t)
	ctx := t.Context()
	d := setup(t)
	pg := d.postgres(t, pool)
	require.NoError(t, pg.principals.Add(ctx, d.tenantID, "user-1"))
	// The principal holds a key already, so the write has a rotation to run.
	user := "user-1"
	require.NoError(t, pg.accessKeys.Add(ctx, accesskeystore.Input{ID: testutil.RandomDID(t), Tenant: d.tenantID, Name: "phone", Principal: &user}))

	keys := accesskeysvc.New(zap.NewNop(), pg.tenants, pg.accessKeys, pg.principals, d.buckets, pg.policies, pg.delegations, d.secrets, d.swarf)
	var created accesskeystore.Record
	written, added := testutil.RequireWaitsForWriter(t,
		func(entered chan<- struct{}, release <-chan struct{}) error {
			principals := &afterLock{Store: pg.principals, after: func() { close(entered); <-release }}
			svc := bucketpolicysvc.New(zap.NewNop(), pg.tenants, d.buckets, principals, pg.policies,
				grant.NewRotator(zap.NewNop(), pg.delegations, pg.accessKeys, d.secrets, d.swarf))
			_, _, err := svc.Put(context.Background(), "tenant-1", "photos", doc(allow(only("user-1"), "s3:GetObject")), nil)
			return err
		},
		func() error {
			var err error
			created, _, err = keys.Create(context.Background(), "tenant-1", "laptop", nil, nil, "user-1", nil)
			return err
		})
	require.NoError(t, written)
	require.NoError(t, added)
	require.Equal(t, commandsFor("s3:GetObject"), pg.over(t, created.ID, d.photos), "the key is created from the committed policy")
}

// TestPolicyWriteToMissingBucketPostgres writes a policy for a bucket the
// service resolves but Postgres has no row for, standing in for a bucket
// deleted between the lookup and the write. It is reported as a missing
// bucket.
func TestPolicyWriteToMissingBucketPostgres(t *testing.T) {
	pool := testutil.PostgresOrSkip(t)
	d := setup(t)
	tenants := tenantmemory.New()
	require.NoError(t, tenants.Add(t.Context(), d.tenantID, "tenant-1", testutil.RandomDID(t), tenant.Active))
	svc := bucketpolicysvc.New(zap.NewNop(), tenants, d.buckets, d.principals,
		bucketpolicypostgres.New(pool), d.rotator(d.swarf))

	_, _, err := svc.Put(t.Context(), "tenant-1", "photos", doc(allow(everyone, "s3:ListBucket")), nil)
	require.ErrorIs(t, err, bucketpolicysvc.ErrBucketNotFound)
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
			{Name: "backups", Actions: []string{"s3:ListBucket"}},
			{Name: "photos", Actions: []string{"s3:GetObject"}},
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
