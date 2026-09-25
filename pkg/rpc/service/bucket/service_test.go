package bucket_test

import (
	"context"
	"errors"
	htestutil "github.com/fil-forge/hilt/internal/testutil"
	"github.com/ipfs/go-cid"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/fil-forge/hilt/pkg/bucketpolicy"
	"github.com/fil-forge/hilt/pkg/client/upload"
	"github.com/fil-forge/hilt/pkg/grant"
	"github.com/fil-forge/hilt/pkg/rpc/service/auth"
	bucketsvc "github.com/fil-forge/hilt/pkg/rpc/service/bucket"
	"github.com/fil-forge/hilt/pkg/sigv4"
	"github.com/fil-forge/hilt/pkg/store"
	"github.com/fil-forge/hilt/pkg/store/accesskey"
	accesskeymemory "github.com/fil-forge/hilt/pkg/store/accesskey/memory"
	bucketmemory "github.com/fil-forge/hilt/pkg/store/bucket/memory"
	bucketpolicystore "github.com/fil-forge/hilt/pkg/store/bucketpolicy"
	bucketpolicymemory "github.com/fil-forge/hilt/pkg/store/bucketpolicy/memory"
	delegationstore "github.com/fil-forge/hilt/pkg/store/delegation"
	delegationmemory "github.com/fil-forge/hilt/pkg/store/delegation/memory"
	principalmemory "github.com/fil-forge/hilt/pkg/store/principal/memory"
	providermemory "github.com/fil-forge/hilt/pkg/store/provider/memory"
	"github.com/fil-forge/hilt/pkg/store/tenant"
	tenantmemory "github.com/fil-forge/hilt/pkg/store/tenant/memory"
	"github.com/fil-forge/hilt/pkg/vault"
	vaultmemory "github.com/fil-forge/hilt/pkg/vault/memory"
	"github.com/fil-forge/libforge/commands/content"
	s3 "github.com/fil-forge/libforge/commands/s3"
	s3bkt "github.com/fil-forge/libforge/commands/s3/bucket"
	"github.com/fil-forge/libforge/testutil"
	"github.com/fil-forge/ucantone/did"
	"github.com/fil-forge/ucantone/multikey"
	"github.com/fil-forge/ucantone/multikey/ed25519"
	"github.com/fil-forge/ucantone/multikey/secp256k1"
	"github.com/fil-forge/ucantone/ucan"
	"github.com/fil-forge/ucantone/ucan/command"
	"github.com/fil-forge/ucantone/ucan/delegation"
	"github.com/multiformats/go-multibase"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

// fakeSprue is a combined stub of the Sprue dependency (ProvisionSpace +
// SpaceEmpty), recording its inputs.
type fakeSprue struct {
	sub         string
	provErr     error
	provCalled  bool
	provAccount did.DID
	provSpace   did.DID

	empty       bool
	emptyErr    error
	emptyCalled bool
	emptySpace  did.DID

	useErr    error
	useCalled bool
	useSpace  did.DID
	usePolicy *did.DID
	useIssuer did.DID
}

func (f *fakeSprue) ProvisionSpace(_ context.Context, account ucan.Issuer, space did.DID) (string, error) {
	f.provCalled = true
	f.provAccount = account.DID()
	f.provSpace = space
	return f.sub, f.provErr
}

func (f *fakeSprue) SpaceEmpty(_ context.Context, space did.DID, _ ...upload.MethodOption) (bool, error) {
	f.emptyCalled = true
	f.emptySpace = space
	return f.empty, f.emptyErr
}

func (f *fakeSprue) UseRoutingPolicy(_ context.Context, space did.DID, policy *did.DID, opts ...upload.MethodOption) error {
	f.useCalled = true
	f.useSpace = space
	f.usePolicy = policy
	if cfg := upload.MethodConfigOf(opts...); cfg.Issuer != nil {
		f.useIssuer = cfg.Issuer.DID()
	}
	return f.useErr
}

// seedKey stores the credential's record and vault entry: a service credential
// carrying perms unless principalBound, in which case a key bound to "user-1",
// who is recorded as a principal of the tenant and holds the grants given,
// the ones the bucket policies map to.
func seedKey(t *testing.T, accessKeys *accesskeymemory.Store, secrets *vaultmemory.Store, delegations delegationstore.Store, principals *principalmemory.Store, signer ed25519.Signer, tenantID did.DID, perms []string, principalBound bool, grants ...ucan.Delegation) {
	t.Helper()
	akDID := signer.KeyDID()
	in := accesskey.Input{ID: akDID, Tenant: tenantID, Name: "k1", Permissions: perms}
	if principalBound {
		principal := "user-1"
		in = accesskey.Input{ID: akDID, Tenant: tenantID, Name: "k1", Principal: &principal}
		require.NoError(t, principals.Add(t.Context(), tenantID, principal))
	}
	require.NoError(t, accessKeys.Add(t.Context(), in))
	require.NoError(t, secrets.Write(t.Context(), vault.AccessKeyPath(tenantID, akDID), signer.Bytes()))
	if len(grants) > 0 {
		require.NoError(t, delegations.PutBatch(t.Context(), grants))
	}
}

// allPerms is the permission set a service key in these tests holds: every
// action the subtests exercise.
var allPerms = []string{
	"s3:CreateBucket",
	"s3:DeleteBucket",
	"s3:ListAllMyBuckets",
	"s3:ListBucket",
	"s3:GetObject",
}

func presign(t *testing.T, signer ed25519.Signer, method, url, region string) s3.Request {
	t.Helper()
	secret, err := multibase.Encode(multibase.Base64url, signer.Bytes())
	require.NoError(t, err)
	signed, err := sigv4.Presign(sigv4.Request{Method: method, URL: url}, signer.KeyDID().Identifier(), secret, region, sigv4.SchemeV4, time.Now(), time.Hour)
	require.NoError(t, err)
	return s3.Request{Method: signed.Method, URL: signed.URL}
}

func TestCreate(t *testing.T) {
	ctx := t.Context()
	const region, bucketName = "us-west-2", "newbucket"

	akSigner, err := ed25519.Generate()
	require.NoError(t, err)
	akDID := akSigner.KeyDID()
	tenantSigner, err := secp256k1.Generate()
	require.NoError(t, err)
	tenantID := tenantSigner.KeyDID()
	providerID := testutil.RandomDID(t)
	providerPolicy := testutil.RandomDID(t)

	// setup seeds a powerline tenant→credential delegation for /content/retrieve.
	// policy is the provider's routing policy; nil registers a provider without one.
	setup := func(t *testing.T, perms []string, principalBound bool, sprue bucketsvc.UploadClient, delegations delegationstore.Store, policy *did.DID) (*bucketsvc.Service, *bucketmemory.Store) {
		t.Helper()
		accessKeys, tenants, buckets := accesskeymemory.New(), tenantmemory.New(), bucketmemory.New()
		providers, secrets := providermemory.New(), vaultmemory.New()
		principals, policies := principalmemory.New(), bucketpolicymemory.New()
		require.NoError(t, providers.Add(ctx, providerID, region, policy))
		require.NoError(t, tenants.Add(ctx, tenantID, "tenant-1", providerID, tenant.Active))
		seedKey(t, accessKeys, secrets, delegations, principals, akSigner, tenantID, perms, principalBound)
		require.NoError(t, secrets.Write(ctx, vault.TenantKeyPath(tenantID), tenantSigner.Bytes()))
		powerline, err := delegation.Delegate(multikey.NewIssuer(tenantID, tenantSigner), akDID, did.DID{}, content.Retrieve.Command)
		require.NoError(t, err)
		require.NoError(t, delegations.PutBatch(ctx, []ucan.Delegation{powerline}))
		az := auth.NewAuthorizer(zap.NewNop(), accessKeys, tenants, providers, buckets, principals, policies, secrets)
		return bucketsvc.New(zap.NewNop(), az, buckets, delegations, accessKeys, policies, sprue, &htestutil.FakeSwarf{}), buckets
	}

	args := func() *s3bkt.CreateArguments {
		return &s3bkt.CreateArguments{Request: presign(t, akSigner, "PUT", "https://s3.fil.one/"+bucketName, region)}
	}

	t.Run("creates and provisions the bucket, returning the powerline chain", func(t *testing.T) {
		sprue := &fakeSprue{sub: "sub-1"}
		svc, buckets := setup(t, allPerms, false, sprue, delegationmemory.New(), &providerPolicy)
		ok, blocks, err := svc.Create(ctx, providerID, args())
		require.NoError(t, err)

		rec, err := buckets.GetByName(ctx, bucketName)
		require.NoError(t, err)
		require.Equal(t, &rec.ID, ok.Bucket)
		require.Equal(t, tenantID, ok.Tenant)
		require.True(t, sprue.provCalled)
		require.Equal(t, tenantID, sprue.provAccount)
		require.Equal(t, *ok.Bucket, sprue.provSpace)
		require.Len(t, ok.Delegations.Entries, 1)
		require.Len(t, blocks, 2) // bucket→tenant root + tenant→access-key powerline
	})

	t.Run("points the bucket at the provider's routing policy as the tenant", func(t *testing.T) {
		sprue := &fakeSprue{sub: "sub-1"}
		svc, _ := setup(t, allPerms, false, sprue, delegationmemory.New(), &providerPolicy)
		ok, _, err := svc.Create(ctx, providerID, args())
		require.NoError(t, err)

		require.True(t, sprue.useCalled)
		require.Equal(t, *ok.Bucket, sprue.useSpace)
		require.NotNil(t, sprue.usePolicy)
		require.Equal(t, providerPolicy, *sprue.usePolicy)
		require.Equal(t, tenantID, sprue.useIssuer)
	})

	t.Run("leaves the bucket on default routing when the provider has no policy", func(t *testing.T) {
		sprue := &fakeSprue{sub: "sub-1"}
		svc, _ := setup(t, allPerms, false, sprue, delegationmemory.New(), nil)
		ok, _, err := svc.Create(ctx, providerID, args())
		require.NoError(t, err)
		require.NotNil(t, ok.Bucket)
		require.True(t, sprue.provCalled)
		require.False(t, sprue.useCalled)
	})

	t.Run("rolls back the bucket when applying the routing policy fails", func(t *testing.T) {
		svc, buckets := setup(t, allPerms, false, &fakeSprue{useErr: errors.New("sprue unavailable")}, delegationmemory.New(), &providerPolicy)
		_, _, err := svc.Create(ctx, providerID, args())
		require.Error(t, err)
		_, err = buckets.GetByName(ctx, bucketName)
		require.ErrorIs(t, err, store.ErrRecordNotFound)
	})

	t.Run("rejects a key without s3:CreateBucket", func(t *testing.T) {
		svc, _ := setup(t, []string{"s3:GetObject"}, false, &fakeSprue{}, delegationmemory.New(), &providerPolicy)
		_, _, err := svc.Create(ctx, providerID, args())
		require.ErrorIs(t, err, auth.ErrOperationNotPermitted)
	})

	t.Run("rejects a principal-bound key", func(t *testing.T) {
		// No policy grants s3:CreateBucket, so the authorizer refuses the key
		// before the service is reached.
		svc, _ := setup(t, nil, true, &fakeSprue{}, delegationmemory.New(), &providerPolicy)
		_, _, err := svc.Create(ctx, providerID, args())
		require.ErrorIs(t, err, auth.ErrOperationNotPermitted)
	})

	t.Run("rejects a duplicate name owned by another tenant", func(t *testing.T) {
		svc, buckets := setup(t, allPerms, false, &fakeSprue{}, delegationmemory.New(), &providerPolicy)
		// Owner is a different tenant → BucketAlreadyExists.
		require.NoError(t, buckets.Add(ctx, testutil.RandomDID(t), testutil.RandomDID(t), bucketName))
		_, _, err := svc.Create(ctx, providerID, args())
		require.ErrorIs(t, err, bucketsvc.ErrBucketExists)
	})

	t.Run("rejects re-creating a bucket you already own", func(t *testing.T) {
		svc, buckets := setup(t, allPerms, false, &fakeSprue{}, delegationmemory.New(), &providerPolicy)
		// Owner is the requesting tenant → BucketAlreadyOwnedByYou.
		require.NoError(t, buckets.Add(ctx, testutil.RandomDID(t), tenantID, bucketName))
		_, _, err := svc.Create(ctx, providerID, args())
		require.ErrorIs(t, err, bucketsvc.ErrBucketAlreadyOwned)
	})

	t.Run("rolls back the bucket when provisioning fails", func(t *testing.T) {
		svc, buckets := setup(t, allPerms, false, &fakeSprue{provErr: errors.New("sprue unavailable")}, delegationmemory.New(), &providerPolicy)
		_, _, err := svc.Create(ctx, providerID, args())
		require.Error(t, err)
		_, err = buckets.GetByName(ctx, bucketName)
		require.ErrorIs(t, err, store.ErrRecordNotFound)
	})

	t.Run("rolls back the bucket when listing delegations fails", func(t *testing.T) {
		// A failure after provisioning (listing the access key's delegations) must
		// still roll the bucket record back.
		delegations := failingListDelegations{Store: delegationmemory.New(), err: errors.New("boom")}
		svc, buckets := setup(t, allPerms, false, &fakeSprue{}, delegations, &providerPolicy)
		_, _, err := svc.Create(ctx, providerID, args())
		require.Error(t, err)
		_, err = buckets.GetByName(ctx, bucketName)
		require.ErrorIs(t, err, store.ErrRecordNotFound)
	})
}

// failingListDelegations wraps a delegation store, failing ListByAudience so a
// post-provisioning failure can be exercised.
type failingListDelegations struct {
	delegationstore.Store
	err error
}

func (f failingListDelegations) ListByAudience(context.Context, did.DID, ...store.PaginationOption) (store.Page[ucan.Delegation], error) {
	return store.Page[ucan.Delegation]{}, f.err
}

// writeOnFirstList runs write once, when the delegations are listed. Info
// lists them after it has read the effective actions, so a policy write put
// here lands wholly between the two reads.
type writeOnFirstList struct {
	delegationstore.Store
	once  sync.Once
	write func()
}

func (w *writeOnFirstList) ListByAudience(ctx context.Context, audience did.DID, opts ...store.PaginationOption) (store.Page[ucan.Delegation], error) {
	w.once.Do(func() {
		if w.write != nil {
			w.write()
		}
	})
	return w.Store.ListByAudience(ctx, audience, opts...)
}

// revocation records one published revocation.
// deleteDeps is the world a Delete subtest operates on.
type deleteDeps struct {
	svc         *bucketsvc.Service
	buckets     *bucketmemory.Store
	delegations *delegationmemory.Store
	policies    bucketpolicystore.Store
	swarf       *htestutil.FakeSwarf
	tenantID    did.DID
	bucketID    did.DID
	root        ucan.Delegation // bucket→tenant, signed by the bucket's discarded key
	grant       ucan.Delegation // tenant→access key, scoped to the bucket
}

func TestDelete(t *testing.T) {
	ctx := t.Context()
	const region, bucketName = "us-west-2", "delbucket"

	akSigner, err := ed25519.Generate()
	require.NoError(t, err)
	akDID := akSigner.KeyDID()
	tenantSigner, err := secp256k1.Generate()
	require.NoError(t, err)
	tenantID := tenantSigner.KeyDID()
	providerID := testutil.RandomDID(t)

	// grantOpts lets a subtest vary the tenant→credential grant's expiry.
	setup := func(t *testing.T, perms []string, principalBound bool, sprue bucketsvc.UploadClient, grantOpts ...delegation.Option) deleteDeps {
		t.Helper()
		accessKeys, tenants, buckets := accesskeymemory.New(), tenantmemory.New(), bucketmemory.New()
		providers, secrets, delegations := providermemory.New(), vaultmemory.New(), delegationmemory.New()
		principals, policies := principalmemory.New(), bucketpolicymemory.New()
		require.NoError(t, providers.Add(ctx, providerID, region, nil))
		require.NoError(t, tenants.Add(ctx, tenantID, "tenant-1", providerID, tenant.Active))
		seedKey(t, accessKeys, secrets, delegations, principals, akSigner, tenantID, perms, principalBound)
		require.NoError(t, secrets.Write(ctx, vault.TenantKeyPath(tenantID), tenantSigner.Bytes()))
		bucketSigner, err := ed25519.Generate()
		require.NoError(t, err)
		bucketID := bucketSigner.KeyDID()
		require.NoError(t, buckets.Add(ctx, bucketID, tenantID, bucketName))
		// Both live as long as the bucket does, as the real ones do — without
		// WithNoExpiration ucantone defaults to a 30-second expiry, which would make
		// the expiry-skip behaviour timing-dependent.
		root, err := delegation.Delegate(
			multikey.NewIssuer(bucketID, bucketSigner), tenantID, bucketID, command.Top(), delegation.WithNoExpiration())
		require.NoError(t, err)
		if len(grantOpts) == 0 {
			grantOpts = []delegation.Option{delegation.WithNoExpiration()}
		}
		grant, err := delegation.Delegate(
			multikey.NewIssuer(tenantID, tenantSigner), akDID, bucketID, content.Retrieve.Command, grantOpts...)
		require.NoError(t, err)
		require.NoError(t, delegations.PutBatch(ctx, []ucan.Delegation{root, grant}))
		az := auth.NewAuthorizer(zap.NewNop(), accessKeys, tenants, providers, buckets, principals, policies, secrets)
		swarf := &htestutil.FakeSwarf{}
		return deleteDeps{
			svc:         bucketsvc.New(zap.NewNop(), az, buckets, delegations, accessKeys, policies, sprue, swarf),
			buckets:     buckets,
			delegations: delegations,
			policies:    policies,
			tenantID:    tenantID,
			swarf:       swarf,
			bucketID:    bucketID,
			root:        root,
			grant:       grant,
		}
	}

	del := func(name string) *s3bkt.DeleteArguments {
		return &s3bkt.DeleteArguments{Request: presign(t, akSigner, "DELETE", "https://s3.fil.one/"+name, region)}
	}

	t.Run("deletes the bucket's policy with the bucket", func(t *testing.T) {
		d := setup(t, allPerms, false, &fakeSprue{empty: true})
		_, err := d.policies.Put(ctx, bucketpolicystore.Input{
			Bucket: d.bucketID, Tenant: d.tenantID,
			Policy: bucketpolicy.Policy{Statements: []bucketpolicy.Statement{{Effect: bucketpolicy.Allow, Principal: bucketpolicy.Everyone(), Actions: []string{"s3:GetObject"}}}},
		}, nil)
		require.NoError(t, err)

		_, err = d.svc.Delete(ctx, providerID, del(bucketName))
		require.NoError(t, err)
		_, err = d.policies.Get(ctx, d.bucketID)
		require.ErrorIs(t, err, store.ErrRecordNotFound)
	})

	t.Run("deletes an empty bucket", func(t *testing.T) {
		sprue := &fakeSprue{empty: true}
		d := setup(t, allPerms, false, sprue)
		_, err := d.svc.Delete(ctx, providerID, del(bucketName))
		require.NoError(t, err)
		require.True(t, sprue.emptyCalled)
		require.Equal(t, d.bucketID, sprue.emptySpace)
		_, err = d.buckets.GetByName(ctx, bucketName)
		require.ErrorIs(t, err, store.ErrRecordNotFound)
	})

	t.Run("revokes the tenant's grant over the bucket, with no witness path", func(t *testing.T) {
		d := setup(t, allPerms, false, &fakeSprue{empty: true})
		_, err := d.svc.Delete(ctx, providerID, del(bucketName))
		require.NoError(t, err)

		require.Len(t, d.swarf.Revocations(), 1)
		require.Equal(t, 1, d.swarf.Calls())
		r := d.swarf.Revocations()[0]
		// The tenant issued the grant, so the tenant revokes it directly.
		require.Equal(t, tenantID, r.Revoker)
		require.Equal(t, d.grant.Link(), r.Revoked)
	})

	t.Run("does not revoke the bucket root", func(t *testing.T) {
		d := setup(t, allPerms, false, &fakeSprue{empty: true})
		_, err := d.svc.Delete(ctx, providerID, del(bucketName))
		require.NoError(t, err)

		// The root was signed by the bucket's discarded key: the tenant is only its
		// audience, so no revocation it could sign would be accepted.
		for _, r := range d.swarf.Revocations() {
			require.NotEqual(t, d.root.Link(), r.Revoked)
		}
	})

	t.Run("skips an expired grant", func(t *testing.T) {
		expired := delegation.WithExpiration(ucan.UnixTimestamp(time.Now().Add(-time.Hour).Unix()))
		d := setup(t, allPerms, false, &fakeSprue{empty: true}, expired)

		// The revocation service rejects expired delegations, and they are unusable
		// anyway — so the bucket is still deleted, just with nothing published.
		_, err := d.svc.Delete(ctx, providerID, del(bucketName))
		require.NoError(t, err)
		require.Empty(t, d.swarf.Revocations())
		_, err = d.buckets.GetByName(ctx, bucketName)
		require.ErrorIs(t, err, store.ErrRecordNotFound)
	})

	t.Run("a revocation failure leaves the bucket intact", func(t *testing.T) {
		d := setup(t, allPerms, false, &fakeSprue{empty: true})
		d.swarf.Err = errors.New("swarf is down")

		_, err := d.svc.Delete(ctx, providerID, del(bucketName))
		require.ErrorContains(t, err, "publishing revocation")

		// Nothing was removed, so the call can simply be retried.
		_, err = d.buckets.GetByName(ctx, bucketName)
		require.NoError(t, err)
		remaining, err := d.delegations.ListBySubject(ctx, d.bucketID)
		require.NoError(t, err)
		require.Len(t, remaining.Results, 2)
	})

	t.Run("rejects a key without s3:DeleteBucket", func(t *testing.T) {
		d := setup(t, []string{"s3:GetObject"}, false, &fakeSprue{empty: true})
		_, err := d.svc.Delete(ctx, providerID, del(bucketName))
		require.ErrorIs(t, err, auth.ErrOperationNotPermitted)
	})

	t.Run("rejects a principal-bound key", func(t *testing.T) {
		// No policy grants s3:DeleteBucket, so the authorizer refuses the key
		// before the service is reached.
		d := setup(t, nil, true, &fakeSprue{empty: true})
		_, err := d.svc.Delete(ctx, providerID, del(bucketName))
		require.ErrorIs(t, err, auth.ErrOperationNotPermitted)
	})

	t.Run("rejects an unknown bucket", func(t *testing.T) {
		d := setup(t, allPerms, false, &fakeSprue{empty: true})
		_, err := d.svc.Delete(ctx, providerID, del("nope"))
		require.ErrorIs(t, err, auth.ErrUnknownBucket)
	})

	t.Run("rejects a non-empty bucket and keeps it", func(t *testing.T) {
		d := setup(t, allPerms, false, &fakeSprue{empty: false})
		_, err := d.svc.Delete(ctx, providerID, del(bucketName))
		require.ErrorIs(t, err, bucketsvc.ErrBucketNotEmpty)
		_, err = d.buckets.GetByName(ctx, bucketName)
		require.NoError(t, err)
		require.Empty(t, d.swarf.Revocations(), "nothing is revoked when the delete is refused")
	})

	t.Run("propagates a SpaceEmpty error", func(t *testing.T) {
		d := setup(t, allPerms, false, &fakeSprue{emptyErr: errors.New("sprue unavailable")})
		_, err := d.svc.Delete(ctx, providerID, del(bucketName))
		require.Error(t, err)
	})
}

func TestList(t *testing.T) {
	ctx := t.Context()
	const region = "us-west-2"

	signer, err := ed25519.Generate()
	require.NoError(t, err)
	providerID := testutil.RandomDID(t)

	setup := func(t *testing.T, perms []string, principalBound bool) (*bucketsvc.Service, *bucketmemory.Store, did.DID) {
		t.Helper()
		accessKeys, tenants, buckets := accesskeymemory.New(), tenantmemory.New(), bucketmemory.New()
		providers, secrets, delegations := providermemory.New(), vaultmemory.New(), delegationmemory.New()
		principals, policies := principalmemory.New(), bucketpolicymemory.New()
		require.NoError(t, providers.Add(ctx, providerID, region, nil))
		tenantID := testutil.RandomDID(t)
		require.NoError(t, tenants.Add(ctx, tenantID, "tenant-1", providerID, tenant.Active))
		seedKey(t, accessKeys, secrets, delegations, principals, signer, tenantID, perms, principalBound)
		az := auth.NewAuthorizer(zap.NewNop(), accessKeys, tenants, providers, buckets, principals, policies, secrets)
		return bucketsvc.New(zap.NewNop(), az, buckets, delegations, accessKeys, policies, &fakeSprue{}, &htestutil.FakeSwarf{}), buckets, tenantID
	}

	// listArgs presigns a ListBuckets request; extra ListBuckets query params
	// (prefix, max-buckets, continuation-token) are appended before signing so
	// the signature covers them.
	listArgs := func(params ...string) *s3bkt.ListArguments {
		url := strings.Join(append([]string{"https://" + region + ".s3.fil.one/?x-id=ListBuckets"}, params...), "&")
		return &s3bkt.ListArguments{Request: presign(t, signer, "GET", url, region)}
	}

	bucketNames := func(ok *s3bkt.ListOK) []string {
		names := make([]string, 0, len(ok.Buckets))
		for _, b := range ok.Buckets {
			names = append(names, b.Name)
		}
		return names
	}

	t.Run("lists the tenant's buckets", func(t *testing.T) {
		svc, buckets, tenantID := setup(t, allPerms, false)
		require.NoError(t, buckets.Add(ctx, testutil.RandomDID(t), tenantID, "alpha"))
		require.NoError(t, buckets.Add(ctx, testutil.RandomDID(t), tenantID, "bravo"))
		ok, err := svc.List(ctx, providerID, listArgs())
		require.NoError(t, err)
		require.Equal(t, []string{"alpha", "bravo"}, bucketNames(ok))
		require.Empty(t, ok.ContinuationToken)
		require.Empty(t, ok.Prefix)
	})

	t.Run("filters by prefix and echoes it", func(t *testing.T) {
		svc, buckets, tenantID := setup(t, allPerms, false)
		require.NoError(t, buckets.Add(ctx, testutil.RandomDID(t), tenantID, "alpha"))
		require.NoError(t, buckets.Add(ctx, testutil.RandomDID(t), tenantID, "apple"))
		require.NoError(t, buckets.Add(ctx, testutil.RandomDID(t), tenantID, "bravo"))
		ok, err := svc.List(ctx, providerID, listArgs("prefix=a"))
		require.NoError(t, err)
		require.Equal(t, []string{"alpha", "apple"}, bucketNames(ok))
		require.Equal(t, "a", ok.Prefix)
		require.Empty(t, ok.ContinuationToken)
	})

	t.Run("paginates with max-buckets and continuation-token", func(t *testing.T) {
		svc, buckets, tenantID := setup(t, allPerms, false)
		for _, name := range []string{"charlie", "alpha", "bravo"} {
			require.NoError(t, buckets.Add(ctx, testutil.RandomDID(t), tenantID, name))
		}

		ok, err := svc.List(ctx, providerID, listArgs("max-buckets=2"))
		require.NoError(t, err)
		require.Equal(t, []string{"alpha", "bravo"}, bucketNames(ok))
		require.Equal(t, "bravo", ok.ContinuationToken)

		ok, err = svc.List(ctx, providerID, listArgs("max-buckets=2", "continuation-token="+ok.ContinuationToken))
		require.NoError(t, err)
		require.Equal(t, []string{"charlie"}, bucketNames(ok))
		require.Empty(t, ok.ContinuationToken)
	})

	t.Run("rejects an invalid max-buckets", func(t *testing.T) {
		svc, _, _ := setup(t, allPerms, false)
		for _, param := range []string{"max-buckets=abc", "max-buckets=0", "max-buckets=-1", "max-buckets=10001"} {
			_, err := svc.List(ctx, providerID, listArgs(param))
			require.ErrorIs(t, err, bucketsvc.ErrInvalidArgument, "param %q", param)
		}
	})

	t.Run("rejects a key without the list permission", func(t *testing.T) {
		svc, _, _ := setup(t, []string{"s3:GetObject"}, false)
		_, err := svc.List(ctx, providerID, listArgs())
		require.ErrorIs(t, err, auth.ErrOperationNotPermitted)
	})

	t.Run("a principal-bound key lists the tenant's buckets", func(t *testing.T) {
		// Every principal holds s3:ListAllMyBuckets, and the listing consults no
		// policy: it is the tenant's whole bucket set, as AWS lists names the
		// caller cannot open.
		svc, buckets, tenantID := setup(t, nil, true)
		require.NoError(t, buckets.Add(ctx, testutil.RandomDID(t), tenantID, "alpha"))
		ok, err := svc.List(ctx, providerID, listArgs())
		require.NoError(t, err)
		require.Equal(t, []string{"alpha"}, bucketNames(ok))
	})

	t.Run("rejects a validly-signed request for a different operation", func(t *testing.T) {
		// A GetObject request the credential IS permitted for passes Authorize, but
		// List rejects it as not a ListBuckets operation.
		svc, buckets, tenantID := setup(t, allPerms, false)
		require.NoError(t, buckets.Add(ctx, testutil.RandomDID(t), tenantID, "bucket-a"))
		args := &s3bkt.ListArguments{Request: presign(t, signer, "GET", "https://"+region+".s3.fil.one/bucket-a/object-key", region)}
		_, err := svc.List(ctx, providerID, args)
		require.ErrorIs(t, err, bucketsvc.ErrOperationMismatch)
	})
}

func TestInfo(t *testing.T) {
	ctx := t.Context()
	const bucketName = "infobucket"

	akSigner, err := ed25519.Generate()
	require.NoError(t, err)
	akDID := akSigner.KeyDID()
	tenantSigner, err := secp256k1.Generate()
	require.NoError(t, err)
	tenantID := tenantSigner.KeyDID()
	bucketSigner, err := ed25519.Generate()
	require.NoError(t, err)
	bucketID := bucketSigner.KeyDID()

	// setup seeds a bucket, a credential (a service credential unless
	// principalBound), a bucket→tenant root, and either a tenant→credential
	// grant with the given subject (did.DID{} = powerline) or, for a
	// principal-bound key, its grants over the bucket.
	setup := func(t *testing.T, perms []string, principalBound bool, grantSubject did.DID, wrap ...func(delegationstore.Store) delegationstore.Store) (*bucketsvc.Service, *bucketpolicymemory.Store, ucan.Delegation) {
		t.Helper()
		accessKeys, buckets, delegations := accesskeymemory.New(), bucketmemory.New(), delegationmemory.New()
		principals, policies := principalmemory.New(), bucketpolicymemory.New()
		// A principal-bound key holds the grants its policy maps to over the
		// bucket, issued as the tenant.
		var grants []ucan.Delegation
		if principalBound {
			grants, err = grant.Issue(multikey.NewIssuer(tenantID, tenantSigner), akDID, []did.DID{bucketID}, []string{"s3:GetObject", "s3:ListBucket"}, nil)
			require.NoError(t, err)
		}
		seedKey(t, accessKeys, vaultmemory.New(), delegations, principals, akSigner, tenantID, perms, principalBound, grants...)
		require.NoError(t, buckets.Add(ctx, bucketID, tenantID, bucketName))
		root, err := delegation.Delegate(multikey.NewIssuer(bucketID, bucketSigner), tenantID, bucketID, command.Top(), delegation.WithNoExpiration())
		require.NoError(t, err)
		// seedKey stored a principal-bound key's grants over the bucket; a
		// service credential holds the tenant's grant over grantSubject instead.
		held := []ucan.Delegation{root}
		if !principalBound {
			grant, err := delegation.Delegate(multikey.NewIssuer(tenantID, tenantSigner), akDID, grantSubject, content.Retrieve.Command)
			require.NoError(t, err)
			held = append(held, grant)
		}
		require.NoError(t, delegations.PutBatch(ctx, held))
		// Info reads a principal-bound key's principal and policy through the
		// authorizer, so it shares the stores the test seeds.
		az := auth.NewAuthorizer(zap.NewNop(), accessKeys, tenantmemory.New(), providermemory.New(), buckets,
			principals, policies, vaultmemory.New())
		var reads delegationstore.Store = delegations
		for _, w := range wrap {
			reads = w(reads)
		}
		return bucketsvc.New(zap.NewNop(), az, buckets, reads, accessKeys, policies, &fakeSprue{}, &htestutil.FakeSwarf{}), policies, root
	}

	// grantPolicy stores a policy allowing "user-1" the given actions on the bucket.
	grantPolicy := func(t *testing.T, policies *bucketpolicymemory.Store, actions ...string) {
		t.Helper()
		_, err := policies.Put(ctx, bucketpolicystore.Input{
			Bucket: bucketID,
			Tenant: tenantID,
			Policy: bucketpolicy.Policy{Statements: []bucketpolicy.Statement{{
				Effect:    bucketpolicy.Allow,
				Principal: bucketpolicy.Only("user-1"),
				Actions:   actions,
			}}},
		}, nil)
		require.NoError(t, err)
	}

	t.Run("returns the bucket, permissions, and delegation chain", func(t *testing.T) {
		svc, _, _ := setup(t, allPerms, false, did.DID{}) // powerline grant reaches the bucket
		ok, blocks, err := svc.Info(ctx, &s3bkt.InfoArguments{Name: bucketName, AccessKey: akDID})
		require.NoError(t, err)
		require.Equal(t, bucketID, ok.ID)
		// A service key carries its own permission set.
		require.Equal(t, allPerms, ok.Permissions.Entries[akDID])
		require.Len(t, blocks, 2)
	})

	t.Run("rejects an unknown bucket", func(t *testing.T) {
		svc, _, _ := setup(t, allPerms, false, did.DID{})
		_, _, err := svc.Info(ctx, &s3bkt.InfoArguments{Name: "nope", AccessKey: akDID})
		require.ErrorIs(t, err, bucketsvc.ErrUnknownBucket)
	})

	t.Run("rejects an unknown access key", func(t *testing.T) {
		svc, _, _ := setup(t, allPerms, false, did.DID{})
		_, _, err := svc.Info(ctx, &s3bkt.InfoArguments{Name: bucketName, AccessKey: testutil.RandomDID(t)})
		require.ErrorIs(t, err, bucketsvc.ErrUnknownAccessKey)
	})

	t.Run("a principal-bound key gets its effective set and the chains through its grants", func(t *testing.T) {
		svc, policies, root := setup(t, nil, true, did.DID{})
		grantPolicy(t, policies, "s3:GetObject", "s3:ListBucket")

		ok, blocks, err := svc.Info(ctx, &s3bkt.InfoArguments{Name: bucketName, AccessKey: akDID})
		require.NoError(t, err)
		require.Equal(t, bucketID, ok.ID)
		require.Equal(t, []string{"s3:GetObject", "s3:ListBucket"}, ok.Permissions.Entries[akDID])

		// The chain runs from the bucket root through the tenant's grant to the
		// key, as a service key scoped to the bucket has it.
		require.Len(t, blocks, 2)
		var held ucan.Delegation
		for _, d := range blocks {
			if d.Link() != root.Link() {
				held = d
			}
		}
		require.NotNil(t, held)
		require.Equal(t, akDID, held.Audience())
		require.Equal(t, bucketID, held.Subject())
		require.Equal(t, content.Retrieve.Command.String(), held.Command().String())
		require.Equal(t, map[cid.Cid][]cid.Cid{held.Link(): {root.Link(), held.Link()}}, ok.Delegations.Entries)
	})

	t.Run("a bucket outside the principal's reach is unknown", func(t *testing.T) {
		svc, _, _ := setup(t, nil, true, did.DID{}) // no policy at all
		_, _, err := svc.Info(ctx, &s3bkt.InfoArguments{Name: bucketName, AccessKey: akDID})
		require.ErrorIs(t, err, bucketsvc.ErrUnknownBucket)
	})

	t.Run("a policy write between the two reads is refused, not served", func(t *testing.T) {
		straddle := &writeOnFirstList{}
		svc, policies, _ := setup(t, nil, true, did.DID{}, func(s delegationstore.Store) delegationstore.Store {
			straddle.Store = s
			return straddle
		})
		grantPolicy(t, policies, "s3:GetObject", "s3:ListBucket")

		// The write narrows the policy to s3:ListBucket after Info has read the
		// effective actions. Both actions map to /content/retrieve, so the
		// rotation reissues a chain that still serves GetObject; pairing it with
		// the old action set would report a permission the policy just removed.
		straddle.write = func() {
			rec, err := policies.Get(ctx, bucketID)
			require.NoError(t, err)
			_, err = policies.Put(ctx, bucketpolicystore.Input{
				Bucket:  bucketID,
				Tenant:  tenantID,
				IfMatch: &rec.ETag,
				Policy: bucketpolicy.Policy{Statements: []bucketpolicy.Statement{{
					Effect:    bucketpolicy.Allow,
					Principal: bucketpolicy.Only("user-1"),
					Actions:   []string{"s3:ListBucket"},
				}}},
			}, nil)
			require.NoError(t, err)
		}

		_, _, err := svc.Info(ctx, &s3bkt.InfoArguments{Name: bucketName, AccessKey: akDID})
		require.ErrorIs(t, err, auth.ErrTemporarilyUnavailable)
	})

	t.Run("returns empty delegations when no grant reaches the bucket", func(t *testing.T) {
		svc, _, _ := setup(t, allPerms, false, testutil.RandomDID(t)) // grant scoped to a different bucket
		ok, blocks, err := svc.Info(ctx, &s3bkt.InfoArguments{Name: bucketName, AccessKey: akDID})
		require.NoError(t, err)
		require.Empty(t, ok.Delegations.Entries)
		require.Empty(t, blocks)
	})
}
