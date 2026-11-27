package bucket_test

import (
	"context"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	htestutil "github.com/fil-forge/hilt/internal/testutil"
	"github.com/ipfs/go-cid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	bucketpolicysvc "github.com/fil-forge/hilt/pkg/api/service/bucketpolicy"
	"github.com/fil-forge/hilt/pkg/client/upload"
	"github.com/fil-forge/hilt/pkg/grant"
	"github.com/fil-forge/hilt/pkg/rpc/service/auth"
	bucketsvc "github.com/fil-forge/hilt/pkg/rpc/service/bucket"
	"github.com/fil-forge/hilt/pkg/sigv4"
	"github.com/fil-forge/hilt/pkg/store"
	"github.com/fil-forge/hilt/pkg/store/accesskey"
	accesskeypostgres "github.com/fil-forge/hilt/pkg/store/accesskey/postgres"
	bucketpostgres "github.com/fil-forge/hilt/pkg/store/bucket/postgres"
	bucketpolicystore "github.com/fil-forge/hilt/pkg/store/bucketpolicy"
	bucketpolicypostgres "github.com/fil-forge/hilt/pkg/store/bucketpolicy/postgres"
	delegationstore "github.com/fil-forge/hilt/pkg/store/delegation"
	delegationpostgres "github.com/fil-forge/hilt/pkg/store/delegation/postgres"
	"github.com/fil-forge/hilt/pkg/store/pglock"
	principalpostgres "github.com/fil-forge/hilt/pkg/store/principal/postgres"
	providerpostgres "github.com/fil-forge/hilt/pkg/store/provider/postgres"
	"github.com/fil-forge/hilt/pkg/store/revocation"
	revocationpostgres "github.com/fil-forge/hilt/pkg/store/revocation/postgres"
	"github.com/fil-forge/hilt/pkg/store/tenant"
	tenantpostgres "github.com/fil-forge/hilt/pkg/store/tenant/postgres"
	"github.com/fil-forge/hilt/pkg/tasks/tenantqueue"
	"github.com/fil-forge/hilt/pkg/vault"
	vaultmemory "github.com/fil-forge/hilt/pkg/vault/memory"
	"github.com/fil-forge/libforge/commands/content"
	s3 "github.com/fil-forge/libforge/commands/s3"
	s3bkt "github.com/fil-forge/libforge/commands/s3/bucket"
	"github.com/fil-forge/libforge/taskrunner"
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
	emptyIssuer did.DID
	// onEmpty, when set, runs when the emptiness is asked.
	onEmpty func()

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

func (f *fakeSprue) SpaceEmpty(_ context.Context, space did.DID, opts ...upload.MethodOption) (bool, error) {
	f.emptyCalled = true
	f.emptySpace = space
	if cfg := upload.MethodConfigOf(opts...); cfg.Issuer != nil {
		f.emptyIssuer = cfg.Issuer.DID()
	}
	if f.onEmpty != nil {
		f.onEmpty()
	}
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
func seedKey(t *testing.T, accessKeys *accesskeypostgres.Store, secrets *vaultmemory.Store, delegations delegationstore.Store, principals *principalpostgres.Store, signer ed25519.Signer, tenantID did.DID, perms []string, principalBound bool, grants ...ucan.Delegation) {
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
	// policy is the provider's routing policy; nil registers a provider without
	// one. wrap, when not nil, decorates the delegation store the service reads
	// and writes through. The tenant store comes back so a test can add another
	// tenant.
	setup := func(t *testing.T, perms []string, principalBound bool, sprue bucketsvc.UploadClient, wrap func(delegationstore.Store) delegationstore.Store, policy *did.DID) (*bucketsvc.Service, *bucketpostgres.Store, *tenantpostgres.Store) {
		t.Helper()
		pool := htestutil.PostgresOrSkip(t)
		var delegations delegationstore.Store = delegationpostgres.New(pool)
		if wrap != nil {
			delegations = wrap(delegations)
		}
		accessKeys, tenants, buckets := accesskeypostgres.New(pool), tenantpostgres.New(pool), bucketpostgres.New(pool)
		providers, secrets := providerpostgres.New(pool), vaultmemory.New()
		principals, policies := principalpostgres.New(pool), bucketpolicypostgres.New(pool)
		require.NoError(t, providers.Add(ctx, providerID, region, policy))
		require.NoError(t, tenants.Add(ctx, tenantID, "tenant-1", tenant.Active))
		seedKey(t, accessKeys, secrets, delegations, principals, akSigner, tenantID, perms, principalBound)
		require.NoError(t, secrets.Write(ctx, vault.TenantKeyPath(tenantID), tenantSigner.Bytes()))
		powerline, err := delegation.Delegate(multikey.NewIssuer(tenantID, tenantSigner), akDID, did.DID{}, content.Retrieve.Command)
		require.NoError(t, err)
		require.NoError(t, delegations.PutBatch(ctx, []ucan.Delegation{powerline}))
		az := auth.NewAuthorizer(zap.NewNop(), accessKeys, tenants, providers, buckets, principals, policies, secrets)
		return bucketsvc.New(zap.NewNop(), az, buckets, delegations, accessKeys, tenants, policies, providers, sprue, nil, nil), buckets, tenants
	}

	args := func() *s3bkt.CreateArguments {
		return &s3bkt.CreateArguments{Request: presign(t, akSigner, "PUT", "https://s3.fil.one/"+bucketName, region)}
	}

	t.Run("creates and provisions the bucket, returning the powerline chain", func(t *testing.T) {
		sprue := &fakeSprue{sub: "sub-1"}
		svc, buckets, _ := setup(t, allPerms, false, sprue, nil, &providerPolicy)
		ok, blocks, err := svc.Create(ctx, providerID, args())
		require.NoError(t, err)

		rec, err := buckets.GetByName(ctx, bucketName)
		require.NoError(t, err)
		require.Equal(t, &rec.ID, ok.Bucket)
		require.Equal(t, tenantID, ok.Tenant)
		require.Equal(t, providerID, rec.Provider) // served by the provider that created it
		require.True(t, sprue.provCalled)
		require.Equal(t, tenantID, sprue.provAccount)
		require.Equal(t, *ok.Bucket, sprue.provSpace)
		require.Len(t, ok.Delegations.Entries, 1)
		require.Len(t, blocks, 2) // bucket→tenant root + tenant→access-key powerline
	})

	t.Run("points the bucket at the provider's routing policy as the tenant", func(t *testing.T) {
		sprue := &fakeSprue{sub: "sub-1"}
		svc, _, _ := setup(t, allPerms, false, sprue, nil, &providerPolicy)
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
		svc, _, _ := setup(t, allPerms, false, sprue, nil, nil)
		ok, _, err := svc.Create(ctx, providerID, args())
		require.NoError(t, err)
		require.NotNil(t, ok.Bucket)
		require.True(t, sprue.provCalled)
		require.False(t, sprue.useCalled)
	})

	t.Run("rolls back the bucket when applying the routing policy fails", func(t *testing.T) {
		svc, buckets, _ := setup(t, allPerms, false, &fakeSprue{useErr: errors.New("sprue unavailable")}, nil, &providerPolicy)
		_, _, err := svc.Create(ctx, providerID, args())
		require.Error(t, err)
		_, err = buckets.GetByName(ctx, bucketName)
		require.ErrorIs(t, err, store.ErrRecordNotFound)
	})

	t.Run("rejects a key without s3:CreateBucket", func(t *testing.T) {
		svc, _, _ := setup(t, []string{"s3:GetObject"}, false, &fakeSprue{}, nil, &providerPolicy)
		_, _, err := svc.Create(ctx, providerID, args())
		require.ErrorIs(t, err, auth.ErrOperationNotPermitted)
	})

	t.Run("rejects a principal-bound key", func(t *testing.T) {
		// No policy grants s3:CreateBucket, so the authorizer refuses the key
		// before the service is reached.
		svc, _, _ := setup(t, nil, true, &fakeSprue{}, nil, &providerPolicy)
		_, _, err := svc.Create(ctx, providerID, args())
		require.ErrorIs(t, err, auth.ErrOperationNotPermitted)
	})

	t.Run("rejects a duplicate name owned by another tenant", func(t *testing.T) {
		svc, buckets, tenants := setup(t, allPerms, false, &fakeSprue{}, nil, &providerPolicy)
		// Owner is a different tenant → BucketAlreadyExists.
		other := testutil.RandomDID(t)
		require.NoError(t, tenants.Add(ctx, other, "tenant-2", tenant.Active))
		require.NoError(t, buckets.Add(ctx, testutil.RandomDID(t), other, providerID, bucketName))
		_, _, err := svc.Create(ctx, providerID, args())
		require.ErrorIs(t, err, bucketsvc.ErrBucketExists)
	})

	t.Run("rejects re-creating a bucket you already own", func(t *testing.T) {
		svc, buckets, _ := setup(t, allPerms, false, &fakeSprue{}, nil, &providerPolicy)
		// Owner is the requesting tenant → BucketAlreadyOwnedByYou.
		require.NoError(t, buckets.Add(ctx, testutil.RandomDID(t), tenantID, providerID, bucketName))
		_, _, err := svc.Create(ctx, providerID, args())
		require.ErrorIs(t, err, bucketsvc.ErrBucketAlreadyOwned)
	})

	t.Run("rolls back the bucket when provisioning fails", func(t *testing.T) {
		svc, buckets, _ := setup(t, allPerms, false, &fakeSprue{provErr: errors.New("sprue unavailable")}, nil, &providerPolicy)
		_, _, err := svc.Create(ctx, providerID, args())
		require.Error(t, err)
		_, err = buckets.GetByName(ctx, bucketName)
		require.ErrorIs(t, err, store.ErrRecordNotFound)
	})

	t.Run("rolls back the bucket when listing delegations fails", func(t *testing.T) {
		// A failure after provisioning (listing the access key's delegations) must
		// still roll the bucket record back.
		failing := func(s delegationstore.Store) delegationstore.Store {
			return failingListDelegations{Store: s, err: errors.New("boom")}
		}
		svc, buckets, _ := setup(t, allPerms, false, &fakeSprue{}, failing, &providerPolicy)
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

// writeOnFirstProofChain runs write once, when the first proof chain is built.
// Info builds the chains after it has listed the delegations, so a policy write
// put here lands between the listing and the chain reads.
type writeOnFirstProofChain struct {
	delegationstore.Store
	once  sync.Once
	write func()
}

func (w *writeOnFirstProofChain) ProofChain(ctx context.Context, aud did.DID, cmd ucan.Command, sub did.DID) ([]ucan.Delegation, []cid.Cid, error) {
	w.once.Do(func() {
		if w.write != nil {
			w.write()
		}
	})
	return w.Store.ProofChain(ctx, aud, cmd, sub)
}

// gatedSwarf is a revocation service that refuses every publish while
// holding is set, so a test can look at the revocations owed first.
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

// deleteDeps is the world a Delete subtest operates on.
type deleteDeps struct {
	svc         *bucketsvc.Service
	runner      *taskrunner.Runner
	pool        *pgxpool.Pool
	buckets     *bucketpostgres.Store
	delegations *delegationpostgres.Store
	policies    bucketpolicystore.Store
	owed        *revocationpostgres.Store
	// policyWrites writes policies through the tenant's queue.
	policyWrites *bucketpolicysvc.Service
	swarf        *gatedSwarf
	tenantID     did.DID
	bucketID     did.DID
	root         ucan.Delegation // bucket→tenant, signed by the bucket's discarded key
	grant        ucan.Delegation // tenant→access key, scoped to the bucket
	// other is a grant over the bucket the tenant issued to someone other
	// than the requesting key, and powerline one that reaches every bucket.
	other, powerline ucan.Delegation
}

// held returns the CIDs of the delegations over the bucket still stored.
func (d deleteDeps) held(t *testing.T) []string {
	t.Helper()
	rows, err := d.pool.Query(t.Context(), `SELECT id FROM delegation WHERE subject = $1 ORDER BY id`, d.bucketID.String())
	require.NoError(t, err)
	ids, err := pgx.CollectRows(rows, pgx.RowTo[string])
	require.NoError(t, err)
	return ids
}

// owedLinks returns the CIDs of the revocations the tenant owes.
func (d deleteDeps) owedLinks(t *testing.T) []cid.Cid {
	t.Helper()
	dels, _, err := d.owed.Oldest(t.Context(), d.tenantID, revocation.Cursor{}, 10_000)
	require.NoError(t, err)
	out := make([]cid.Cid, len(dels))
	for i, dlg := range dels {
		out[i] = dlg.Link()
	}
	return out
}

// awaitPublished lets the revocation service take publishes and waits until
// the tenant owes nothing.
func (d deleteDeps) awaitPublished(t *testing.T) {
	t.Helper()
	d.swarf.holding.Store(false)
	require.Eventually(t, func() bool { return len(d.owedLinks(t)) == 0 }, htestutil.WaitTimeout, 10*time.Millisecond,
		"the revocations owed were not published")
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
	tenantIssuer := multikey.NewIssuer(tenantID, tenantSigner)
	providerID := testutil.RandomDID(t)

	// grantOpts lets a subtest vary the tenant→credential grant's expiry.
	setup := func(t *testing.T, perms []string, principalBound bool, sprue *fakeSprue, grantOpts ...delegation.Option) deleteDeps {
		t.Helper()
		pool := htestutil.PostgresOrSkip(t)
		accessKeys, tenants, buckets := accesskeypostgres.New(pool), tenantpostgres.New(pool), bucketpostgres.New(pool)
		providers, secrets, delegations := providerpostgres.New(pool), vaultmemory.New(), delegationpostgres.New(pool)
		principals, policies := principalpostgres.New(pool), bucketpolicypostgres.New(pool)
		require.NoError(t, providers.Add(ctx, providerID, region, nil))
		require.NoError(t, tenants.Add(ctx, tenantID, "tenant-1", tenant.Active))
		seedKey(t, accessKeys, secrets, delegations, principals, akSigner, tenantID, perms, principalBound)
		require.NoError(t, secrets.Write(ctx, vault.TenantKeyPath(tenantID), tenantSigner.Bytes()))
		bucketSigner, err := ed25519.Generate()
		require.NoError(t, err)
		bucketID := bucketSigner.KeyDID()
		require.NoError(t, buckets.Add(ctx, bucketID, tenantID, providerID, bucketName))
		// Both live as long as the bucket does, as the real ones do — without
		// WithNoExpiration ucantone defaults to a 30-second expiry, which would make
		// the expiry-skip behaviour timing-dependent.
		root, err := delegation.Delegate(
			multikey.NewIssuer(bucketID, bucketSigner), tenantID, bucketID, command.Top(), delegation.WithNoExpiration())
		require.NoError(t, err)
		if len(grantOpts) == 0 {
			grantOpts = []delegation.Option{delegation.WithNoExpiration()}
		}
		grant, err := delegation.Delegate(tenantIssuer, akDID, bucketID, content.Retrieve.Command, grantOpts...)
		require.NoError(t, err)
		other, err := delegation.Delegate(tenantIssuer, testutil.RandomDID(t), bucketID, content.Retrieve.Command, delegation.WithNoExpiration())
		require.NoError(t, err)
		powerline, err := delegation.Delegate(tenantIssuer, akDID, did.Undef, content.Retrieve.Command, delegation.WithNoExpiration())
		require.NoError(t, err)
		require.NoError(t, delegations.PutBatch(ctx, []ucan.Delegation{root, grant, other, powerline}))

		swarf := &gatedSwarf{}
		runner := htestutil.StartServiceTasks(t, pool, secrets, swarf, func(d *tenantqueue.Deps) { d.Uploads = sprue })
		az := auth.NewAuthorizer(zap.NewNop(), accessKeys, tenants, providers, buckets, principals, policies, secrets,
			auth.WithTenantChanges(runner), auth.WithSnapshots(pglock.NewSnapshots(pool)))
		policyWrites := bucketpolicysvc.New(zap.NewNop(), tenants, buckets, principals, policies, runner)
		return deleteDeps{
			svc:          bucketsvc.New(zap.NewNop(), az, buckets, delegations, accessKeys, tenants, policies, providers, sprue, policyWrites, runner),
			runner:       runner,
			pool:         pool,
			buckets:      buckets,
			delegations:  delegations,
			policies:     policies,
			owed:         revocationpostgres.New(pool),
			policyWrites: policyWrites,
			tenantID:     tenantID,
			swarf:        swarf,
			bucketID:     bucketID,
			root:         root,
			grant:        grant,
			other:        other,
			powerline:    powerline,
		}
	}

	del := func(name string) *s3bkt.DeleteArguments {
		return &s3bkt.DeleteArguments{Request: presign(t, akSigner, "DELETE", "https://s3.fil.one/"+name, region)}
	}
	everyone := func(name string) s3bkt.PolicyDocument {
		return s3bkt.PolicyDocument{Version: s3bkt.Version2012, Statements: []s3bkt.Statement{{Effect: s3bkt.Allow, Principal: s3bkt.Everyone(), Actions: s3bkt.NewStringSet("s3:GetObject"), Resources: s3bkt.NewStringSet(s3bkt.BucketARN(name), s3bkt.ObjectsARN(name))}}}
	}

	t.Run("deletes an empty bucket with its delegations and policy, asking Sprue as the tenant", func(t *testing.T) {
		sprue := &fakeSprue{empty: true}
		d := setup(t, allPerms, false, sprue)
		htestutil.PutPolicy(t, d.pool, d.tenantID, d.bucketID, everyone(bucketName))

		_, err := d.svc.Delete(ctx, providerID, del(bucketName))
		require.NoError(t, err)
		require.True(t, sprue.emptyCalled)
		require.Equal(t, d.bucketID, sprue.emptySpace)
		require.Equal(t, tenantID, sprue.emptyIssuer)
		_, err = d.buckets.GetByName(ctx, bucketName)
		require.ErrorIs(t, err, store.ErrRecordNotFound)
		_, err = d.policies.Get(ctx, d.bucketID)
		require.ErrorIs(t, err, store.ErrRecordNotFound)
		require.Empty(t, d.held(t), "no delegation over the bucket outlives it")
		page, err := d.delegations.ListByAudience(ctx, akDID)
		require.NoError(t, err)
		require.Equal(t, []ucan.Delegation{d.powerline}, page.Results, "a powerline grant reaches the tenant's other buckets and stays")
	})

	t.Run("owes the tenant's grants over the bucket and publishes them, with no witness path, and not the root", func(t *testing.T) {
		d := setup(t, allPerms, false, &fakeSprue{empty: true})
		d.swarf.holding.Store(true)

		_, err := d.svc.Delete(ctx, providerID, del(bucketName))
		require.NoError(t, err)
		require.ElementsMatch(t, []cid.Cid{d.grant.Link(), d.other.Link()}, d.owedLinks(t), "every grant the tenant issued over the bucket, whoever holds it")
		require.Empty(t, d.swarf.Revocations(), "nothing is published before the commit")

		d.awaitPublished(t)
		var revoked []cid.Cid
		for _, r := range d.swarf.Revocations() {
			// The tenant issued each grant, so the tenant revokes it directly.
			require.Equal(t, tenantID, r.Revoker)
			// The root was signed by the bucket's discarded key: the tenant is
			// only its audience, so no revocation it could sign would be
			// accepted.
			require.NotEqual(t, d.root.Link(), r.Revoked)
			revoked = append(revoked, r.Revoked)
		}
		require.ElementsMatch(t, []cid.Cid{d.grant.Link(), d.other.Link()}, revoked)
	})

	t.Run("skips an expired grant", func(t *testing.T) {
		expired := delegation.WithExpiration(ucan.UnixTimestamp(time.Now().Add(-time.Hour).Unix()))
		d := setup(t, allPerms, false, &fakeSprue{empty: true}, expired)

		// The revocation service rejects expired delegations, and they are unusable
		// anyway — so the bucket is still deleted, with the expired grant never
		// published.
		_, err := d.svc.Delete(ctx, providerID, del(bucketName))
		require.NoError(t, err)
		d.awaitPublished(t)
		for _, r := range d.swarf.Revocations() {
			require.NotEqual(t, d.grant.Link(), r.Revoked)
		}
		_, err = d.buckets.GetByName(ctx, bucketName)
		require.ErrorIs(t, err, store.ErrRecordNotFound)
	})

	t.Run("succeeds while the revocation service is down, and publishes once it is back", func(t *testing.T) {
		d := setup(t, allPerms, false, &fakeSprue{empty: true})
		d.swarf.holding.Store(true)

		_, err := d.svc.Delete(ctx, providerID, del(bucketName))
		require.NoError(t, err)
		_, err = d.buckets.GetByName(ctx, bucketName)
		require.ErrorIs(t, err, store.ErrRecordNotFound)
		require.NotEmpty(t, d.owedLinks(t))
		d.awaitPublished(t)
		require.Len(t, d.swarf.Revocations(), 2)
	})

	t.Run("a policy write issued during the deletion waits for it and finds the bucket gone", func(t *testing.T) {
		sprue := &fakeSprue{empty: true}
		d := setup(t, []string{"s3:DeleteBucket"}, false, sprue)
		written := make(chan error, 1)
		sprue.onEmpty = func() {
			go func() {
				_, _, err := d.policyWrites.Write(context.Background(), d.tenantID, d.bucketID, bucketName, everyone(bucketName))
				written <- err
			}()
			select {
			case err := <-written:
				t.Errorf("the write finished while the deletion was running: %v", err)
			case <-time.After(htestutil.MinBlock):
			}
		}

		_, err := d.svc.Delete(ctx, providerID, del(bucketName))
		require.NoError(t, err)
		select {
		case err := <-written:
			require.ErrorIs(t, err, bucketpolicysvc.ErrBucketNotFound, "the write ran after the deletion and found no bucket")
		case <-time.After(htestutil.WaitTimeout):
			t.Fatal("the write did not finish")
		}
		_, err = d.policies.Get(ctx, d.bucketID)
		require.ErrorIs(t, err, store.ErrRecordNotFound)
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

	// requireUnchanged requires that nothing of the bucket was deleted or
	// owed.
	requireUnchanged := func(t *testing.T, d deleteDeps) {
		t.Helper()
		_, err := d.buckets.GetByName(ctx, bucketName)
		require.NoError(t, err)
		_, err = d.policies.Get(ctx, d.bucketID)
		require.NoError(t, err, "the policy stays")
		require.Len(t, d.held(t), 3, "the root and both grants stay")
		require.Empty(t, d.owedLinks(t), "nothing is owed")
		require.Empty(t, d.swarf.Revocations(), "nothing is revoked")
	}

	t.Run("rejects a non-empty bucket and keeps it", func(t *testing.T) {
		d := setup(t, allPerms, false, &fakeSprue{empty: false})
		htestutil.PutPolicy(t, d.pool, d.tenantID, d.bucketID, everyone(bucketName))
		_, err := d.svc.Delete(ctx, providerID, del(bucketName))
		require.ErrorIs(t, err, bucketsvc.ErrBucketNotEmpty)
		require.ErrorContains(t, err, bucketName)
		requireUnchanged(t, d)
	})

	t.Run("propagates a SpaceEmpty error and keeps the bucket", func(t *testing.T) {
		d := setup(t, allPerms, false, &fakeSprue{emptyErr: errors.New("sprue unavailable")})
		htestutil.PutPolicy(t, d.pool, d.tenantID, d.bucketID, everyone(bucketName))
		_, err := d.svc.Delete(ctx, providerID, del(bucketName))
		require.ErrorContains(t, err, "sprue unavailable")
		requireUnchanged(t, d)
	})
}

func TestList(t *testing.T) {
	ctx := t.Context()
	// providerID serves region and handles every request here; provider2ID
	// serves region2 and only ever owns buckets.
	const region, region2 = "us-west-2", "eu-west-1"

	signer, err := ed25519.Generate()
	require.NoError(t, err)
	providerID, provider2ID := testutil.RandomDID(t), testutil.RandomDID(t)

	setup := func(t *testing.T, perms []string, principalBound bool) (*bucketsvc.Service, *bucketpostgres.Store, did.DID) {
		t.Helper()
		pool := htestutil.PostgresOrSkip(t)
		accessKeys, tenants, buckets := accesskeypostgres.New(pool), tenantpostgres.New(pool), bucketpostgres.New(pool)
		providers, secrets, delegations := providerpostgres.New(pool), vaultmemory.New(), delegationpostgres.New(pool)
		principals, policies := principalpostgres.New(pool), bucketpolicypostgres.New(pool)
		require.NoError(t, providers.Add(ctx, providerID, region, nil))
		require.NoError(t, providers.Add(ctx, provider2ID, region2, nil))
		tenantID := testutil.RandomDID(t)
		require.NoError(t, tenants.Add(ctx, tenantID, "tenant-1", tenant.Active))
		seedKey(t, accessKeys, secrets, delegations, principals, signer, tenantID, perms, principalBound)
		az := auth.NewAuthorizer(zap.NewNop(), accessKeys, tenants, providers, buckets, principals, policies, secrets)
		return bucketsvc.New(zap.NewNop(), az, buckets, delegations, accessKeys, tenants, policies, providers, &fakeSprue{}, nil, nil), buckets, tenantID
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
		require.NoError(t, buckets.Add(ctx, testutil.RandomDID(t), tenantID, providerID, "alpha"))
		require.NoError(t, buckets.Add(ctx, testutil.RandomDID(t), tenantID, providerID, "bravo"))
		ok, err := svc.List(ctx, providerID, listArgs())
		require.NoError(t, err)
		require.Equal(t, []string{"alpha", "bravo"}, bucketNames(ok))
		require.Empty(t, ok.ContinuationToken)
		require.Empty(t, ok.Prefix)
	})

	t.Run("reports every bucket of the tenant in the region of its provider", func(t *testing.T) {
		// ListBuckets is account-wide in S3: a bucket served by another region is
		// listed, labelled with that region, rather than hidden.
		svc, buckets, tenantID := setup(t, []string{"s3:ListAllMyBuckets"}, false)
		require.NoError(t, buckets.Add(ctx, testutil.RandomDID(t), tenantID, providerID, "local"))
		require.NoError(t, buckets.Add(ctx, testutil.RandomDID(t), tenantID, provider2ID, "remote"))
		ok, err := svc.List(ctx, providerID, listArgs())
		require.NoError(t, err)
		require.Equal(t, []string{"local", "remote"}, bucketNames(ok))
		require.Equal(t, region, ok.Buckets[0].Region)
		require.Equal(t, region2, ok.Buckets[1].Region)
	})

	t.Run("bucket-region narrows the listing to one region", func(t *testing.T) {
		svc, buckets, tenantID := setup(t, []string{"s3:ListAllMyBuckets"}, false)
		require.NoError(t, buckets.Add(ctx, testutil.RandomDID(t), tenantID, providerID, "local"))
		require.NoError(t, buckets.Add(ctx, testutil.RandomDID(t), tenantID, provider2ID, "remote"))

		ok, err := svc.List(ctx, providerID, listArgs("bucket-region="+region))
		require.NoError(t, err)
		require.Equal(t, []string{"local"}, bucketNames(ok))
		require.Equal(t, region, ok.Buckets[0].Region)
	})

	t.Run("rejects a bucket-region other than the one signed for", func(t *testing.T) {
		// S3 does not answer the parameter from another region's endpoint: a
		// listing limited to one region must be asked of that region.
		svc, buckets, tenantID := setup(t, []string{"s3:ListAllMyBuckets"}, false)
		require.NoError(t, buckets.Add(ctx, testutil.RandomDID(t), tenantID, providerID, "local"))
		require.NoError(t, buckets.Add(ctx, testutil.RandomDID(t), tenantID, provider2ID, "remote"))

		for _, r := range []string{region2, "ap-south-1"} {
			_, err := svc.List(ctx, providerID, listArgs("bucket-region="+r))
			require.ErrorIs(t, err, bucketsvc.ErrInvalidArgument, "bucket-region %q", r)
		}
	})

	t.Run("bucket-region paginates within the filter", func(t *testing.T) {
		// Interleaved by name, so a filter applied after the page was read
		// would answer with one bucket and a token instead of a full page.
		svc, buckets, tenantID := setup(t, []string{"s3:ListAllMyBuckets"}, false)
		for _, b := range []struct {
			name     string
			provider did.DID
		}{
			{"alpha", providerID},
			{"bravo", provider2ID},
			{"charlie", providerID},
			{"delta", provider2ID},
			{"echo", providerID},
		} {
			require.NoError(t, buckets.Add(ctx, testutil.RandomDID(t), tenantID, b.provider, b.name))
		}

		ok, err := svc.List(ctx, providerID, listArgs("bucket-region="+region, "max-buckets=2"))
		require.NoError(t, err)
		require.Equal(t, []string{"alpha", "charlie"}, bucketNames(ok))
		require.Equal(t, "charlie", ok.ContinuationToken)

		ok, err = svc.List(ctx, providerID, listArgs("bucket-region="+region, "max-buckets=2", "continuation-token="+ok.ContinuationToken))
		require.NoError(t, err)
		require.Equal(t, []string{"echo"}, bucketNames(ok))
		require.Empty(t, ok.ContinuationToken)
	})

	t.Run("filters by prefix and echoes it", func(t *testing.T) {
		svc, buckets, tenantID := setup(t, allPerms, false)
		require.NoError(t, buckets.Add(ctx, testutil.RandomDID(t), tenantID, providerID, "alpha"))
		require.NoError(t, buckets.Add(ctx, testutil.RandomDID(t), tenantID, providerID, "apple"))
		require.NoError(t, buckets.Add(ctx, testutil.RandomDID(t), tenantID, providerID, "bravo"))
		ok, err := svc.List(ctx, providerID, listArgs("prefix=a"))
		require.NoError(t, err)
		require.Equal(t, []string{"alpha", "apple"}, bucketNames(ok))
		require.Equal(t, "a", ok.Prefix)
		require.Empty(t, ok.ContinuationToken)
	})

	t.Run("paginates with max-buckets and continuation-token", func(t *testing.T) {
		svc, buckets, tenantID := setup(t, allPerms, false)
		for _, name := range []string{"charlie", "alpha", "bravo"} {
			require.NoError(t, buckets.Add(ctx, testutil.RandomDID(t), tenantID, providerID, name))
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
		require.NoError(t, buckets.Add(ctx, testutil.RandomDID(t), tenantID, providerID, "alpha"))
		ok, err := svc.List(ctx, providerID, listArgs())
		require.NoError(t, err)
		require.Equal(t, []string{"alpha"}, bucketNames(ok))
	})

	t.Run("rejects a validly-signed request for a different operation", func(t *testing.T) {
		// A GetObject request the credential IS permitted for passes Authorize, but
		// List rejects it as not a ListBuckets operation.
		svc, buckets, tenantID := setup(t, allPerms, false)
		require.NoError(t, buckets.Add(ctx, testutil.RandomDID(t), tenantID, providerID, "bucket-a"))
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
	providerID := testutil.RandomDID(t)

	// setup seeds a tenant belonging to providerID, its bucket, a credential (a
	// service credential unless principalBound), a bucket→tenant root, and either
	// a tenant→credential grant with the given subject (did.DID{} = powerline) or,
	// for a principal-bound key, its grants over the bucket. Each wrap decorates
	// the delegation store the service reads through. It also returns a
	// function that adds a key belonging to another tenant.
	setup := func(t *testing.T, perms []string, principalBound bool, grantSubject did.DID) (*bucketsvc.Service, *pgxpool.Pool, ucan.Delegation, func(t *testing.T) did.DID) {
		t.Helper()
		pool := htestutil.PostgresOrSkip(t)
		accessKeys, buckets, delegations := accesskeypostgres.New(pool), bucketpostgres.New(pool), delegationpostgres.New(pool)
		tenants := tenantpostgres.New(pool)
		principals, policies := principalpostgres.New(pool), bucketpolicypostgres.New(pool)
		require.NoError(t, tenants.Add(ctx, tenantID, "tenant-1", tenant.Active))
		// A principal-bound key holds the grants its policy maps to over the
		// bucket, issued as the tenant.
		var grants []ucan.Delegation
		if principalBound {
			grants, err = grant.Issue(multikey.NewIssuer(tenantID, tenantSigner), akDID, []did.DID{bucketID}, []string{"s3:GetObject", "s3:ListBucket"}, nil)
			require.NoError(t, err)
		}
		seedKey(t, accessKeys, vaultmemory.New(), delegations, principals, akSigner, tenantID, perms, principalBound, grants...)
		providers := providerpostgres.New(pool)
		require.NoError(t, providers.Add(ctx, providerID, "us-west-2", nil))
		require.NoError(t, buckets.Add(ctx, bucketID, tenantID, providerID, bucketName))
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
		az := auth.NewAuthorizer(zap.NewNop(), accessKeys, tenants, providers, buckets, principals, policies, vaultmemory.New(),
			auth.WithSnapshots(pglock.NewSnapshots(pool)))
		addForeignKey := func(t *testing.T) did.DID {
			t.Helper()
			other, foreign := testutil.RandomDID(t), testutil.RandomDID(t)
			require.NoError(t, tenants.Add(ctx, other, "tenant-2", tenant.Active))
			require.NoError(t, accessKeys.Add(ctx, accesskey.Input{ID: foreign, Tenant: other, Name: "k2", Permissions: []string{"s3:GetObject"}}))
			return foreign
		}
		return bucketsvc.New(zap.NewNop(), az, buckets, delegations, accessKeys, tenants, policies, providers, &fakeSprue{}, nil, nil), pool, root, addForeignKey
	}

	// grantPolicy stores a policy allowing "user-1" the given actions on the bucket.
	grantPolicy := func(t *testing.T, pool *pgxpool.Pool, actions ...string) {
		t.Helper()
		htestutil.PutPolicy(t, pool, tenantID, bucketID, s3bkt.PolicyDocument{Version: s3bkt.Version2012, Statements: []s3bkt.Statement{{
			Effect:    s3bkt.Allow,
			Principal: s3bkt.Only("user-1"),
			Actions:   s3bkt.NewStringSet(actions...),
			Resources: s3bkt.NewStringSet(s3bkt.BucketARN("photos"), s3bkt.ObjectsARN("photos")),
		}}})
	}

	t.Run("returns the bucket, permissions, and delegation chain", func(t *testing.T) {
		svc, _, _, _ := setup(t, allPerms, false, did.DID{}) // powerline grant reaches the bucket
		ok, blocks, err := svc.Info(ctx, providerID, &s3bkt.InfoArguments{Name: bucketName, AccessKey: akDID})
		require.NoError(t, err)
		require.Equal(t, bucketID, ok.ID)
		// A service key carries its own permission set.
		require.Equal(t, allPerms, ok.Permissions.Entries[akDID])
		require.Len(t, blocks, 2)
	})

	t.Run("rejects an unknown bucket", func(t *testing.T) {
		svc, _, _, _ := setup(t, allPerms, false, did.DID{})
		_, _, err := svc.Info(ctx, providerID, &s3bkt.InfoArguments{Name: "nope", AccessKey: akDID})
		require.ErrorIs(t, err, bucketsvc.ErrUnknownBucket)
	})

	t.Run("rejects an issuer that is not the tenant's provider", func(t *testing.T) {
		svc, _, _, _ := setup(t, allPerms, false, did.DID{})
		_, _, err := svc.Info(ctx, testutil.RandomDID(t), &s3bkt.InfoArguments{Name: bucketName, AccessKey: akDID})
		require.ErrorIs(t, err, auth.ErrIssuerForbidden)
	})

	t.Run("rejects an access key belonging to another tenant", func(t *testing.T) {
		svc, _, _, addForeignKey := setup(t, allPerms, false, did.DID{})
		foreign := addForeignKey(t)
		_, _, err := svc.Info(ctx, providerID, &s3bkt.InfoArguments{Name: bucketName, AccessKey: foreign})
		require.ErrorIs(t, err, auth.ErrForeignBucket)
	})

	t.Run("rejects an unknown access key", func(t *testing.T) {
		svc, _, _, _ := setup(t, allPerms, false, did.DID{})
		_, _, err := svc.Info(ctx, providerID, &s3bkt.InfoArguments{Name: bucketName, AccessKey: testutil.RandomDID(t)})
		require.ErrorIs(t, err, bucketsvc.ErrUnknownAccessKey)
	})

	t.Run("a principal-bound key gets its effective set and the chains through its grants", func(t *testing.T) {
		svc, pool, root, _ := setup(t, nil, true, did.DID{})
		grantPolicy(t, pool, "s3:GetObject", "s3:ListBucket")

		ok, blocks, err := svc.Info(ctx, providerID, &s3bkt.InfoArguments{Name: bucketName, AccessKey: akDID})
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
		svc, _, _, _ := setup(t, nil, true, did.DID{}) // no policy at all
		_, _, err := svc.Info(ctx, providerID, &s3bkt.InfoArguments{Name: bucketName, AccessKey: akDID})
		require.ErrorIs(t, err, bucketsvc.ErrUnknownBucket)
	})

	t.Run("returns empty delegations when no grant reaches the bucket", func(t *testing.T) {
		svc, _, _, _ := setup(t, allPerms, false, testutil.RandomDID(t)) // grant scoped to a different bucket
		ok, blocks, err := svc.Info(ctx, providerID, &s3bkt.InfoArguments{Name: bucketName, AccessKey: akDID})
		require.NoError(t, err)
		require.Empty(t, ok.Delegations.Entries)
		require.Empty(t, blocks)
	})
}

// TestInfoAcrossAPolicyWrite commits a policy write that narrows a
// principal's actions on the bucket while Info is between two of its reads:
// after it has read the effective actions and before it lists the key's
// grants, or after it has listed them and before it builds their chains.
// Both s3:GetObject and s3:ListBucket map to /content/retrieve, so pairing
// the old actions with the new grants would report a permission the write
// removed over a chain that still serves it. Info reads in one snapshot, so
// it answers the state before the write, whole: the old actions over the old
// grants, which the write withdrew and owes as revocations.
func TestInfoAcrossAPolicyWrite(t *testing.T) {
	for name, hook := range map[string]func(s delegationstore.Store, write func()) delegationstore.Store{
		"before the grants are listed": func(s delegationstore.Store, write func()) delegationstore.Store {
			return &writeOnFirstList{Store: s, write: write}
		},
		"before the chains are built": func(s delegationstore.Store, write func()) delegationstore.Store {
			return &writeOnFirstProofChain{Store: s, write: write}
		},
	} {
		t.Run(name, func(t *testing.T) {
			infoAcrossAPolicyWrite(t, hook)
		})
	}
}

func infoAcrossAPolicyWrite(t *testing.T, straddle func(s delegationstore.Store, write func()) delegationstore.Store) {
	pool := htestutil.PostgresOrSkip(t)
	ctx := t.Context()
	principals, policies := principalpostgres.New(pool), bucketpolicypostgres.New(pool)
	tenants, buckets, delegations := tenantpostgres.New(pool), bucketpostgres.New(pool), delegationpostgres.New(pool)
	accessKeys, providers, owed := accesskeypostgres.New(pool), providerpostgres.New(pool), revocationpostgres.New(pool)
	secrets := vaultmemory.New()

	akSigner, err := ed25519.Generate()
	require.NoError(t, err)
	akDID := akSigner.KeyDID()
	tenantSigner, err := secp256k1.Generate()
	require.NoError(t, err)
	tenantID := tenantSigner.KeyDID()
	require.NoError(t, secrets.Write(ctx, vault.TenantKeyPath(tenantID), tenantSigner.Bytes()))
	bucketSigner, err := ed25519.Generate()
	require.NoError(t, err)
	bucketID := bucketSigner.KeyDID()
	providerID := testutil.RandomDID(t)
	const bucketName = "infowrite"

	require.NoError(t, providers.Add(ctx, providerID, "us-west-2", nil))
	require.NoError(t, tenants.Add(ctx, tenantID, "ext-"+tenantID.String(), tenant.Active))
	require.NoError(t, buckets.Add(ctx, bucketID, tenantID, providerID, bucketName))
	root, err := delegation.Delegate(multikey.NewIssuer(bucketID, bucketSigner), tenantID, bucketID, command.Top(), delegation.WithNoExpiration())
	require.NoError(t, err)
	require.NoError(t, delegations.PutBatch(ctx, []ucan.Delegation{root}))

	statement := func(actions ...string) s3bkt.PolicyDocument {
		return s3bkt.PolicyDocument{Version: s3bkt.Version2012, Statements: []s3bkt.Statement{{Effect: s3bkt.Allow, Principal: s3bkt.Only("user-1"), Actions: s3bkt.NewStringSet(actions...), Resources: s3bkt.NewStringSet(s3bkt.BucketARN(bucketName), s3bkt.ObjectsARN(bucketName))}}}
	}
	// The key and the policy are made through the services, so the key
	// holds the grants of the policy.
	swarf := &htestutil.FakeSwarf{}
	runner := htestutil.StartServiceTasks(t, pool, secrets, swarf)
	policyWrites := bucketpolicysvc.New(zap.NewNop(), tenants, buckets, principals, policies, runner)
	require.NoError(t, principals.Add(ctx, tenantID, "user-1"))
	_, _, err = policyWrites.Write(ctx, tenantID, bucketID, bucketName, statement("s3:GetObject", "s3:ListBucket"))
	require.NoError(t, err)
	principal := "user-1"
	require.NoError(t, secrets.Write(ctx, vault.AccessKeyPath(tenantID, akDID), akSigner.Bytes()))
	spec, err := tenantqueue.CreateKeySpec(accesskey.Input{ID: akDID, Tenant: tenantID, Name: "k1", Principal: &principal})
	require.NoError(t, err)
	_, err = runner.Run(ctx, spec)
	require.NoError(t, err)
	page, err := delegations.ListByAudience(ctx, akDID)
	require.NoError(t, err)
	before := page.Results
	require.NotEmpty(t, before)

	reads := straddle(delegations, func() {
		_, _, err := policyWrites.Write(context.Background(), tenantID, bucketID, bucketName, statement("s3:ListBucket"))
		require.NoError(t, err)
	})
	az := auth.NewAuthorizer(zap.NewNop(), accessKeys, tenants, providers, buckets, principals, policies, secrets,
		auth.WithSnapshots(pglock.NewSnapshots(pool)))
	svc := bucketsvc.New(zap.NewNop(), az, buckets, reads, accessKeys, tenants, policies, providers, &fakeSprue{}, policyWrites, runner)

	ok, _, err := svc.Info(ctx, providerID, &s3bkt.InfoArguments{Name: bucketName, AccessKey: akDID})
	require.NoError(t, err)
	require.Equal(t, []string{"s3:GetObject", "s3:ListBucket"}, ok.Permissions.Entries[akDID], "the actions before the write")
	var answered []cid.Cid
	for link := range ok.Delegations.Entries {
		answered = append(answered, link)
	}
	var held []cid.Cid
	for _, d := range before {
		held = append(held, d.Link())
	}
	require.ElementsMatch(t, held, answered, "the grants before the write")

	// Those grants are the ones the write withdrew: every one is owed or,
	// once the revocation queue has run, published, so the gateway is told
	// to drop an answer that names them.
	dels, _, err := owed.Oldest(ctx, tenantID, revocation.Cursor{}, 100)
	require.NoError(t, err)
	withdrawn := swarf.Revoked()
	for _, d := range dels {
		withdrawn = append(withdrawn, d.Link())
	}
	require.Subset(t, withdrawn, held)

	// The next call answers the state the write left.
	ok, _, err = svc.Info(ctx, providerID, &s3bkt.InfoArguments{Name: bucketName, AccessKey: akDID})
	require.NoError(t, err)
	require.Equal(t, []string{"s3:ListBucket"}, ok.Permissions.Entries[akDID])
	for link := range ok.Delegations.Entries {
		require.NotContains(t, held, link)
	}
}
