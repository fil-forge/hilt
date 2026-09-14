package accesskey_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/fil-forge/hilt/internal/testutil"
	accesskeysvc "github.com/fil-forge/hilt/pkg/api/service/accesskey"
	"github.com/fil-forge/hilt/pkg/store"
	accesskeystore "github.com/fil-forge/hilt/pkg/store/accesskey"
	accesskeymemory "github.com/fil-forge/hilt/pkg/store/accesskey/memory"
	bucketmemory "github.com/fil-forge/hilt/pkg/store/bucket/memory"
	delegationmemory "github.com/fil-forge/hilt/pkg/store/delegation/memory"
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
	"github.com/fil-forge/ucantone/ucan/command"
	"github.com/fil-forge/ucantone/ucan/delegation"
	"github.com/ipfs/go-cid"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

// revocation records one published revocation. options counts the [PublishOption]s
// it was published with: Swarf's publishConfig is unexported, so the count is how
// a witness path being sent is detected.
type revocation struct {
	revoker did.DID
	revoked cid.Cid
	options int
}

// fakeSwarf is a stub of the revocation service, recording what it was asked to
// publish.
type fakeSwarf struct {
	err         error
	revocations []revocation
}

func (f *fakeSwarf) Publish(_ context.Context, revoker ucan.Issuer, revoked ucan.Delegation, opts ...swarfclient.PublishOption) error {
	if f.err != nil {
		return f.err
	}
	f.revocations = append(f.revocations, revocation{revoker: revoker.DID(), revoked: revoked.Link(), options: len(opts)})
	return nil
}

// failReadBack wraps an access-key store and fails its first Get, standing in
// for a read-back that cannot see the row the call just wrote. It records the ID
// it was asked for, so the test can check what the rollback cleaned up.
type failReadBack struct {
	accesskeystore.Store
	id     did.DID
	failed bool
}

func (f *failReadBack) Get(ctx context.Context, id did.DID, opts ...store.ReadOption) (accesskeystore.Record, error) {
	if !f.failed {
		f.failed, f.id = true, id
		return accesskeystore.Record{}, errors.New("read-back failed")
	}
	return f.Store.Get(ctx, id, opts...)
}

// fakeInvalidations is a stub of the principal invalidation publisher,
// recording the principals it was asked to invalidate.
type fakeInvalidations struct {
	err        error
	principals []string
}

func (f *fakeInvalidations) Invalidate(_ context.Context, _ did.DID, principal string) error {
	if f.err != nil {
		return f.err
	}
	f.principals = append(f.principals, principal)
	return nil
}

// lockedAccessKeys fails Delete with err, standing in for the store giving up
// on a row another write holds.
type lockedAccessKeys struct {
	accesskeystore.Store
	err error
}

func (l *lockedAccessKeys) Delete(context.Context, did.DID, func(context.Context) error) error {
	return l.err
}

type deps struct {
	svc           *accesskeysvc.Service
	tenants       *tenantmemory.Store
	accessKeys    *accesskeymemory.Store
	principals    *principalmemory.Store
	delegations   *delegationmemory.Store
	buckets       *bucketmemory.Store
	secrets       *vaultmemory.Store
	swarf         *fakeSwarf
	invalidations *fakeInvalidations
	tenantID      did.DID
	bucketID      did.DID
	bucketRoot    ucan.Delegation
}

// setup wires the service over memory stores with one tenant ("tenant-1") whose
// secp256k1 key is in the vault, owning one bucket ("bucket-a") that has issued
// the tenant top authority over itself — the root of every proof chain through
// the bucket, as [bucket.Service.Create] would have stored it. Its audience is the
// tenant, not an access key, so it must never be revoked along with one. The
// tenant has one principal, "alice".
//
// wrapAccessKeys, when given, wraps the memory access-key store the service is
// built over, so a test can make one of its methods fail.
func setup(t *testing.T, wrapAccessKeys ...func(accesskeystore.Store) accesskeystore.Store) deps {
	t.Helper()
	ctx := t.Context()
	tenants, accessKeys, principals := tenantmemory.New(), accesskeymemory.New(), principalmemory.New()
	buckets, delegations, secrets := bucketmemory.New(), delegationmemory.New(), vaultmemory.New()

	var keys accesskeystore.Store = accessKeys
	for _, wrap := range wrapAccessKeys {
		keys = wrap(keys)
	}

	signer, err := secp256k1.Generate()
	require.NoError(t, err)
	tenantID := signer.KeyDID()
	require.NoError(t, tenants.Add(ctx, tenantID, "tenant-1", testutil.RandomDID(t), tenant.Active))
	require.NoError(t, secrets.Write(ctx, vault.TenantKeyPath(tenantID), signer.Bytes()))
	require.NoError(t, principals.Add(ctx, tenantID, "alice"))

	// The bucket key is ephemeral: it signs the bucket→tenant root and is discarded.
	bucketSigner, err := ed25519.Generate()
	require.NoError(t, err)
	bucketID := bucketSigner.KeyDID()
	require.NoError(t, buckets.Add(ctx, bucketID, tenantID, "bucket-a"))
	root, err := delegation.Delegate(
		multikey.NewIssuer(bucketID, bucketSigner), tenantID, bucketID, command.Top(), delegation.WithNoExpiration())
	require.NoError(t, err)
	require.NoError(t, delegations.PutBatch(ctx, []ucan.Delegation{root}))

	swarf := &fakeSwarf{}
	invalidations := &fakeInvalidations{}
	return deps{
		svc:           accesskeysvc.New(zap.NewNop(), tenants, keys, principals, buckets, delegations, secrets, swarf, invalidations),
		tenants:       tenants,
		accessKeys:    accessKeys,
		principals:    principals,
		delegations:   delegations,
		buckets:       buckets,
		secrets:       secrets,
		swarf:         swarf,
		invalidations: invalidations,
		tenantID:      tenantID,
		bucketID:      bucketID,
		bucketRoot:    root,
	}
}

func TestCreate(t *testing.T) {
	ctx := t.Context()

	t.Run("creates a bucket-scoped key", func(t *testing.T) {
		d := setup(t)
		rec, secret, err := d.svc.Create(ctx, "tenant-1", "k1", []string{"s3:GetObject"}, []string{"bucket-a"}, "", nil)
		require.NoError(t, err)
		require.NotEmpty(t, secret)
		require.Equal(t, "k1", rec.Name)
		require.Equal(t, []did.DID{d.bucketID}, rec.Buckets)
	})

	t.Run("rejects an empty name", func(t *testing.T) {
		d := setup(t)
		_, _, err := d.svc.Create(ctx, "tenant-1", "", []string{"s3:GetObject"}, nil, "", nil)
		require.ErrorIs(t, err, accesskeysvc.ErrInvalidName)
	})

	t.Run("rejects no permissions", func(t *testing.T) {
		d := setup(t)
		_, _, err := d.svc.Create(ctx, "tenant-1", "k1", nil, nil, "", nil)
		require.ErrorIs(t, err, accesskeysvc.ErrNoPermissions)
	})

	t.Run("rejects an unknown permission", func(t *testing.T) {
		d := setup(t)
		_, _, err := d.svc.Create(ctx, "tenant-1", "k1", []string{"s3:Bogus"}, nil, "", nil)
		require.ErrorIs(t, err, accesskeysvc.ErrInvalidPermission)
	})

	t.Run("rejects an unknown bucket", func(t *testing.T) {
		d := setup(t)
		_, _, err := d.svc.Create(ctx, "tenant-1", "k1", []string{"s3:GetObject"}, []string{"nope"}, "", nil)
		require.ErrorIs(t, err, accesskeysvc.ErrUnknownBucket)
	})

	t.Run("rejects an unknown tenant", func(t *testing.T) {
		d := setup(t)
		_, _, err := d.svc.Create(ctx, "missing", "k1", []string{"s3:GetObject"}, nil, "", nil)
		require.ErrorIs(t, err, accesskeysvc.ErrTenantNotFound)
	})

	t.Run("rejects a duplicate name", func(t *testing.T) {
		d := setup(t)
		_, _, err := d.svc.Create(ctx, "tenant-1", "dup", []string{"s3:GetObject"}, nil, "", nil)
		require.NoError(t, err)
		_, _, err = d.svc.Create(ctx, "tenant-1", "dup", []string{"s3:GetObject"}, nil, "", nil)
		require.ErrorIs(t, err, accesskeysvc.ErrNameConflict)
	})
}

func TestCreatePrincipalBound(t *testing.T) {
	ctx := t.Context()

	t.Run("binds the key to the principal and issues nothing", func(t *testing.T) {
		d := setup(t)
		rec, secret, err := d.svc.Create(ctx, "tenant-1", "laptop", nil, nil, "alice", nil)
		require.NoError(t, err)
		require.NotEmpty(t, secret)
		require.Equal(t, "laptop", rec.Name)
		require.NotNil(t, rec.Principal)
		require.Equal(t, "alice", *rec.Principal)
		require.Empty(t, rec.Permissions)
		require.Empty(t, rec.Buckets)

		issued, err := d.delegations.ListByAudience(ctx, rec.ID)
		require.NoError(t, err)
		require.Empty(t, issued.Results, "a principal-bound key holds no delegation")
		// The key pair is stored where every access key's is.
		_, err = d.secrets.Read(ctx, vault.AccessKeyPath(d.tenantID, rec.ID))
		require.NoError(t, err)
	})

	t.Run("persists an expiry", func(t *testing.T) {
		d := setup(t)
		exp := time.Now().Add(time.Hour).UTC().Truncate(time.Second)
		rec, _, err := d.svc.Create(ctx, "tenant-1", "laptop", nil, nil, "alice", &exp)
		require.NoError(t, err)
		require.NotNil(t, rec.ExpiresAt)
		require.True(t, exp.Equal(*rec.ExpiresAt))
	})

	t.Run("rejects permissions on a principal-bound key", func(t *testing.T) {
		d := setup(t)
		_, _, err := d.svc.Create(ctx, "tenant-1", "laptop", []string{"s3:GetObject"}, nil, "alice", nil)
		require.ErrorIs(t, err, accesskeysvc.ErrPrincipalScoped)
	})

	t.Run("rejects buckets on a principal-bound key", func(t *testing.T) {
		d := setup(t)
		_, _, err := d.svc.Create(ctx, "tenant-1", "laptop", nil, []string{"bucket-a"}, "alice", nil)
		require.ErrorIs(t, err, accesskeysvc.ErrPrincipalScoped)
	})

	t.Run("rejects an unknown principal", func(t *testing.T) {
		d := setup(t)
		_, _, err := d.svc.Create(ctx, "tenant-1", "laptop", nil, nil, "ghost", nil)
		require.ErrorIs(t, err, accesskeysvc.ErrUnknownPrincipal)
	})

	t.Run("rejects an empty name", func(t *testing.T) {
		d := setup(t)
		_, _, err := d.svc.Create(ctx, "tenant-1", "", nil, nil, "alice", nil)
		require.ErrorIs(t, err, accesskeysvc.ErrInvalidName)
	})

	t.Run("the name is unique within the principal and independent of service keys", func(t *testing.T) {
		d := setup(t)
		_, _, err := d.svc.Create(ctx, "tenant-1", "laptop", nil, nil, "alice", nil)
		require.NoError(t, err)
		_, _, err = d.svc.Create(ctx, "tenant-1", "laptop", nil, nil, "alice", nil)
		require.ErrorIs(t, err, accesskeysvc.ErrNameConflict)
		// A service key of the tenant may hold the same name.
		_, _, err = d.svc.Create(ctx, "tenant-1", "laptop", []string{"s3:GetObject"}, nil, "", nil)
		require.NoError(t, err)
	})

	t.Run("a failed read-back leaves no row and no vault entry", func(t *testing.T) {
		var readBack *failReadBack
		d := setup(t, func(s accesskeystore.Store) accesskeystore.Store {
			readBack = &failReadBack{Store: s}
			return readBack
		})
		_, _, err := d.svc.Create(ctx, "tenant-1", "laptop", nil, nil, "alice", nil)
		require.Error(t, err)
		require.True(t, readBack.failed, "the read-back is what failed")

		recs, err := d.accessKeys.ListByTenant(ctx, d.tenantID)
		require.NoError(t, err)
		require.Empty(t, recs)
		_, err = d.secrets.Read(ctx, vault.AccessKeyPath(d.tenantID, readBack.id))
		require.ErrorIs(t, err, vault.ErrNotFound)
	})

	t.Run("delete removes the key and invalidates its principal", func(t *testing.T) {
		d := setup(t)
		rec, _, err := d.svc.Create(ctx, "tenant-1", "laptop", nil, nil, "alice", nil)
		require.NoError(t, err)

		require.NoError(t, d.svc.Delete(ctx, "tenant-1", rec.ID.Identifier()))
		require.Empty(t, d.swarf.revocations, "there is no delegation to revoke")
		// Nothing a revocation could name, so the gateway is told to drop what it
		// cached for the principal instead.
		require.Equal(t, []string{"alice"}, d.invalidations.principals)
		_, _, err = d.svc.Get(ctx, "tenant-1", rec.ID.Identifier())
		require.ErrorIs(t, err, accesskeysvc.ErrAccessKeyNotFound)
		_, err = d.secrets.Read(ctx, vault.AccessKeyPath(d.tenantID, rec.ID))
		require.ErrorIs(t, err, vault.ErrNotFound)
	})

	t.Run("delete leaves the key usable when the invalidation cannot be published", func(t *testing.T) {
		d := setup(t)
		rec, _, err := d.svc.Create(ctx, "tenant-1", "laptop", nil, nil, "alice", nil)
		require.NoError(t, err)
		d.invalidations.err = errors.New("swarf unreachable")

		require.ErrorContains(t, d.svc.Delete(ctx, "tenant-1", rec.ID.Identifier()), "swarf unreachable")

		got, _, err := d.svc.Get(ctx, "tenant-1", rec.ID.Identifier())
		require.NoError(t, err, "the key row must survive")
		require.Equal(t, rec.ID, got.ID)
		_, err = d.secrets.Read(ctx, vault.AccessKeyPath(d.tenantID, rec.ID))
		require.NoError(t, err, "the vault entry must survive so the key still signs")
	})

	t.Run("delete reports a lock the store gave up on as a retryable conflict", func(t *testing.T) {
		d := setup(t)
		rec, _, err := d.svc.Create(ctx, "tenant-1", "laptop", nil, nil, "alice", nil)
		require.NoError(t, err)
		locked := &lockedAccessKeys{Store: d.accessKeys, err: store.ErrLockTimeout}
		svc := accesskeysvc.New(zap.NewNop(), d.tenants, locked, d.principals, d.buckets, d.delegations, d.secrets, d.swarf, d.invalidations)

		require.ErrorIs(t, svc.Delete(ctx, "tenant-1", rec.ID.Identifier()), accesskeysvc.ErrConcurrentChange)

		got, _, err := d.svc.Get(ctx, "tenant-1", rec.ID.Identifier())
		require.NoError(t, err, "the key row must survive")
		require.Equal(t, rec.ID, got.ID)
		_, err = d.secrets.Read(ctx, vault.AccessKeyPath(d.tenantID, rec.ID))
		require.NoError(t, err, "the vault entry must survive so the key still signs")
		require.Empty(t, d.invalidations.principals)
	})

	t.Run("list and get return both kinds", func(t *testing.T) {
		d := setup(t)
		svcKey, _, err := d.svc.Create(ctx, "tenant-1", "ci", []string{"s3:GetObject"}, []string{"bucket-a"}, "", nil)
		require.NoError(t, err)
		bound, _, err := d.svc.Create(ctx, "tenant-1", "laptop", nil, nil, "alice", nil)
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
		_, _, err := d.svc.Create(ctx, "tenant-1", "k1", []string{"s3:GetObject"}, []string{"bucket-a"}, "", nil)
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
		created, _, err := d.svc.Create(ctx, "tenant-1", "k1", []string{"s3:GetObject"}, nil, "", nil)
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
		created, _, err := d.svc.Create(ctx, "tenant-1", "k1", []string{"s3:GetObject"}, nil, "", nil)
		require.NoError(t, err)
		require.NoError(t, d.svc.Delete(ctx, "tenant-1", created.ID.Identifier()))
		_, _, err = d.svc.Get(ctx, "tenant-1", created.ID.Identifier())
		require.ErrorIs(t, err, accesskeysvc.ErrAccessKeyNotFound)
	})

	t.Run("delete rejects an unknown access key", func(t *testing.T) {
		d := setup(t)
		err := d.svc.Delete(ctx, "tenant-1", testutil.RandomDID(t).Identifier())
		require.ErrorIs(t, err, accesskeysvc.ErrAccessKeyNotFound)
	})
}

func TestDeleteRevokes(t *testing.T) {
	ctx := t.Context()

	t.Run("revokes every bucket-scoped delegation, with no witness path", func(t *testing.T) {
		d := setup(t)
		// s3:PutObject maps to several commands, so the key gets several delegations.
		created, _, err := d.svc.Create(ctx, "tenant-1", "k1", []string{"s3:PutObject"}, []string{"bucket-a"}, "", nil)
		require.NoError(t, err)
		issued, err := d.delegations.ListByAudience(ctx, created.ID)
		require.NoError(t, err)
		require.Greater(t, len(issued.Results), 1)

		require.NoError(t, d.svc.Delete(ctx, "tenant-1", created.ID.Identifier()))

		require.Len(t, d.swarf.revocations, len(issued.Results))
		revoked := map[cid.Cid]bool{}
		for _, r := range d.swarf.revocations {
			// The tenant issued the delegations, so the tenant revokes them directly:
			// no witness path is needed to prove its authority over them.
			require.Equal(t, d.tenantID, r.revoker)
			require.Zero(t, r.options)
			revoked[r.revoked] = true
		}
		for _, dlg := range issued.Results {
			require.True(t, revoked[dlg.Link()], "delegation %s was not revoked", dlg.Link())
		}
		// The bucket→tenant root is the tenant's own, not the access key's.
		require.False(t, revoked[d.bucketRoot.Link()], "the bucket root must not be revoked")
	})

	t.Run("revokes a powerline delegation", func(t *testing.T) {
		d := setup(t)
		created, _, err := d.svc.Create(ctx, "tenant-1", "k1", []string{"s3:GetObject"}, nil, "", nil)
		require.NoError(t, err)
		issued, err := d.delegations.ListByAudience(ctx, created.ID)
		require.NoError(t, err)
		require.Len(t, issued.Results, 1)
		require.False(t, issued.Results[0].Subject().Defined(), "expected a powerline delegation")

		require.NoError(t, d.svc.Delete(ctx, "tenant-1", created.ID.Identifier()))

		require.Len(t, d.swarf.revocations, 1)
		r := d.swarf.revocations[0]
		require.Equal(t, d.tenantID, r.revoker)
		require.Equal(t, issued.Results[0].Link(), r.revoked)
		require.Zero(t, r.options)
	})

	t.Run("revokes a powerline delegation when the tenant owns no bucket", func(t *testing.T) {
		d := setup(t)
		created, _, err := d.svc.Create(ctx, "tenant-1", "k1", []string{"s3:GetObject"}, nil, "", nil)
		require.NoError(t, err)
		// A subject-less delegation used to need one of the tenant's bucket roots to
		// witness it, so dropping the only bucket left it unrevoked. It no longer does.
		require.NoError(t, d.buckets.Delete(ctx, d.bucketID))

		require.NoError(t, d.svc.Delete(ctx, "tenant-1", created.ID.Identifier()))
		require.Len(t, d.swarf.revocations, 1)
		_, _, err = d.svc.Get(ctx, "tenant-1", created.ID.Identifier())
		require.ErrorIs(t, err, accesskeysvc.ErrAccessKeyNotFound)
	})

	t.Run("skips an already-expired delegation", func(t *testing.T) {
		d := setup(t)
		expired := time.Now().Add(-time.Hour)
		created, _, err := d.svc.Create(ctx, "tenant-1", "k1", []string{"s3:GetObject"}, nil, "", &expired)
		require.NoError(t, err)

		// The revocation service rejects expired delegations, and they are unusable
		// anyway — so the key is still deleted, just with nothing published.
		require.NoError(t, d.svc.Delete(ctx, "tenant-1", created.ID.Identifier()))
		require.Empty(t, d.swarf.revocations)
		_, _, err = d.svc.Get(ctx, "tenant-1", created.ID.Identifier())
		require.ErrorIs(t, err, accesskeysvc.ErrAccessKeyNotFound)
	})

	t.Run("a revocation failure leaves the key intact", func(t *testing.T) {
		d := setup(t)
		created, _, err := d.svc.Create(ctx, "tenant-1", "k1", []string{"s3:GetObject"}, []string{"bucket-a"}, "", nil)
		require.NoError(t, err)
		d.swarf.err = errors.New("swarf is down")

		err = d.svc.Delete(ctx, "tenant-1", created.ID.Identifier())
		require.ErrorContains(t, err, "publishing revocation")

		// Nothing was removed, so the call can simply be retried.
		_, _, err = d.svc.Get(ctx, "tenant-1", created.ID.Identifier())
		require.NoError(t, err)
		remaining, err := d.delegations.ListByAudience(ctx, created.ID)
		require.NoError(t, err)
		require.NotEmpty(t, remaining.Results)
		_, err = d.secrets.Read(ctx, vault.AccessKeyPath(d.tenantID, created.ID))
		require.NoError(t, err)
		require.Empty(t, d.swarf.revocations)
		require.Empty(t, d.invalidations.principals)
	})
}
