package accesskey_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/fil-forge/hilt/internal/testutil"
	accesskeysvc "github.com/fil-forge/hilt/pkg/api/service/accesskey"
	"github.com/fil-forge/hilt/pkg/bucketpolicy"
	"github.com/fil-forge/hilt/pkg/s3perm"
	"github.com/fil-forge/hilt/pkg/store"
	accesskeystore "github.com/fil-forge/hilt/pkg/store/accesskey"
	accesskeymemory "github.com/fil-forge/hilt/pkg/store/accesskey/memory"
	accesskeypostgres "github.com/fil-forge/hilt/pkg/store/accesskey/postgres"
	"github.com/fil-forge/hilt/pkg/store/bucket"
	bucketmemory "github.com/fil-forge/hilt/pkg/store/bucket/memory"
	bucketpostgres "github.com/fil-forge/hilt/pkg/store/bucket/postgres"
	bucketpolicystore "github.com/fil-forge/hilt/pkg/store/bucketpolicy"
	bucketpolicymemory "github.com/fil-forge/hilt/pkg/store/bucketpolicy/memory"
	bucketpolicypostgres "github.com/fil-forge/hilt/pkg/store/bucketpolicy/postgres"
	delegationstore "github.com/fil-forge/hilt/pkg/store/delegation"
	delegationmemory "github.com/fil-forge/hilt/pkg/store/delegation/memory"
	delegationpostgres "github.com/fil-forge/hilt/pkg/store/delegation/postgres"
	"github.com/fil-forge/hilt/pkg/store/principal"
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
	"github.com/fil-forge/ucantone/ucan/command"
	"github.com/fil-forge/ucantone/ucan/delegation"
	"github.com/ipfs/go-cid"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

// revocation records one published revocation.
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

type deps struct {
	svc         *accesskeysvc.Service
	accessKeys  accesskeystore.Store
	principals  principal.Store
	delegations delegationstore.Store
	buckets     bucket.Store
	secrets     vault.Vault
	swarf       *testutil.FakeSwarf
	tenantID    did.DID
	bucketID    did.DID
	bucketRoot  ucan.Delegation
}

// setup is setupWith over the memory stores.
func setup(t *testing.T, wrapAccessKeys ...func(accesskeystore.Store) accesskeystore.Store) deps {
	t.Helper()
	return setupWith(t, backend{
		tenants: tenantmemory.New(), accessKeys: accesskeymemory.New(), principals: principalmemory.New(),
		buckets: bucketmemory.New(), delegations: delegationmemory.New(), policies: bucketpolicymemory.New(),
		providerID: testutil.RandomDID(t),
	}, wrapAccessKeys...)
}

// setupPostgres is setup over the Postgres stores, for what only a real
// transaction shows. It skips without Docker.
func setupPostgres(t *testing.T, wrapAccessKeys ...func(accesskeystore.Store) accesskeystore.Store) deps {
	t.Helper()
	pool := testutil.PostgresOrSkip(t)
	providerID := testutil.RandomDID(t)
	require.NoError(t, providerpostgres.New(pool).Add(t.Context(), providerID, "region-1", nil))
	return setupWith(t, backend{
		tenants: tenantpostgres.New(pool), accessKeys: accesskeypostgres.New(pool), principals: principalpostgres.New(pool),
		buckets: bucketpostgres.New(pool), delegations: delegationpostgres.New(pool), policies: bucketpolicypostgres.New(pool),
		providerID: providerID,
	}, wrapAccessKeys...)
}

// backend is the stores setupWith builds the service over, and the provider
// the tenant is placed with.
type backend struct {
	tenants     tenant.Store
	accessKeys  accesskeystore.Store
	principals  principal.Store
	buckets     bucket.Store
	delegations delegationstore.Store
	policies    bucketpolicystore.Store
	providerID  did.DID
}

// setupWith wires the service over b with one tenant ("tenant-1") whose
// secp256k1 key is in the vault, owning one bucket ("bucket-a") that has issued
// the tenant top authority over itself: the root of every proof chain through
// the bucket, as [bucket.Service.Create] would have stored it. Its audience is
// the tenant, not an access key, so it must never be revoked along with one.
// The tenant has one principal, "alice". wrapAccessKeys, when given, wraps the
// access-key store the service is built over, so a test can make one of its
// methods fail.
func setupWith(t *testing.T, b backend, wrapAccessKeys ...func(accesskeystore.Store) accesskeystore.Store) deps {
	t.Helper()
	ctx := t.Context()
	tenants, accessKeys, principals := b.tenants, b.accessKeys, b.principals
	buckets, delegations, policies := b.buckets, b.delegations, b.policies
	secrets := vaultmemory.New()

	keys := accessKeys
	for _, wrap := range wrapAccessKeys {
		keys = wrap(keys)
	}

	signer, err := secp256k1.Generate()
	require.NoError(t, err)
	tenantID := signer.KeyDID()
	require.NoError(t, tenants.Add(ctx, tenantID, "tenant-1", b.providerID, tenant.Active))
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
	// alice may read bucket-a; her keys hold the matching delegations.
	_, err = policies.Put(ctx, bucketpolicystore.Input{Bucket: bucketID, Tenant: tenantID, Policy: bucketpolicy.Policy{
		Statements: []bucketpolicy.Statement{{Effect: bucketpolicy.Allow, Principal: bucketpolicy.Only("alice"), Actions: []string{"s3:GetObject"}}},
	}}, nil)
	require.NoError(t, err)

	swarf := &testutil.FakeSwarf{}
	return deps{
		svc:         accesskeysvc.New(zap.NewNop(), tenants, keys, principals, buckets, policies, delegations, secrets, swarf),
		accessKeys:  accessKeys,
		principals:  principals,
		delegations: delegations,
		buckets:     buckets,
		secrets:     secrets,
		swarf:       swarf,
		tenantID:    tenantID,
		bucketID:    bucketID,
		bucketRoot:  root,
	}
}

func TestCreate(t *testing.T) {
	ctx := t.Context()

	t.Run("creates a bucket-scoped key", func(t *testing.T) {
		d := setup(t)
		rec, secret, err := d.svc.Create(ctx, "tenant-1", "k1", []string{"s3:GetObject"}, []string{"bucket-a"}, nil, nil)
		require.NoError(t, err)
		require.NotEmpty(t, secret)
		require.Equal(t, "k1", rec.Name)
		require.Equal(t, []did.DID{d.bucketID}, rec.Buckets)

		issued, err := d.delegations.ListByAudience(ctx, rec.ID)
		require.NoError(t, err)
		require.NotEmpty(t, issued.Results, "the key's delegations are stored")
		for _, dlg := range issued.Results {
			require.Equal(t, d.bucketID, dlg.Subject())
		}
	})

	t.Run("rejects an empty name", func(t *testing.T) {
		d := setup(t)
		_, _, err := d.svc.Create(ctx, "tenant-1", "", []string{"s3:GetObject"}, nil, nil, nil)
		require.ErrorIs(t, err, accesskeysvc.ErrInvalidName)
	})

	t.Run("rejects no permissions", func(t *testing.T) {
		d := setup(t)
		_, _, err := d.svc.Create(ctx, "tenant-1", "k1", nil, nil, nil, nil)
		require.ErrorIs(t, err, accesskeysvc.ErrNoPermissions)
	})

	t.Run("rejects an unknown permission", func(t *testing.T) {
		d := setup(t)
		_, _, err := d.svc.Create(ctx, "tenant-1", "k1", []string{"s3:Bogus"}, nil, nil, nil)
		require.ErrorIs(t, err, accesskeysvc.ErrInvalidPermission)
	})

	t.Run("rejects an unknown bucket", func(t *testing.T) {
		d := setup(t)
		_, _, err := d.svc.Create(ctx, "tenant-1", "k1", []string{"s3:GetObject"}, []string{"nope"}, nil, nil)
		require.ErrorIs(t, err, accesskeysvc.ErrUnknownBucket)
	})

	t.Run("rejects an unknown tenant", func(t *testing.T) {
		d := setup(t)
		_, _, err := d.svc.Create(ctx, "missing", "k1", []string{"s3:GetObject"}, nil, nil, nil)
		require.ErrorIs(t, err, accesskeysvc.ErrTenantNotFound)
	})

	t.Run("rejects a duplicate name", func(t *testing.T) {
		d := setup(t)
		_, _, err := d.svc.Create(ctx, "tenant-1", "dup", []string{"s3:GetObject"}, nil, nil, nil)
		require.NoError(t, err)
		_, _, err = d.svc.Create(ctx, "tenant-1", "dup", []string{"s3:GetObject"}, nil, nil, nil)
		require.ErrorIs(t, err, accesskeysvc.ErrNameConflict)
	})
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
		issued, err := d.delegations.ListByAudience(ctx, rec.ID)
		require.NoError(t, err)
		var got []string
		for _, m := range issued.Results {
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
	})

	t.Run("rejects buckets on a principal-bound key", func(t *testing.T) {
		d := setup(t)
		_, _, err := d.svc.Create(ctx, "tenant-1", "laptop", nil, []string{"bucket-a"}, new("alice"), nil)
		require.ErrorIs(t, err, accesskeysvc.ErrPrincipalScoped)
	})

	t.Run("rejects an unknown principal", func(t *testing.T) {
		d := setup(t)
		_, _, err := d.svc.Create(ctx, "tenant-1", "laptop", nil, nil, new("ghost"), nil)
		require.ErrorIs(t, err, accesskeysvc.ErrUnknownPrincipal)
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

	t.Run("a failed read-back leaves no row and no vault entry", func(t *testing.T) {
		var readBack *failReadBack
		d := setup(t, func(s accesskeystore.Store) accesskeystore.Store {
			readBack = &failReadBack{Store: s}
			return readBack
		})
		_, _, err := d.svc.Create(ctx, "tenant-1", "laptop", nil, nil, new("alice"), nil)
		require.Error(t, err)
		require.True(t, readBack.failed, "the read-back is what failed")

		recs, err := d.accessKeys.ListByTenant(ctx, d.tenantID)
		require.NoError(t, err)
		require.Empty(t, recs)
		_, err = d.secrets.Read(ctx, vault.AccessKeyPath(d.tenantID, readBack.id))
		require.ErrorIs(t, err, vault.ErrNotFound)
	})

	t.Run("delete removes the key and revokes its marker", func(t *testing.T) {
		d := setup(t)
		rec, _, err := d.svc.Create(ctx, "tenant-1", "laptop", nil, nil, new("alice"), nil)
		require.NoError(t, err)
		issued, err := d.delegations.ListByAudience(ctx, rec.ID)
		require.NoError(t, err)
		require.Len(t, issued.Results, 1)

		require.NoError(t, d.svc.Delete(ctx, "tenant-1", rec.ID.Identifier()))
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
		require.Empty(t, d.swarf.Revocations())
		_, _, err = d.svc.Get(ctx, "tenant-1", created.ID.Identifier())
		require.ErrorIs(t, err, accesskeysvc.ErrAccessKeyNotFound)
	})

	t.Run("deletes a key holding no delegations without the tenant key", func(t *testing.T) {
		d := setup(t)
		require.NoError(t, d.principals.Add(ctx, d.tenantID, "bob"))
		created, _, err := d.svc.Create(ctx, "tenant-1", "laptop", nil, nil, "bob", nil)
		require.NoError(t, err)
		// With nothing to revoke, the tenant's signing key is never needed.
		require.NoError(t, d.secrets.Delete(ctx, vault.TenantKeyPath(d.tenantID)))

		require.NoError(t, d.svc.Delete(ctx, "tenant-1", created.ID.Identifier()))
		require.Empty(t, d.swarf.Revocations())
		_, _, err = d.svc.Get(ctx, "tenant-1", created.ID.Identifier())
		require.ErrorIs(t, err, accesskeysvc.ErrAccessKeyNotFound)
	})

	t.Run("a revocation failure leaves the key intact", func(t *testing.T) {
		d := setup(t)
		created, _, err := d.svc.Create(ctx, "tenant-1", "k1", []string{"s3:GetObject"}, []string{"bucket-a"}, nil, nil)
		require.NoError(t, err)
		d.swarf.Err = errors.New("swarf is down")

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
	})
}

// cancelAfterDelete cancels the request's ctx once the key row's delete has
// run, so the delegation write that follows it fails and the transaction rolls
// back.
type cancelAfterDelete struct {
	accesskeystore.Store
	cancel context.CancelFunc
}

func (c *cancelAfterDelete) Delete(ctx context.Context, id did.DID) error {
	err := c.Store.Delete(ctx, id)
	c.cancel()
	return err
}

// A deletion that fails after the key row's delete leaves the row, its
// delegations and its secret for a retry: the row's delete commits with the
// delegation write or not at all.
func TestDeletePostgresRollsBackAfterRowDelete(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	wrap := &cancelAfterDelete{cancel: cancel}
	d := setupPostgres(t, func(s accesskeystore.Store) accesskeystore.Store { wrap.Store = s; return wrap })
	rec, _, err := d.svc.Create(t.Context(), "tenant-1", "k1", nil, nil, "alice", nil)
	require.NoError(t, err)
	page, err := d.delegations.ListByAudience(t.Context(), rec.ID)
	require.NoError(t, err)
	require.NotEmpty(t, page.Results, "the key holds alice's delegations")

	require.ErrorIs(t, d.svc.Delete(ctx, "tenant-1", rec.ID.Identifier()), context.Canceled)

	_, err = d.accessKeys.Get(t.Context(), rec.ID)
	require.NoError(t, err, "the row survives the failed deletion")
	page, err = d.delegations.ListByAudience(t.Context(), rec.ID)
	require.NoError(t, err)
	require.NotEmpty(t, page.Results, "so do the delegations")
	_, err = d.secrets.Read(t.Context(), vault.AccessKeyPath(d.tenantID, rec.ID))
	require.NoError(t, err, "and the secret")

	require.NoError(t, d.svc.Delete(t.Context(), "tenant-1", rec.ID.Identifier()))
	_, err = d.accessKeys.Get(t.Context(), rec.ID)
	require.ErrorIs(t, err, store.ErrRecordNotFound)
	page, err = d.delegations.ListByAudience(t.Context(), rec.ID)
	require.NoError(t, err)
	require.Empty(t, page.Results)
	_, err = d.secrets.Read(t.Context(), vault.AccessKeyPath(d.tenantID, rec.ID))
	require.Error(t, err)
}
