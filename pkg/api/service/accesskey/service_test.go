package accesskey_test

import (
	"testing"

	"github.com/fil-forge/hilt/internal/testutil"
	accesskeysvc "github.com/fil-forge/hilt/pkg/api/service/accesskey"
	accesskeymemory "github.com/fil-forge/hilt/pkg/store/accesskey/memory"
	bucketmemory "github.com/fil-forge/hilt/pkg/store/bucket/memory"
	delegationmemory "github.com/fil-forge/hilt/pkg/store/delegation/memory"
	"github.com/fil-forge/hilt/pkg/store/tenant"
	tenantmemory "github.com/fil-forge/hilt/pkg/store/tenant/memory"
	"github.com/fil-forge/hilt/pkg/vault"
	vaultmemory "github.com/fil-forge/hilt/pkg/vault/memory"
	"github.com/fil-forge/ucantone/did"
	"github.com/fil-forge/ucantone/multikey/secp256k1"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

type deps struct {
	svc      *accesskeysvc.Service
	tenantID did.DID
	bucketID did.DID
}

// setup wires the service over memory stores with one tenant ("tenant-1") whose
// secp256k1 key is in the vault, owning one bucket ("bucket-a").
func setup(t *testing.T) deps {
	t.Helper()
	ctx := t.Context()
	tenants, accessKeys := tenantmemory.New(), accesskeymemory.New()
	buckets, delegations, secrets := bucketmemory.New(), delegationmemory.New(), vaultmemory.New()

	signer, err := secp256k1.Generate()
	require.NoError(t, err)
	tenantID := signer.KeyDID()
	require.NoError(t, tenants.Add(ctx, tenantID, "tenant-1", testutil.RandomDID(t), tenant.Active))
	require.NoError(t, secrets.Write(ctx, vault.TenantKeyPath(tenantID), signer.Bytes()))
	bucketID := testutil.RandomDID(t)
	require.NoError(t, buckets.Add(ctx, bucketID, tenantID, "bucket-a"))

	return deps{
		svc:      accesskeysvc.New(zap.NewNop(), tenants, accessKeys, buckets, delegations, secrets),
		tenantID: tenantID,
		bucketID: bucketID,
	}
}

func TestCreate(t *testing.T) {
	ctx := t.Context()

	t.Run("creates a bucket-scoped key", func(t *testing.T) {
		d := setup(t)
		rec, secret, err := d.svc.Create(ctx, "tenant-1", "k1", []string{"s3:GetObject"}, []string{"bucket-a"}, nil)
		require.NoError(t, err)
		require.NotEmpty(t, secret)
		require.Equal(t, "k1", rec.Name)
		require.Equal(t, []did.DID{d.bucketID}, rec.Buckets)
	})

	t.Run("rejects an empty name", func(t *testing.T) {
		d := setup(t)
		_, _, err := d.svc.Create(ctx, "tenant-1", "", []string{"s3:GetObject"}, nil, nil)
		require.ErrorIs(t, err, accesskeysvc.ErrInvalidName)
	})

	t.Run("rejects no permissions", func(t *testing.T) {
		d := setup(t)
		_, _, err := d.svc.Create(ctx, "tenant-1", "k1", nil, nil, nil)
		require.ErrorIs(t, err, accesskeysvc.ErrNoPermissions)
	})

	t.Run("rejects an unknown permission", func(t *testing.T) {
		d := setup(t)
		_, _, err := d.svc.Create(ctx, "tenant-1", "k1", []string{"s3:Bogus"}, nil, nil)
		require.ErrorIs(t, err, accesskeysvc.ErrInvalidPermission)
	})

	t.Run("rejects an unknown bucket", func(t *testing.T) {
		d := setup(t)
		_, _, err := d.svc.Create(ctx, "tenant-1", "k1", []string{"s3:GetObject"}, []string{"nope"}, nil)
		require.ErrorIs(t, err, accesskeysvc.ErrUnknownBucket)
	})

	t.Run("rejects an unknown tenant", func(t *testing.T) {
		d := setup(t)
		_, _, err := d.svc.Create(ctx, "missing", "k1", []string{"s3:GetObject"}, nil, nil)
		require.ErrorIs(t, err, accesskeysvc.ErrTenantNotFound)
	})

	t.Run("rejects a duplicate name", func(t *testing.T) {
		d := setup(t)
		_, _, err := d.svc.Create(ctx, "tenant-1", "dup", []string{"s3:GetObject"}, nil, nil)
		require.NoError(t, err)
		_, _, err = d.svc.Create(ctx, "tenant-1", "dup", []string{"s3:GetObject"}, nil, nil)
		require.ErrorIs(t, err, accesskeysvc.ErrNameConflict)
	})
}

func TestListGetDelete(t *testing.T) {
	ctx := t.Context()

	t.Run("list returns the tenant's keys with bucket names", func(t *testing.T) {
		d := setup(t)
		_, _, err := d.svc.Create(ctx, "tenant-1", "k1", []string{"s3:GetObject"}, []string{"bucket-a"}, nil)
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
		created, _, err := d.svc.Create(ctx, "tenant-1", "k1", []string{"s3:GetObject"}, nil, nil)
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
		created, _, err := d.svc.Create(ctx, "tenant-1", "k1", []string{"s3:GetObject"}, nil, nil)
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
