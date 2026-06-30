package wrapkey_test

import (
	"context"
	"fmt"
	"testing"

	"github.com/fil-forge/hilt/internal/testutil"
	registry "github.com/fil-forge/hilt/pkg/store/wrapkey"
	wrapkeymemory "github.com/fil-forge/hilt/pkg/store/wrapkey/memory"
	"github.com/fil-forge/hilt/pkg/vault"
	vaultmemory "github.com/fil-forge/hilt/pkg/vault/memory"
	"github.com/fil-forge/hilt/pkg/wrapkey"
	"github.com/fil-forge/ucantone/did"
	"github.com/fil-forge/ucantone/did/plc"
	"github.com/fil-forge/ucantone/multikey/secp256k1"
	"github.com/fil-forge/ucantone/multikey/x25519"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

// fakeDirectory is an in-memory stand-in for the did:plc directory: it stores
// the latest signed operation per DID.
type fakeDirectory struct {
	ops map[string]*plc.SignedOperation
}

func newFakeDirectory() *fakeDirectory {
	return &fakeDirectory{ops: map[string]*plc.SignedOperation{}}
}

func (d *fakeDirectory) Last(_ context.Context, id did.DID) (*plc.SignedOperation, error) {
	op, ok := d.ops[id.String()]
	if !ok {
		return nil, fmt.Errorf("no operation for %s", id)
	}
	return op, nil
}

func (d *fakeDirectory) Update(_ context.Context, id did.DID, op *plc.SignedOperation) error {
	d.ops[id.String()] = op
	return nil
}

// provisionTenant mimics the provisioning handler: it mints a rotation key and a
// v1 wrap key, publishes a genesis op carrying both, seals the wrap private, and
// records the active v1 registry row. It returns the tenant DID and its rotation
// signer.
func provisionTenant(t *testing.T, ctx context.Context, dir wrapkey.Directory, keys registry.Store, v vault.Vault) (did.DID, secp256k1.Signer) {
	t.Helper()
	signer, err := secp256k1.Generate()
	require.NoError(t, err)
	key := signer.KeyDID()

	v1, err := x25519.Generate()
	require.NoError(t, err)

	tenant, genesis, err := plc.New(signer,
		plc.WithRotationKeys(key),
		plc.WithVerificationMethods(map[string]did.DID{"hilt": key, "wrap-1": v1.KeyDID()}),
	)
	require.NoError(t, err)
	require.NoError(t, dir.Update(ctx, tenant, genesis))

	require.NoError(t, v.Write(ctx, registry.VaultKey(tenant, 1), v1.Bytes()))
	require.NoError(t, keys.Add(ctx, registry.Record{
		Tenant:    tenant,
		Version:   1,
		KID:       registry.KID(tenant, 1),
		PublicKey: v1.Public().String(),
		Status:    registry.Active,
		VaultKey:  registry.VaultKey(tenant, 1),
	}))
	return tenant, signer
}

func TestRotate(t *testing.T) {
	ctx := t.Context()

	t.Run("rotates the wrap key and republishes the DID document", func(t *testing.T) {
		dir := newFakeDirectory()
		keys := wrapkeymemory.New()
		v := vaultmemory.New()
		tenant, signer := provisionTenant(t, ctx, dir, keys, v)

		m := wrapkey.NewManager(keys, v, dir, zap.NewNop())
		rec, err := m.Rotate(ctx, tenant, signer)
		require.NoError(t, err)

		// The new active version is v2.
		require.Equal(t, 2, rec.Version)
		require.Equal(t, registry.Active, rec.Status)
		require.Equal(t, registry.KID(tenant, 2), rec.KID)

		active, err := keys.GetActive(ctx, tenant)
		require.NoError(t, err)
		require.Equal(t, 2, active.Version)

		// v1 is archived but retained (archive-don't-destroy).
		v1rec, err := keys.Get(ctx, tenant, 1)
		require.NoError(t, err)
		require.Equal(t, registry.Archived, v1rec.Status)
		require.False(t, v1rec.ArchivedAt.IsZero())

		// The new private half is sealed and decodes as X25519, matching the
		// recorded public key.
		sealed, err := v.Read(ctx, registry.VaultKey(tenant, 2))
		require.NoError(t, err)
		kp, err := x25519.Decode(sealed)
		require.NoError(t, err)
		require.Equal(t, "did:key:"+rec.PublicKey, kp.KeyDID().String())

		// The archived key's private half is still in the vault.
		oldSealed, err := v.Read(ctx, registry.VaultKey(tenant, 1))
		require.NoError(t, err)
		require.NotEmpty(t, oldSealed)

		// The republished operation drops wrap-1, adds wrap-2 (== the new public
		// key), retains the "hilt" signing key, and links to the previous op.
		op, err := dir.Last(ctx, tenant)
		require.NoError(t, err)
		require.Contains(t, op.VerificationMethods, "hilt")
		require.Contains(t, op.VerificationMethods, "wrap-2")
		require.NotContains(t, op.VerificationMethods, "wrap-1")
		require.Equal(t, "did:key:"+rec.PublicKey, op.VerificationMethods["wrap-2"].String())
		require.NotNil(t, op.Previous)
	})

	t.Run("rotates repeatedly, incrementing the version each time", func(t *testing.T) {
		dir := newFakeDirectory()
		keys := wrapkeymemory.New()
		v := vaultmemory.New()
		tenant, signer := provisionTenant(t, ctx, dir, keys, v)

		m := wrapkey.NewManager(keys, v, dir, zap.NewNop())
		_, err := m.Rotate(ctx, tenant, signer)
		require.NoError(t, err)
		rec3, err := m.Rotate(ctx, tenant, signer)
		require.NoError(t, err)
		require.Equal(t, 3, rec3.Version)

		all, err := keys.List(ctx, tenant)
		require.NoError(t, err)
		require.Len(t, all, 3)

		op, err := dir.Last(ctx, tenant)
		require.NoError(t, err)
		require.Contains(t, op.VerificationMethods, "wrap-3")
		require.NotContains(t, op.VerificationMethods, "wrap-2")
		require.NotContains(t, op.VerificationMethods, "wrap-1")
	})

	t.Run("errors when the tenant has no active wrap key", func(t *testing.T) {
		dir := newFakeDirectory()
		keys := wrapkeymemory.New()
		v := vaultmemory.New()

		m := wrapkey.NewManager(keys, v, dir, zap.NewNop())
		_, err := m.Rotate(ctx, testutil.RandomDID(t), nil)
		require.Error(t, err)
	})
}
