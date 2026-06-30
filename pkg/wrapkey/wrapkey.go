// Package wrapkey implements the wrap-key lifecycle operations that span the
// registry, the vault, and the did:plc directory — currently Tier-1 rotation.
//
// The registry schema and the provisioning-time creation of a tenant's first
// wrap key live in pkg/store/wrapkey and the provisioning handler respectively;
// this package holds the multi-step flows that also touch the PLC directory.
package wrapkey

import (
	"context"
	"fmt"

	registry "github.com/fil-forge/hilt/pkg/store/wrapkey"
	"github.com/fil-forge/hilt/pkg/vault"
	"github.com/fil-forge/ucantone/did"
	"github.com/fil-forge/ucantone/did/plc"
	"github.com/fil-forge/ucantone/multikey/x25519"
	"go.uber.org/zap"
)

// Directory is the subset of the did:plc directory client the wrap-key flows
// need: fetch the tenant's latest signed operation and publish a new one.
// *plc.DirectoryClient satisfies it.
type Directory interface {
	Last(ctx context.Context, d did.DID) (*plc.SignedOperation, error)
	Update(ctx context.Context, d did.DID, op *plc.SignedOperation) error
}

// Manager performs wrap-key lifecycle operations that span the registry, the
// vault, and the PLC directory.
type Manager struct {
	keys   registry.Store
	vault  vault.Vault
	dir    Directory
	logger *zap.Logger
}

// NewManager constructs a Manager. A nil logger is replaced with a no-op logger.
func NewManager(keys registry.Store, vlt vault.Vault, dir Directory, logger *zap.Logger) *Manager {
	if logger == nil {
		logger = zap.NewNop()
	}
	return &Manager{keys: keys, vault: vlt, dir: dir, logger: logger}
}

// Rotate performs a Tier-1 wrap-key rotation for a tenant: it mints a new X25519
// wrap keypair, seals the private half in the vault, and publishes a new PLC
// operation that removes the previous wrap fragment from the tenant's DID
// document and adds the new one (re-signed with the tenant's rotation key). The
// superseded registry record is archived — its private half retained
// indefinitely so historic envelopes stay unwrappable — and the new version is
// recorded active.
//
// rotationKey must be the tenant's did:plc rotation key (the same secp256k1
// signer minted at provisioning): PLC only accepts an operation signed by a key
// in the previous operation's rotation set.
func (m *Manager) Rotate(ctx context.Context, tenant did.DID, rotationKey plc.Signer) (registry.Record, error) {
	current, err := m.keys.GetActive(ctx, tenant)
	if err != nil {
		return registry.Record{}, fmt.Errorf("loading active wrap key: %w", err)
	}
	newVersion := current.Version + 1

	// Mint and seal the new keypair before touching the directory or registry,
	// so the private half is never lost.
	newKeyPair, err := x25519.Generate()
	if err != nil {
		return registry.Record{}, fmt.Errorf("generating wrap key: %w", err)
	}
	newVaultKey := registry.VaultKey(tenant, newVersion)
	if err := m.vault.Write(ctx, newVaultKey, newKeyPair.Bytes()); err != nil {
		return registry.Record{}, fmt.Errorf("sealing wrap key: %w", err)
	}

	// Build the next DID operation from the tenant's current one: drop the old
	// wrap fragment from the public document and add the new one. Only the map
	// key (fragment) matters to WithoutVerificationMethods.
	last, err := m.dir.Last(ctx, tenant)
	if err != nil {
		_ = m.vault.Delete(ctx, newVaultKey)
		return registry.Record{}, fmt.Errorf("fetching current PLC operation: %w", err)
	}
	op, err := plc.NewOperationFromPrevious(last,
		plc.WithoutVerificationMethods(map[string]did.DID{registry.Fragment(current.Version): did.Undef}),
		plc.WithVerificationMethods(map[string]did.DID{registry.Fragment(newVersion): newKeyPair.KeyDID()}),
	)
	if err != nil {
		_ = m.vault.Delete(ctx, newVaultKey)
		return registry.Record{}, fmt.Errorf("building rotation operation: %w", err)
	}
	signed, err := plc.SignOperation(rotationKey, op)
	if err != nil {
		_ = m.vault.Delete(ctx, newVaultKey)
		return registry.Record{}, fmt.Errorf("signing rotation operation: %w", err)
	}
	if err := m.dir.Update(ctx, tenant, signed); err != nil {
		_ = m.vault.Delete(ctx, newVaultKey)
		return registry.Record{}, fmt.Errorf("publishing rotation operation: %w", err)
	}

	// Archive the superseded key (retained, not destroyed) before recording the
	// new active version — the registry permits only one active key per tenant.
	if err := m.keys.Archive(ctx, tenant, current.Version); err != nil {
		return registry.Record{}, fmt.Errorf("archiving previous wrap key: %w", err)
	}
	newRec := registry.Record{
		Tenant:    tenant,
		Version:   newVersion,
		KID:       registry.KID(tenant, newVersion),
		PublicKey: newKeyPair.Public().String(),
		Status:    registry.Active,
		VaultKey:  newVaultKey,
	}
	if err := m.keys.Add(ctx, newRec); err != nil {
		return registry.Record{}, fmt.Errorf("recording new wrap key: %w", err)
	}

	m.logger.Info("rotated tenant wrap key",
		zap.Stringer("tenant", tenant),
		zap.Int("from_version", current.Version),
		zap.Int("to_version", newVersion),
	)
	return newRec, nil
}
