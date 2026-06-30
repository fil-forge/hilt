// Package wrapkey defines the per-tenant X25519 wrap-key registry: the metadata
// for each version of a tenant's FEE recipient wrap key.
//
// The registry never holds private key material — the private half of every
// wrap keypair is sealed in the vault (see [Record.VaultKey]) and only its
// metadata (kid, version, status, epoch, public key) lives here. Rotated keys
// are archived rather than deleted (archive-don't-destroy) so historic FEE
// envelopes addressed to an older kid remain unwrappable from Hilt's custody.
package wrapkey

import (
	"context"
	"fmt"
	"strconv"
	"time"

	"github.com/fil-forge/ucantone/did"
)

// Status is the lifecycle state of a wrap-key version.
type Status string

const (
	// Active is the current wrap key: the one published in the tenant's DID
	// document and used for new FEE envelopes. There is at most one per tenant.
	Active Status = "active"
	// Archived is a superseded wrap key. Its private half is retained
	// indefinitely so historic envelopes stay unwrappable, but it is no longer
	// published or used for new envelopes.
	Archived Status = "archived"
)

// Record is one version of a tenant's wrap key.
type Record struct {
	// Tenant is the tenant DID (did:plc) this wrap key belongs to.
	Tenant did.DID
	// Version is the 1-based version number, incremented on each rotation.
	Version int
	// KID is the full DID URL identifying this key in FEE envelopes, e.g.
	// did:plc:abc123#wrap-1. It is what an envelope holder reads to resolve and
	// locate the public key.
	KID string
	// PublicKey is the multibase-encoded X25519 public key (the same encoding
	// used as a did:key identifier).
	PublicKey string
	// Status is the lifecycle state (active or archived).
	Status Status
	// Epoch is the at-rest protection epoch the sealed private half is under.
	// It exists as groundwork for Tier-0 rotation (re-sealing private material
	// under a new master key); it is 0 until that flow exists.
	Epoch int
	// VaultKey is the opaque vault path where the private half is sealed.
	VaultKey string
	// CreatedAt is when this version was created.
	CreatedAt time.Time
	// ArchivedAt is when this version was archived; zero while active.
	ArchivedAt time.Time
}

// Store persists wrap-key registry records.
type Store interface {
	// Add inserts a new wrap-key record. It returns [store.ErrRecordExists] if a
	// record already exists for the same (tenant, version), or if adding a second
	// active key for a tenant.
	Add(ctx context.Context, rec Record) error
	// GetActive returns the tenant's current active wrap key. It returns
	// [store.ErrRecordNotFound] if the tenant has no active key.
	GetActive(ctx context.Context, tenant did.DID) (Record, error)
	// Get returns a specific version of a tenant's wrap key. It returns
	// [store.ErrRecordNotFound] if no such version exists.
	Get(ctx context.Context, tenant did.DID, version int) (Record, error)
	// List returns all wrap-key records for a tenant, newest version first.
	List(ctx context.Context, tenant did.DID) ([]Record, error)
	// Archive marks a version archived, recording the archival time. It returns
	// [store.ErrRecordNotFound] if no such version exists.
	Archive(ctx context.Context, tenant did.DID, version int) error
}

// Fragment returns the DID document fragment for a wrap-key version, e.g.
// "wrap-1". It is the verification-method key used in the tenant's did:plc
// operation and the fragment of the key's [KID].
func Fragment(version int) string {
	return "wrap-" + strconv.Itoa(version)
}

// KID returns the full DID URL kid for a tenant's wrap-key version, e.g.
// did:plc:abc123#wrap-1.
func KID(tenant did.DID, version int) string {
	return tenant.String() + "#" + Fragment(version)
}

// VaultKey returns the vault path under which a tenant wrap key's private half
// is sealed, e.g. /tenant/did:plc:abc123/wrap/1.
func VaultKey(tenant did.DID, version int) string {
	return fmt.Sprintf("/tenant/%s/wrap/%d", tenant.String(), version)
}
