// Package wrapkey defines the per-tenant X25519 wrap-key registry: the metadata
// for each version of a tenant's FEE recipient wrap key.
//
// The registry never holds private key material — the private half of every
// wrap keypair is sealed in the vault (see [Record.VaultKey]) and only its
// metadata (kid, version, status, epoch) lives here. Rotated keys are archived
// rather than deleted (archive-don't-destroy) so historic FEE envelopes
// addressed to an older kid remain unwrappable from Hilt's custody.
package wrapkey

import (
	"context"
	"fmt"
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
	// KID is the fingerprint that identifies this key in FEE envelopes: the
	// multibase-encoded, multicodec-tagged X25519 public key (the same string
	// used as the key's did:key identifier). Being content-derived, it names one
	// specific key forever regardless of any later DID-document change, and it is
	// what recovery matches an envelope's recipient against. The key material is
	// recoverable by decoding it, so no separate public-key column is kept.
	KID string
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

// Input is the data needed to create a new wrap-key record.
type Input struct {
	// Tenant is the tenant DID (did:plc) this wrap key belongs to.
	Tenant did.DID
	// Version is the 1-based version number, incremented on each rotation.
	Version int
	// KID is the fingerprint that identifies this key in FEE envelopes: the
	// multibase-encoded, multicodec-tagged X25519 public key (the same string
	// used as the key's did:key identifier). Being content-derived, it names one
	// specific key forever regardless of any later DID-document change, and it is
	// what recovery matches an envelope's recipient against. The key material is
	// recoverable by decoding it, so no separate public-key column is kept.
	KID string
	// Epoch is the at-rest protection epoch the sealed private half is under.
	// It exists as groundwork for Tier-0 rotation (re-sealing private material
	// under a new master key); it is 0 until that flow exists.
	Epoch int
	// VaultKey is the opaque vault path where the private half is sealed.
	VaultKey string
}

// Store persists wrap-key registry records.
type Store interface {
	// Add inserts a new wrap-key record. It returns [store.ErrRecordExists] if a
	// record already exists for the same (tenant, version), or if adding a second
	// active key for a tenant.
	Add(ctx context.Context, input Input) error
	// Get returns the tenant's current active wrap key. It returns
	// [store.ErrRecordNotFound] if the tenant has no active key.
	Get(ctx context.Context, tenant did.DID) (Record, error)
	// GetVersion returns a specific version of a tenant's wrap key. It returns
	// [store.ErrRecordNotFound] if no such version exists.
	GetVersion(ctx context.Context, tenant did.DID, version int) (Record, error)
	// GetByKID returns the wrap key with the given kid (public-key fingerprint) —
	// the lookup a recovery path uses to resolve an envelope's recipient back to
	// its (retained) key. It returns [store.ErrRecordNotFound] if none matches.
	GetByKID(ctx context.Context, kid string) (Record, error)
	// List returns all wrap-key records for a tenant, newest version first.
	List(ctx context.Context, tenant did.DID) ([]Record, error)
	// Archive marks an active version archived, recording the archival time.
	// It returns [store.ErrRecordNotFound] if no such version exists or it is
	// already archived, so an original archival timestamp is never re-stamped.
	Archive(ctx context.Context, tenant did.DID, version int) error
	// Delete removes every wrap-key record for a tenant (all versions,
	// active and archived). It is used by tenant deletion — the "true deletion"
	// that ends the envelope-recovery path — and is idempotent: a tenant with no
	// records is a no-op.
	Delete(ctx context.Context, tenant did.DID) error
}

// VaultKey returns the vault path under which a tenant wrap key's private half
// is sealed, e.g. /tenant/did:plc:abc123/wrap/1.
func VaultKey(tenant did.DID, version int) string {
	return fmt.Sprintf("/tenant/%s/wrap/%d", tenant.String(), version)
}
