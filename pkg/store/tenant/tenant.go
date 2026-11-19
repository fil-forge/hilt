package tenant

import (
	"context"
	"time"

	"github.com/fil-forge/ucantone/did"
)

// LockNamespace is the first key of the per-tenant advisory lock; the
// second is the tenant DID. A policy write holds it shared for its
// transaction; a principal add holds it exclusive for its upsert. Row locks
// cannot order the two, because the add's row does not exist until it
// commits: without the lock a principal added after the write's callback
// listed the tenant's principals, and before the write committed, could
// create an access key that finds no policy to grant from and is never
// rotated. Under it the add commits either before the listing, so the write
// rotates the new principal's keys, or after the commit, so the key's
// creation reads the committed policy. Status changes and tenant deletion also
// hold it exclusive; key creation and authorize-response construction hold it
// shared through their authority work, fencing stale status-derived grants.
const LockNamespace int32 = 0x54454e54 // "TENT"

type Status string

const (
	Active      Status = "active"
	WriteLocked Status = "write-locked"
	Disabled    Status = "disabled"
)

// Valid reports whether s is a recognized tenant status.
func (s Status) Valid() bool {
	switch s {
	case Active, WriteLocked, Disabled:
		return true
	}
	return false
}

type Record struct {
	// Identifier for the tenant (the tenant's did:plc, the internal crypto
	// identity).
	ID did.DID
	// ExternalID is the tenant identifier used by the Tenant API (the {tenantId}
	// path parameter supplied by the caller).
	ExternalID string
	// Current status of the tenant.
	Status Status
	// When the tenant record was created.
	CreatedAt time.Time
	// When the tenant record was last updated.
	UpdatedAt time.Time
}

type Store interface {
	// Add creates a new tenant record. It returns [store.ErrInvalidArgument] if
	// the ID is undef or the status is not valid, and [store.ErrRecordExists]
	// if a record with the same ID or external ID already exists.
	Add(ctx context.Context, id did.DID, externalID string, status Status) error
	// Get retrieves the tenant record for a given ID. It returns
	// [store.ErrRecordNotFound] if no record exists for the specified ID.
	Get(ctx context.Context, id did.DID) (Record, error)
	// GetByExternalID retrieves the tenant record for a given external ID. It
	// returns [store.ErrRecordNotFound] if no record exists for the specified
	// external ID.
	GetByExternalID(ctx context.Context, externalID string) (Record, error)
	// SetStatus updates the status of a tenant record. It returns
	// [store.ErrInvalidArgument] if the status is not valid, and
	// [store.ErrRecordNotFound] if no record exists for the specified ID.
	SetStatus(ctx context.Context, id did.DID, status Status) error
	// ChangeStatus holds the tenant fence exclusively, invokes beforeCommit
	// with the current record and transaction context, then commits the status.
	// A failed callback leaves the status unchanged. Grant writers use
	// WithReadLock so none can publish authority from a superseded status.
	ChangeStatus(ctx context.Context, id did.DID, status Status, beforeCommit func(context.Context, Record) error) error
	// WithReadLock holds the shared tenant fence while fn validates and stores
	// authority. Its callback joins the enclosing Postgres transaction.
	WithReadLock(ctx context.Context, id did.DID, fn func(context.Context, Record) error) error
	// Delete removes the tenant record for a given ID. It is idempotent:
	// deleting an absent record returns nil.
	Delete(ctx context.Context, id did.DID) error
}
