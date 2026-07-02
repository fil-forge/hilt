package tenant

import (
	"context"
	"time"

	"github.com/fil-forge/ucantone/did"
)

type Status string

const (
	Active      Status = "active"
	WriteLocked Status = "write-locked"
	Disabled    Status = "disabled"
)

type Record struct {
	// Identifier for the tenant (the tenant's did:plc, the internal crypto
	// identity).
	ID did.DID
	// ExternalID is the tenant identifier used by the Tenant API (the {tenantId}
	// path parameter supplied by the caller).
	ExternalID string
	// Provider this tenant belongs to.
	Provider did.DID
	// Current status of the tenant.
	Status Status
	// When the tenant record was created.
	CreatedAt time.Time
	// When the tenant record was last updated.
	UpdatedAt time.Time
}

type Store interface {
	// Add creates a new tenant record. It returns [store.ErrRecordExists] if a
	// record with the same ID or external ID already exists.
	Add(ctx context.Context, id did.DID, externalID string, provider did.DID, status Status) error
	// Get retrieves the tenant record for a given ID. It returns
	// [store.ErrRecordNotFound] if no record exists for the specified ID.
	Get(ctx context.Context, id did.DID) (Record, error)
	// GetByExternalID retrieves the tenant record for a given external ID. It
	// returns [store.ErrRecordNotFound] if no record exists for the specified
	// external ID.
	GetByExternalID(ctx context.Context, externalID string) (Record, error)
	// SetStatus updates the status of a tenant record. It returns
	// [store.ErrRecordNotFound] if no record exists for the specified ID.
	SetStatus(ctx context.Context, id did.DID, status Status) error
	// Delete removes the tenant record for a given ID. It is idempotent:
	// deleting an absent record returns nil.
	Delete(ctx context.Context, id did.DID) error
}
