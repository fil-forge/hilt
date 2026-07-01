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
	// Identifier for the tenant.
	ID did.DID
	// Provider this tenant belongs to.
	Provider did.DID
	// Human readable name of the tenant.
	Name string
	// Current status of the tenant.
	Status Status
	// When the tenant record was created.
	CreatedAt time.Time
	// When the tenant record was last updated.
	UpdatedAt time.Time
}

type Store interface {
	// Add creates a new tenant record. It returns [store.ErrRecordExists] if a
	// record with the same ID already exists.
	Add(ctx context.Context, id did.DID, provider did.DID, name string, status Status) error
	// Get retrieves the tenant record for a given ID. It returns
	// [store.ErrRecordNotFound] if no record exists for the specified ID.
	Get(ctx context.Context, id did.DID) (Record, error)
	// SetStatus updates the status of a tenant record. It returns
	// [store.ErrRecordNotFound] if no record exists for the specified ID.
	SetStatus(ctx context.Context, id did.DID, status Status) error
}
