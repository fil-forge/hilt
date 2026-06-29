package bucket

import (
	"context"
	"time"

	"github.com/fil-forge/hilt/pkg/store"
	"github.com/fil-forge/ucantone/did"
)

type Record struct {
	// Identifier for the bucket.
	ID did.DID
	// Tenant the bucket belongs to.
	Tenant did.DID
	// Human readable name of the bucket.
	Name string
	// When the bucket record was created.
	CreatedAt time.Time
}

type Store interface {
	// Add creates a new bucket record. It returns [store.ErrRecordExists] if a
	// record with the same ID already exists.
	Add(ctx context.Context, id did.DID, tenant did.DID, name string) error
	// GetByName retrieves the bucket record for a given name. It returns
	// [store.ErrRecordNotFound] if no bucket exists with the specified name.
	GetByName(ctx context.Context, name string) (Record, error)
	// ListByTenant retrieves a paginated list of bucket records for a given
	// tenant.
	ListByTenant(ctx context.Context, tenant did.DID, opts ...store.PaginationOption) (store.Page[Record], error)
	// Delete removes the bucket record for a given ID. It is idempotent:
	// deleting an absent record returns nil.
	Delete(ctx context.Context, id did.DID) error
}
