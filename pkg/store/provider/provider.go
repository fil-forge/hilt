package provider

import (
	"context"
	"time"

	"github.com/fil-forge/ucantone/did"
)

type Record struct {
	// Identifier for the regional provider.
	ID did.DID
	// Region the provider operates in.
	Region string
	// When the provider record was created.
	CreatedAt time.Time
	// When the provider record was last updated.
	UpdatedAt time.Time
}

type Store interface {
	// Add creates a new provider record. It returns [store.ErrInvalidArgument]
	// if the ID is undef or the region is empty, and [store.ErrRecordExists] if
	// a record with the same ID already exists.
	Add(ctx context.Context, id did.DID, region string) error
	// GetByRegion retrieves the provider record for a given region. It returns
	// [store.ErrRecordNotFound] if no record exists for the specified region.
	GetByRegion(ctx context.Context, region string) (Record, error)
}
