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
	// Policy is the DID of the routing policy the provider's buckets use. Hilt
	// issues the policy when the provider is registered and holds its root
	// delegation; the upload service holds the policy's candidate set. Nil when
	// the provider has no policy: its buckets then use default routing.
	Policy *did.DID
	// When the provider record was created.
	CreatedAt time.Time
	// When the provider record was last updated.
	UpdatedAt time.Time
}

type Store interface {
	// Add creates a new provider record. Policy may be nil. It returns
	// [store.ErrInvalidArgument] if the ID is undef or the region is empty, and
	// [store.ErrRecordExists] if a record with the same ID or region already
	// exists.
	Add(ctx context.Context, id did.DID, region string, policy *did.DID) error
	// Get retrieves the provider record by ID. It returns
	// [store.ErrRecordNotFound] if no record exists.
	Get(ctx context.Context, id did.DID) (Record, error)
	// SetPolicy sets the routing policy of a provider. It returns
	// [store.ErrInvalidArgument] if the policy is undef and
	// [store.ErrRecordNotFound] if no record exists.
	SetPolicy(ctx context.Context, id did.DID, policy did.DID) error
	// GetByRegion retrieves the provider record for a given region. It returns
	// [store.ErrRecordNotFound] if no record exists for the specified region.
	GetByRegion(ctx context.Context, region string) (Record, error)
	// List retrieves every provider record, ordered by ID (byte-wise, so the
	// order is the same for every backend). It returns an empty slice when no
	// provider is registered.
	List(ctx context.Context) ([]Record, error)
}
