package accesskey

import (
	"context"
	"time"

	"github.com/fil-forge/ucantone/did"
)

type Record struct {
	// Identifier for the tenant.
	ID did.DID
	// Tenant this access key belongs to.
	Tenant did.DID
	// Human readable name of the access key.
	Name string
	// Buckets the access key is authorized to use. Empty slice means the access
	// key has access to all buckets.
	Buckets []did.DID
	// S3 permissions granted to the access key.
	Permissions []string
	// When the access key record was created.
	CreatedAt time.Time
	// When the access key expires. Nil means it never expires.
	ExpiresAt *time.Time
}

type Store interface {
	// Add creates a new access key record. It returns [store.ErrInvalidArgument]
	// if the ID or tenant is undef, the name is empty, or buckets contains an
	// undef DID. It returns [store.ErrRecordExists] if a record with the same
	// ID, or the same (tenant, name), already exists. Names must be unique
	// within a tenant.
	Add(ctx context.Context, id did.DID, tenant did.DID, name string, buckets []did.DID, permissions []string, expiresAt *time.Time) error
	// Get retrieves the access key record for a given ID. It returns
	// [store.ErrRecordNotFound] if no record exists for the specified ID.
	Get(ctx context.Context, id did.DID) (Record, error)
	// ListByTenant retrieves all access key records for a given tenant.
	ListByTenant(ctx context.Context, tenant did.DID) ([]Record, error)
	// Delete removes the access key record for a given ID. It is idempotent:
	// deleting an absent record returns nil.
	Delete(ctx context.Context, id did.DID) error
}
