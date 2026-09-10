// Package accesskey defines the store of a tenant's S3 access keys. A key is
// one of two kinds. A service key carries its own permissions and bucket scope
// and holds the delegations issued from them. A principal-bound key names the
// console principal it belongs to, carries no permissions or buckets of its
// own, and is authorized from the tenant's bucket policies at request time.
package accesskey

import (
	"context"
	"fmt"
	"slices"
	"time"

	"github.com/fil-forge/hilt/pkg/store"
	"github.com/fil-forge/ucantone/did"
)

// Record is one stored access key.
type Record struct {
	// ID is the access key's did:key.
	ID did.DID
	// Tenant is the tenant DID the access key belongs to.
	Tenant did.DID
	// Name is the human readable name. A service key's name is unique within its
	// tenant; a principal-bound key's name is unique within its principal.
	Name string
	// Buckets the access key is authorized to use. Empty means every bucket of
	// the tenant. Always nil for a principal-bound key, which is stored as NULL.
	Buckets []did.DID
	// Permissions are the S3 permissions granted to the access key. Always nil
	// for a principal-bound key, which is stored as NULL.
	Permissions []string
	// Principal is the console principalId of the principal the key is bound
	// to. Nil for a service key.
	Principal *string
	// CreatedAt is when the record was created.
	CreatedAt time.Time
	// ExpiresAt is when the access key expires. Nil means it never expires.
	ExpiresAt *time.Time
}

// Input is the data needed to create an access key.
type Input struct {
	// ID is the access key's did:key.
	ID did.DID
	// Tenant is the tenant DID the access key belongs to.
	Tenant did.DID
	// Name is the human readable name.
	Name string
	// Buckets the access key is authorized to use. Empty means every bucket of
	// the tenant. Must be empty when Principal is set.
	Buckets []did.DID
	// Permissions are the S3 permissions granted to the access key. Must be
	// empty when Principal is set.
	Permissions []string
	// Principal is the console principalId of the principal to bind the key to.
	// Nil for a service key.
	Principal *string
	// ExpiresAt is when the access key expires. Nil means it never expires.
	ExpiresAt *time.Time
}

// Validate checks the input's own consistency (not its referential integrity),
// returning [store.ErrInvalidArgument] wrapped with the reason. Both backends
// apply it before writing.
func (in Input) Validate() error {
	switch {
	case in.ID == did.Undef:
		return fmt.Errorf("access key ID is required: %w", store.ErrInvalidArgument)
	case in.Tenant == did.Undef:
		return fmt.Errorf("access key tenant is required: %w", store.ErrInvalidArgument)
	case in.Name == "":
		return fmt.Errorf("access key name is required: %w", store.ErrInvalidArgument)
	case slices.Contains(in.Buckets, did.Undef):
		return fmt.Errorf("access key bucket DIDs must be defined: %w", store.ErrInvalidArgument)
	case in.Principal != nil && *in.Principal == "":
		return fmt.Errorf("access key principal must not be empty: %w", store.ErrInvalidArgument)
	case in.Principal != nil && (len(in.Permissions) > 0 || len(in.Buckets) > 0):
		return fmt.Errorf("a principal-bound access key holds no permissions or buckets: %w", store.ErrInvalidArgument)
	}
	return nil
}

// ListConfig configures [Store.ListByTenant].
type ListConfig struct {
	// Principal restricts results to keys bound to this principal.
	Principal *string
}

// ListOption configures a [ListConfig].
type ListOption func(*ListConfig)

// WithPrincipal restricts results to keys bound to the given principal.
func WithPrincipal(externalID string) ListOption {
	return func(c *ListConfig) { c.Principal = &externalID }
}

// NewListConfig applies opts to a zero [ListConfig].
func NewListConfig(opts ...ListOption) ListConfig {
	cfg := ListConfig{}
	for _, opt := range opts {
		opt(&cfg)
	}
	return cfg
}

// Store persists access key records.
type Store interface {
	// Add creates an access key record. It returns [store.ErrInvalidArgument] if
	// the input fails [Input.Validate] or, on Postgres, the principal does not
	// exist for the tenant. It returns [store.ErrRecordExists] if a record with
	// the same ID already exists, if a service key of the tenant already holds
	// the name, or if the principal already holds a key of the name.
	Add(ctx context.Context, in Input) error
	// Get retrieves the record for a given ID. It returns
	// [store.ErrRecordNotFound] if no record exists for the specified ID. With
	// [store.WithLock]([store.LockShare]) the read waits for a transaction
	// holding the row to commit or roll back; on Postgres the wait is bounded
	// at [store.LockTimeout] and returns [store.ErrLockTimeout] when it runs
	// out.
	Get(ctx context.Context, id did.DID, opts ...store.ReadOption) (Record, error)
	// ListByTenant retrieves the tenant's records, ordered by ID, optionally
	// restricted to one principal's keys (see [WithPrincipal]).
	ListByTenant(ctx context.Context, tenant did.DID, opts ...ListOption) ([]Record, error)
	// Delete removes the access key record for a given ID. It is idempotent:
	// deleting an absent record returns nil. On Postgres the wait for a row
	// another write holds is bounded at [store.LockTimeout] and returns
	// [store.ErrLockTimeout].
	Delete(ctx context.Context, id did.DID) error
}
