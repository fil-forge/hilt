// Package principal defines the store of a tenant's principals: the console
// users (identified by the console's principalId) whose access to the tenant's
// buckets is computed from bucket policies at request time. A principal holds
// no key material and no delegations.
//
// A removed principal stays in the store as a tombstone that no read returns.
// Add revives it, so the console may reuse an id without the new principal
// inheriting anything from the old one.
package principal

import (
	"context"
	"time"

	"github.com/fil-forge/ucantone/did"
)

// Record is one principal of a tenant.
type Record struct {
	// Tenant is the tenant DID (did:plc) the principal belongs to.
	Tenant did.DID
	// ExternalID is the console principalId that identifies the principal
	// within the tenant.
	ExternalID string
	// CreatedAt is when the principal was recorded.
	CreatedAt time.Time
}

// Store persists principal records.
type Store interface {
	// Add records a principal, or revives a removed one under the same external
	// ID with a fresh CreatedAt. It returns [store.ErrInvalidArgument] if the
	// tenant is undef or the external ID is empty, and [store.ErrRecordExists]
	// if the tenant already has a live principal with that external ID.
	Add(ctx context.Context, tenant did.DID, externalID string) error
	// Get returns the tenant's principal with the given external ID. It returns
	// [store.ErrRecordNotFound] if there is none or it was removed.
	Get(ctx context.Context, tenant did.DID, externalID string) (Record, error)
	// ListByTenant returns every live principal of the tenant, ordered by
	// external ID.
	ListByTenant(ctx context.Context, tenant did.DID) ([]Record, error)
	// ListIDsByTenant returns the external IDs of the tenant's live
	// principals, in the order ListByTenant returns them. It is the list a
	// caller checks a policy document's principals against.
	ListIDsByTenant(ctx context.Context, tenant did.DID) ([]string, error)
	// Tombstone marks a principal's row removed; the row stays, so that Add
	// can revive it. It runs fn (nil allowed) inside the write, before it takes
	// effect, then marks the row. An error from fn is returned and leaves the
	// principal live. It is idempotent: when no live row exists it returns nil
	// without running fn. On Postgres fn's ctx carries the transaction, so a
	// store that opens with pglock.Begin writes inside it.
	Tombstone(ctx context.Context, tenant did.DID, externalID string, fn func(ctx context.Context) error) error
	// DeleteByTenant deletes the rows of every principal of the tenant,
	// tombstones included. It is idempotent.
	DeleteByTenant(ctx context.Context, tenant did.DID) error
}
