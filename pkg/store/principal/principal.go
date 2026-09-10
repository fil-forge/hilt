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

	"github.com/fil-forge/hilt/pkg/store"
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
	// [store.ErrRecordNotFound] if there is none or it was removed. With
	// [store.WithLock]([store.LockShare]) the read waits for an in-flight
	// [Store.Delete] of the same row to commit or roll back.
	Get(ctx context.Context, tenant did.DID, externalID string, opts ...store.ReadOption) (Record, error)
	// ListByTenant returns every live principal of the tenant, ordered by
	// external ID.
	ListByTenant(ctx context.Context, tenant did.DID) ([]Record, error)
	// Delete removes a principal by marking its row deleted. It locks the row
	// for the whole call, runs beforeCommit (nil allowed) while holding the
	// lock, then marks the row and commits. An error from beforeCommit is
	// returned and leaves the principal live. It is idempotent: when no live
	// row exists it returns nil without running beforeCommit.
	//
	// beforeCommit must not read or write this store: on the memory backend it
	// runs under the store mutex, and on Postgres a locked read of the same row
	// would wait on the lock the call itself holds.
	Delete(ctx context.Context, tenant did.DID, externalID string, beforeCommit func(ctx context.Context) error) error
	// DeleteByTenant deletes every row of the tenant, tombstones included. It is
	// idempotent.
	DeleteByTenant(ctx context.Context, tenant did.DID) error
}

// ExternalIDs returns the external IDs of the tenant's live principals, in
// the order [Store.ListByTenant] returns them. It is the list a caller checks
// a policy document's principals against.
func ExternalIDs(ctx context.Context, s Store, tenant did.DID) ([]string, error) {
	recs, err := s.ListByTenant(ctx, tenant)
	if err != nil {
		return nil, err
	}
	ids := make([]string, 0, len(recs))
	for _, rec := range recs {
		ids = append(ids, rec.ExternalID)
	}
	return ids, nil
}
