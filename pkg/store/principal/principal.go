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
	// [Store.Delete] of the same row to commit or roll back; on Postgres the
	// wait is bounded at [store.LockTimeout] and returns
	// [store.ErrLockTimeout] when it runs out.
	Get(ctx context.Context, tenant did.DID, externalID string, opts ...store.ReadOption) (Record, error)
	// ListByTenant returns every live principal of the tenant, ordered by
	// external ID.
	ListByTenant(ctx context.Context, tenant did.DID) ([]Record, error)
	// Delete removes a principal by marking its row deleted. It excludes
	// concurrent removals and revives of the same row for the whole call, runs
	// beforeCommit (nil allowed), then marks the row and commits. An error from
	// beforeCommit is returned and leaves the principal live. It is idempotent:
	// when no live row exists it returns nil without running beforeCommit. On
	// Postgres the wait for the row lock is bounded at [store.LockTimeout] and
	// returns [store.ErrLockTimeout], which the caller retries.
	//
	// beforeCommit must not read or write this store: a share-locked read or a
	// write of the same row waits on the lock the call itself holds. It may
	// write other stores, including ones whose own writes read this one: no
	// lock on this store's records is held while it runs.
	Delete(ctx context.Context, tenant did.DID, externalID string, beforeCommit func(ctx context.Context) error) error
	// Lock holds the tenant's live principals with the given external IDs
	// against concurrent removals, revives and share-locked reads while fn runs,
	// then releases them. A policy write uses it so that a key created for one
	// of the principals meanwhile is either included in the write's rotation or
	// created from the committed policy. IDs with no live row are skipped. fn
	// follows the contract of [Store.Delete]'s beforeCommit. On Postgres the
	// wait for the rows is bounded at [store.LockTimeout] and returns
	// [store.ErrLockTimeout].
	Lock(ctx context.Context, tenant did.DID, externalIDs []string, fn func(ctx context.Context) error) error
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
