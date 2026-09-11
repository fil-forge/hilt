// Package principal defines the store of a tenant's principals: the console
// users (identified by the console's userId) whose access to the tenant's
// buckets is computed from bucket policies at request time. A principal holds
// no key material and no delegations.
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
	// ExternalID is the console userId that identifies the principal within the
	// tenant.
	ExternalID string
	// CreatedAt is when the principal was recorded.
	CreatedAt time.Time
}

// Store persists principal records.
type Store interface {
	// Add records a principal. It returns [store.ErrInvalidArgument] if the
	// tenant is undef or the external ID is empty, and [store.ErrRecordExists]
	// if the tenant already has a principal with that external ID.
	Add(ctx context.Context, tenant did.DID, externalID string) error
	// Get returns the tenant's principal with the given external ID. It returns
	// [store.ErrRecordNotFound] if there is none. With
	// [store.WithLock]([store.LockShare]) the read waits for an in-flight
	// [Store.Delete] of the same row to commit or roll back; on Postgres the
	// wait is bounded at [store.LockTimeout] and returns
	// [store.ErrLockTimeout] when it runs out.
	Get(ctx context.Context, tenant did.DID, externalID string, opts ...store.ReadOption) (Record, error)
	// ListByTenant returns every principal of the tenant, ordered by external
	// ID.
	ListByTenant(ctx context.Context, tenant did.DID) ([]Record, error)
	// Delete removes a principal. It locks the row for the whole call, runs
	// beforeCommit (nil allowed) while holding the lock, then deletes the row
	// and commits. An error from beforeCommit is returned and leaves the row in
	// place. It is idempotent: when no row exists it returns nil without running
	// beforeCommit. On Postgres the wait for the row lock is bounded at
	// [store.LockTimeout] and returns [store.ErrLockTimeout], which the caller
	// retries.
	//
	// beforeCommit must not read or write this store: on the memory backend it
	// runs under the store mutex, and on Postgres a locked read of the same row
	// would wait on the lock the call itself holds.
	Delete(ctx context.Context, tenant did.DID, externalID string, beforeCommit func(ctx context.Context) error) error
	// DeleteByTenant removes every principal of the tenant. It is idempotent.
	DeleteByTenant(ctx context.Context, tenant did.DID) error
}
