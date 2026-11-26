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
	// if the tenant already has a live principal with that external ID. The
	// wait for a row an in-flight [Store.Tombstone] holds is
	// bounded at [store.LockTimeout] and returns [store.ErrLockTimeout].
	Add(ctx context.Context, tenant did.DID, externalID string) error
	// Get returns the tenant's principal with the given external ID. It returns
	// [store.ErrRecordNotFound] if there is none or it was removed. With
	// [store.WithShareLock] the read waits for an in-flight [Store.Tombstone] of
	// the same row to commit or roll back; the wait is bounded at
	// [store.LockTimeout] and returns [store.ErrLockTimeout] when it runs out.
	Get(ctx context.Context, tenant did.DID, externalID string, opts ...store.ReadOption) (Record, error)
	// ListByTenant returns every live principal of the tenant, ordered by
	// external ID.
	ListByTenant(ctx context.Context, tenant did.DID) ([]Record, error)
	// ListIDsByTenant returns the external IDs of the tenant's live
	// principals, in the order ListByTenant returns them. It is the list a
	// caller checks a policy document's principals against.
	ListIDsByTenant(ctx context.Context, tenant did.DID) ([]string, error)
	// Tombstone marks a principal's row removed; the row stays, so that Add
	// can revive it. It excludes concurrent removals and revives of the same
	// row for the whole call, runs fn (nil allowed) inside the write, before
	// it takes effect, then marks the row. An error from fn is returned and
	// leaves the principal live. It is idempotent: when no live row exists it
	// returns nil without running fn. The wait for the row lock is bounded at
	// [store.LockTimeout] and returns [store.ErrLockTimeout], which the caller
	// retries.
	//
	// fn must not read or write this store: a share-locked read or a write of
	// the same row waits on the lock the call itself holds. It may write other
	// stores, including ones whose own writes read this one: only the removed
	// row is held while it runs, and ListByTenant does not wait on it. On
	// Postgres fn's ctx carries the transaction, so a store that opens with
	// pglock.Begin writes inside it.
	Tombstone(ctx context.Context, tenant did.DID, externalID string, fn func(ctx context.Context) error) error
	// DeleteByTenant deletes the rows of every principal of the tenant,
	// tombstones included. It is idempotent. It waits for calls that hold any
	// of the tenant's principals, bounded at [store.LockTimeout], and returns
	// [store.ErrLockTimeout] when the wait runs out.
	DeleteByTenant(ctx context.Context, tenant did.DID) error
	// RequireLiveStatement returns a statement for a task whose commit
	// depends on every one of the principals being live, to run in the commit
	// with WriteConditional ahead of the task's writes: a key creation names
	// the key's principal, and a policy write the principals its document
	// names. It share-locks the principals' live rows until the commit and
	// affects no row when one of them is missing or removed, which fails the
	// commit so the task runs again and refuses the change. It needs at
	// least one principal.
	//
	// The lock is there for principal removal, which runs outside the
	// tenant's task queue and holds the principal's row while it checks that
	// no policy names the principal and deletes the principal's keys. The
	// statement waits for a removal in flight and then finds the row
	// removed; a removal that starts later waits for the task's commit, and
	// then finds the policy naming the principal, or lists the new key.
	RequireLiveStatement(tenant did.DID, externalIDs ...string) store.Statement
}
