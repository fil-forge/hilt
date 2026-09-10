// Package policy defines the store of bucket policies: one document per
// bucket (see [policy.Document]) with the strong ETag its compare-and-set
// writes are conditioned on, and an index from principal to the buckets whose
// statements name it.
//
// Every write that changes a principal's access takes a beforeCommit callback.
// The Postgres backend runs it inside the write's transaction, after taking a
// bucket-keyed advisory lock (and the row lock, when a row exists) and before
// committing, so a caller can publish an invalidation with the guarantee that
// a share-locked read of the bucket (see [store.WithLock]) waits for the
// outcome, whether the write creates, replaces or deletes the policy. A
// callback error rolls the write back. The memory backend runs the callback
// under the store mutex.
package policy

import (
	"context"
	"time"

	"github.com/fil-forge/hilt/pkg/policy"
	"github.com/fil-forge/hilt/pkg/store"
	"github.com/fil-forge/ucantone/did"
)

// Record is a bucket's stored policy.
type Record struct {
	// Bucket is the bucket DID the policy applies to.
	Bucket did.DID
	// Document is the policy.
	Document policy.Document
	// ETag is the strong entity tag of Document (see [policy.ETag]).
	ETag string
	// UpdatedAt is when the policy was last written.
	UpdatedAt time.Time
}

// Input is the data needed to create or replace a bucket's policy.
type Input struct {
	// Bucket is the bucket DID the policy applies to.
	Bucket did.DID
	// Tenant is the DID of the tenant that owns the bucket. The index rows are
	// keyed by it so a principal's policies can be listed within its tenant.
	Tenant did.DID
	// Document is the policy to store. The store does not validate it beyond
	// referential integrity; callers run [policy.Validate] first.
	Document policy.Document
	// IfMatch is the ETag the bucket's current policy must carry for the write
	// to proceed. Nil means the bucket must have no policy (If-None-Match: *).
	IfMatch *string
}

// Store persists bucket policies.
type Store interface {
	// Get returns the bucket's policy. It returns [store.ErrRecordNotFound] if
	// the bucket has none. With [store.WithLock]([store.LockShare]) the read
	// waits for an in-flight write of the same bucket's policy, a create
	// included, to commit or roll back; on Postgres the wait is bounded and
	// an error is returned when it runs out.
	Get(ctx context.Context, bucket did.DID, opts ...store.ReadOption) (Record, error)
	// Put creates or replaces the bucket's policy in one transaction: it locks
	// the current row, checks in.IfMatch against it, runs beforeCommit (nil
	// allowed) with the current record (nil when creating), writes the row and
	// its index rows, and commits. It returns the new ETag. It returns
	// [store.ErrPreconditionFailed] when IfMatch is nil and a policy exists, or
	// IfMatch names a tag other than the current one (including when no policy
	// exists); [store.ErrInvalidArgument] when the bucket or tenant is undef or,
	// on Postgres, the bucket or a named principal does not exist. An error from
	// beforeCommit is returned and nothing is written. The referential checks
	// run after beforeCommit, so a callback that published may still see the
	// write fail.
	//
	// beforeCommit must not read or write this store: on the memory backend it
	// runs under the store mutex, and on Postgres a locked read of the same row
	// would wait on the lock the call itself holds.
	Put(ctx context.Context, in Input, beforeCommit func(ctx context.Context, old *Record) error) (string, error)
	// Delete removes the bucket's policy in one transaction, under the same
	// locking and callback contract as [Store.Put]. It returns
	// [store.ErrRecordNotFound] if the bucket has no policy and
	// [store.ErrPreconditionFailed] if ifMatch is not the current ETag; in both
	// cases beforeCommit does not run.
	Delete(ctx context.Context, bucket did.DID, ifMatch string, beforeCommit func(ctx context.Context, old Record) error) error
	// DeleteByBucket removes the bucket's policy and index rows
	// unconditionally. It is idempotent and is used by bucket and tenant
	// deletion, which publish nothing.
	DeleteByBucket(ctx context.Context, bucket did.DID) error
	// ListByPrincipal returns the tenant's policies whose statements name
	// principal, including those naming every principal with the wildcard,
	// ordered by bucket. It is answered from the index. With
	// [store.WithLock]([store.LockShare]) the read waits for in-flight writes of
	// the listed rows.
	//
	// Deleting a principal removes its index rows on Postgres by cascade but
	// not on the memory backend, and neither backend rewrites the documents.
	// Principal removal must strip the principal from each listed document
	// itself and must not rely on the cascade.
	ListByPrincipal(ctx context.Context, tenant did.DID, principal string, opts ...store.ReadOption) ([]Record, error)
}
