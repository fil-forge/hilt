// Package bucketpolicy defines the store of bucket policies: one policy per
// bucket (see [bucketpolicy.Policy]) with the strong ETag its compare-and-set
// writes are conditioned on, and an index from principal to the buckets whose
// statements name it.
//
// Every write that changes a principal's access takes a callback, fn, that
// runs inside the write, before it takes effect.
// The Postgres backend runs it inside the write's transaction, after taking a
// bucket-keyed advisory lock (and the row lock, when a row exists) and before
// committing, so a caller can run a callback with the guarantee that
// a share-locked read of the bucket (see [store.WithShareLock]) waits for the
// outcome, whether the write creates, replaces or deletes the policy. A
// callback error rolls the write back. The memory backend runs the callback
// under the store mutex.
package bucketpolicy

import (
	"context"
	"fmt"
	"time"

	"github.com/fil-forge/hilt/pkg/bucketpolicy"
	"github.com/fil-forge/hilt/pkg/store"
	"github.com/fil-forge/ucantone/did"
)

// Record is a bucket's stored policy.
type Record struct {
	// Bucket is the bucket DID the policy applies to.
	Bucket did.DID
	// Policy is the bucket's policy.
	Policy bucketpolicy.Policy
	// ETag is the strong entity tag of Policy (see [bucketpolicy.ETag]).
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
	// Policy is the policy to store. The store does not validate it beyond
	// referential integrity; callers run [bucketpolicy.Validate] first.
	Policy bucketpolicy.Policy
	// IfMatch is the ETag the bucket's current policy must carry for the write
	// to proceed. Nil means the bucket must have no policy (If-None-Match: *).
	IfMatch *string
	// Unconditional writes whether or not the bucket has a policy and
	// whatever tag it carries; IfMatch is ignored. It is the write a
	// PutBucketPolicy without a precondition makes.
	Unconditional bool
}

// Store persists bucket policies.
type Store interface {
	// Get returns the bucket's policy. It returns [store.ErrRecordNotFound] if
	// the bucket has none. With [store.WithShareLock] the read waits for an
	// in-flight write of the same bucket's policy, a create included, to
	// commit or roll back; on Postgres the wait is bounded at
	// [store.LockTimeout] and returns [store.ErrLockTimeout] when it runs out.
	Get(ctx context.Context, bucket did.DID, opts ...store.ReadOption) (Record, error)
	// Put creates or replaces the bucket's policy in one transaction: it locks
	// the current row, checks in.IfMatch against it, runs fn (nil
	// allowed) with the current record (nil when creating), writes the row and
	// its index rows, and commits. It returns the new ETag. Unless in is
	// Unconditional, it returns [store.ErrPreconditionFailed] when IfMatch is
	// nil and a policy exists, or IfMatch names a tag other than the current
	// one (including when no policy exists); [store.ErrRecordNotFound] when the
	// bucket does not exist, checked before fn runs; and
	// [store.ErrInvalidArgument] when the bucket or tenant is undef or, on
	// Postgres, a named principal does not exist or the bucket is not the
	// tenant's. An error from fn is returned and nothing is written.
	// The tenant check on Postgres runs after fn, so a callback that
	// published may still see the write fail. On Postgres every lock the write takes is bounded at
	// [store.LockTimeout]; a longer wait returns [store.ErrLockTimeout] and
	// nothing is written.
	//
	// fn must not read or write this store: on the memory backend it
	// runs under the store mutex, and on Postgres a locked read of the same row
	// would wait on the lock the call itself holds.
	Put(ctx context.Context, in Input, fn func(ctx context.Context, old *Record) error) (string, error)
	// Delete removes the bucket's policy in one transaction, under the same
	// locking and callback contract as [Store.Put]. It returns
	// [store.ErrRecordNotFound] if the bucket has no policy and
	// [store.ErrPreconditionFailed] if ifMatch is not the current ETag; in both
	// cases fn does not run. An empty ifMatch is unconditional.
	Delete(ctx context.Context, bucket did.DID, ifMatch string, fn func(ctx context.Context, old Record) error) error
	// DeleteByBucket removes the bucket's policy and index rows
	// unconditionally, holding the bucket's write lock across fn
	// (nil allowed): a policy write in flight finishes first and one arriving
	// later waits, so nothing the callback revokes or deletes is granted again
	// behind it. It is idempotent. Bucket deletion revokes the bucket's grants
	// and deletes the bucket row inside the callback; tenant deletion passes
	// nil. The callback's error is returned as it came. fn must not
	// read or write this store, as for [Store.Put].
	DeleteByBucket(ctx context.Context, bucket did.DID, fn func(ctx context.Context) error) error
	// ListByPrincipal returns the tenant's policies whose statements name
	// principal, including those naming every principal with the wildcard,
	// ordered by bucket. It is answered from the index. With [store.WithShareLock]
	// the read waits for in-flight writes of the listed rows.
	//
	// Deleting a principal removes its index rows on Postgres by cascade but
	// not on the memory backend, and neither backend rewrites the policies.
	// Principal removal must strip the principal from each listed policy
	// itself and must not rely on the cascade.
	ListByPrincipal(ctx context.Context, tenant did.DID, principal string, opts ...store.ReadOption) ([]Record, error)
}

// CheckInputPrecondition applies [CheckPrecondition] to in unless it is
// Unconditional.
func CheckInputPrecondition(in Input, old *Record) error {
	if in.Unconditional {
		return nil
	}
	return CheckPrecondition(old, in.IfMatch)
}

// CheckPrecondition applies the If-Match / If-None-Match rule of [Store.Put]:
// a nil ifMatch requires no current policy; a non-nil one must equal the
// current ETag.
func CheckPrecondition(old *Record, ifMatch *string) error {
	switch {
	case ifMatch == nil && old != nil:
		return fmt.Errorf("policy already exists with ETag %s: %w", old.ETag, store.ErrPreconditionFailed)
	case ifMatch != nil && old == nil:
		return fmt.Errorf("bucket has no policy: %w", store.ErrPreconditionFailed)
	case ifMatch != nil && old.ETag != *ifMatch:
		return fmt.Errorf("policy ETag is %s: %w", old.ETag, store.ErrPreconditionFailed)
	}
	return nil
}
