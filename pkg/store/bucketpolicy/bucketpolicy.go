// Package bucketpolicy defines the store of bucket policies: one policy per
// bucket (see [s3bkt.PolicyDocument]) with the strong ETag its compare-and-set
// writes are conditioned on, and an index from principal to the buckets whose
// statements name it.
//
// A policy write or removal the tenant asks for is a task on the tenant's
// queue, and writes through the statements this store builds for the task's
// commit ([Store.LockStatement], [Store.PutStatements],
// [Store.DeleteStatements]).
//
// Put, Delete and DeleteByBucket are the writes of principal removal and
// bucket deletion, which run outside the queue. Each takes a callback, fn,
// that runs inside the write, before it takes effect. The Postgres backend
// runs it inside the write's transaction, after taking a bucket-keyed
// advisory lock (and the row lock, when a row exists) and before committing,
// so a share-locked read of the bucket (see [store.WithShareLock]) waits for
// the outcome, whether the write creates, replaces or deletes the policy. A
// callback error rolls the write back.
package bucketpolicy

import (
	"context"
	"fmt"
	"time"

	s3bkt "github.com/fil-forge/libforge/commands/s3/bucket"

	"github.com/fil-forge/hilt/pkg/store"
	"github.com/fil-forge/ucantone/did"
)

// Record is a bucket's stored policy.
type Record struct {
	// Bucket is the bucket DID the policy applies to.
	Bucket did.DID
	// Policy is the bucket's policy.
	Policy s3bkt.PolicyDocument
	// ETag is the strong entity tag of Policy (see [s3bkt.ETag]).
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
	Policy s3bkt.PolicyDocument
	// Conditional makes the write check IfMatch. Unset, the write replaces
	// whatever is stored, whatever tag it carries, and creates when nothing
	// is: the write a PutBucketPolicy without a precondition makes.
	Conditional bool
	// IfMatch is the ETag the bucket's current policy must carry for a
	// Conditional write to proceed. Nil means the bucket must have no policy
	// (If-None-Match: *).
	IfMatch *string
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
	// its index rows, and commits. It returns the new ETag. When in is
	// Conditional, it returns [store.ErrPreconditionFailed] when IfMatch is
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
	// fn must not read or write this store: a locked read of the same row
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
	// Deleting a principal removes its index rows by cascade but does not
	// rewrite the policies. Principal removal must strip the principal from each listed policy
	// itself and must not rely on the cascade.
	ListByPrincipal(ctx context.Context, tenant did.DID, principal string, opts ...store.ReadOption) ([]Record, error)
	// RequireUnchangedStatement returns a statement for a task that issued
	// grants from read, the result of [Store.ListByPrincipal] for the
	// principal, to run in its commit with WriteConditional. It affects one
	// row when the policies naming the principal are still exactly those,
	// compared by bucket and ETag, and none otherwise, which fails the commit
	// so the task runs again from the policies as they are then.
	//
	// It is there for the two writers that change a policy outside the
	// tenant's task queue: principal removal, which rewrites the policies
	// naming the principal it removes, and bucket deletion, which takes the
	// bucket's policy with it. One that commits after the task read the
	// policies would otherwise leave the task storing grants from a document
	// that is no longer stored. It takes no lock, so one that commits after
	// the statement ran and before the task commits is not seen.
	RequireUnchangedStatement(tenant did.DID, principal string, read []Record) store.Statement
	// LockStatement returns the statement that opens the commit of a task
	// that writes or removes the bucket's policy: it takes the bucket's
	// policy write lock until the commit, the lock [Store.Put],
	// [Store.Delete] and [Store.DeleteByBucket] hold.
	//
	// The lock is there for bucket deletion, which runs outside the tenant's
	// task queue and holds it while it revokes the grants over the bucket
	// and deletes the bucket ([Store.DeleteByBucket]). The task's commit
	// waits for a deletion in flight and then finds the bucket gone, so it
	// stores no grant the deletion did not revoke, and a deletion that
	// starts later revokes what the task stored.
	LockStatement(bucket did.DID) store.Statement
	// PutStatements returns the writes that create or replace the policy of
	// the tenant's bucket with doc, for a task to run in its commit: cas
	// with WriteConditional, then index, in order, with Write. read is the
	// policy the task's handler read, nil when the bucket had none.
	//
	// cas writes the document on the condition that the stored policy is
	// still read (the same ETag, or still none). It affects no row
	// otherwise, which fails the commit, so the task runs again and decides
	// from the policy as it is then. index replaces the bucket's index rows. Callers run [bucketpolicy.Validate]
	// first, as for [Store.Put].
	//
	// The condition on the ETag is there for principal removal, which
	// rewrites the policies naming the principal it removes outside the
	// tenant's task queue. A bucket deleted since the read needs no
	// condition: the policy's foreign key to the bucket fails a create, and
	// the deletion removed the row a replace would update, so the commit
	// fails either way and the task runs again and finds the bucket gone.
	PutStatements(tenant, bucket did.DID, doc s3bkt.PolicyDocument, read *Record) (cas store.Statement, index []store.Statement)
	// DeleteStatements returns the writes that remove the bucket's policy,
	// for a task to run in its commit: cas with WriteConditional, then
	// index with Write. cas deletes the policy on the condition that it is
	// still read, the policy the task's handler read, compared by ETag, and
	// affects no row otherwise, for the reasons [Store.PutStatements] gives.
	// index removes the bucket's index rows.
	DeleteStatements(bucket did.DID, read Record) (cas, index store.Statement)
}

// CheckInputPrecondition applies [CheckPrecondition] to a Conditional in.
func CheckInputPrecondition(in Input, old *Record) error {
	if !in.Conditional {
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
		return fmt.Errorf("policy ETag is %s, not %s: %w", old.ETag, *ifMatch, store.ErrPreconditionFailed)
	}
	return nil
}
