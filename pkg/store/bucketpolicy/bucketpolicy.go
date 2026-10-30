// Package bucketpolicy defines the store of bucket policies: one policy per
// bucket (see [s3bkt.PolicyDocument]), and an index from principal to the
// buckets whose statements name it.
//
// Every write that changes a principal's access takes a callback, fn, that
// runs inside the write, before it takes effect. The Postgres backend runs it
// inside the write's transaction, before committing, and a callback error
// rolls the write back. No write waits for another: two writes to one bucket
// both commit, and the stored policy is the last one committed.
package bucketpolicy

import (
	"context"
	"time"

	s3bkt "github.com/fil-forge/libforge/commands/s3/bucket"

	"github.com/fil-forge/ucantone/did"
)

// Record is a bucket's stored policy.
type Record struct {
	// Bucket is the bucket DID the policy applies to.
	Bucket did.DID
	// Policy is the bucket's policy.
	Policy s3bkt.PolicyDocument
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
}

// Store persists bucket policies.
type Store interface {
	// Get returns the bucket's policy. It returns [store.ErrRecordNotFound] if
	// the bucket has none.
	Get(ctx context.Context, bucket did.DID) (Record, error)
	// Put creates or replaces the bucket's policy in one transaction: it reads
	// the current record, runs fn (nil allowed) with it (nil when creating),
	// writes the row and its index rows, and commits. It returns
	// [store.ErrRecordNotFound] when the bucket does not exist, checked before
	// fn runs, and [store.ErrInvalidArgument] when the bucket or tenant is
	// undef or, on Postgres, a named principal does not exist or is removed, or
	// the bucket is not the tenant's. An error from fn is returned and nothing
	// is written. The tenant check on Postgres runs after fn, so a callback
	// that published may still see the write fail.
	//
	// fn must not read or write this store.
	Put(ctx context.Context, in Input, fn func(ctx context.Context, old *Record) error) error
	// Delete removes the bucket's policy in one transaction, under the same
	// callback contract as [Store.Put]. It returns [store.ErrRecordNotFound] if
	// the bucket has no policy, and fn does not run.
	Delete(ctx context.Context, bucket did.DID, fn func(ctx context.Context, old Record) error) error
	// DeleteByBucket removes the bucket's policy and index rows, running fn
	// (nil allowed) inside the same transaction first. It is idempotent.
	// Bucket deletion revokes the bucket's grants and deletes the bucket row
	// inside the callback; tenant deletion passes nil. The callback's error is
	// returned as it came. fn must not read or write this store.
	DeleteByBucket(ctx context.Context, bucket did.DID, fn func(ctx context.Context) error) error
	// ListByPrincipal returns the tenant's policies whose statements name
	// principal, including those naming every principal with the wildcard,
	// ordered by bucket. It is answered from the index.
	//
	// Deleting a principal removes its index rows on Postgres by cascade but
	// not on the memory backend, and neither backend rewrites the policies.
	// Principal removal must strip the principal from each listed policy
	// itself and must not rely on the cascade.
	ListByPrincipal(ctx context.Context, tenant did.DID, principal string) ([]Record, error)
	// Snapshot runs fn so that every store read fn makes with the ctx it is
	// handed sees the stores as of one moment: a write that commits while fn
	// runs is either wholly visible to fn or not at all. It is for reads that
	// must agree with each other, such as a policy and the delegations a write
	// rotated from it. On Postgres fn runs in a read-only REPEATABLE READ
	// transaction, which ctx carries; the memory backend keeps no
	// transactions and runs fn as it is. fn must not write.
	Snapshot(ctx context.Context, fn func(ctx context.Context) error) error
}
