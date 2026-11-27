// Package bucketpolicy defines the store of bucket policies: one policy per
// bucket (see [s3bkt.PolicyDocument]) with the strong ETag a request's
// precondition is checked against, and an index from principal to the
// buckets whose statements name it.
//
// Every write of a policy is a task on the tenant's queue (a policy write or
// removal, a principal removal), and writes through the statements this
// store builds for the task's commit ([Store.PutStatements],
// [Store.DeleteStatements]). A bucket's deletion takes its policy and index
// rows with it, by cascade.
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

// Store persists bucket policies.
type Store interface {
	// Get returns the bucket's policy. It returns [store.ErrRecordNotFound] if
	// the bucket has none.
	Get(ctx context.Context, bucket did.DID) (Record, error)
	// ListByPrincipal returns the tenant's policies whose statements name
	// principal, including those naming every principal with the wildcard,
	// ordered by bucket. It is answered from the index.
	//
	// Removing a principal's row would remove its index rows by cascade but
	// leave the policies naming it, so principal removal strips the principal
	// from each listed policy itself, and only tombstones the row.
	ListByPrincipal(ctx context.Context, tenant did.DID, principal string) ([]Record, error)
	// PutStatements returns the writes that create or replace the policy of
	// the tenant's bucket with doc, for a task to run in its commit: put,
	// then index, in order. Callers check that the bucket is the tenant's
	// and run [bucketpolicy.Validate] first; a bucket that is missing fails
	// put when it runs, and a principal doc names that the tenant does not
	// have fails index. index replaces the bucket's index rows.
	PutStatements(tenant, bucket did.DID, doc s3bkt.PolicyDocument) (put store.Statement, index []store.Statement)
	// DeleteStatements returns the writes that remove the bucket's policy,
	// for a task to run in its commit: del, then index. index removes the
	// bucket's index rows.
	DeleteStatements(bucket did.DID) (del, index store.Statement)
}

// CheckPrecondition applies the If-Match / If-None-Match rule of a
// conditional write: a nil ifMatch requires no current policy, old being nil;
// a non-nil one must equal the current ETag.
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
