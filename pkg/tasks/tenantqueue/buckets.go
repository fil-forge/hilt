package tenantqueue

import (
	"context"
	"errors"
	"fmt"

	"github.com/fil-forge/hilt/pkg/tasks"
	"github.com/fil-forge/hilt/pkg/tasks/revocationqueue"
	"github.com/fil-forge/libforge/taskrunner"
	"github.com/fil-forge/ucantone/did"
	"go.uber.org/zap"
)

// DeleteBucketSpec returns the queue-tenant.delete-bucket task that deletes
// the tenant's bucket. Its arguments are the bucket's DID.
func DeleteBucketSpec(tenant, bucket did.DID) taskrunner.Spec {
	return taskrunner.Spec{
		Queue:   tasks.QueueTenant,
		Subject: tenant.String(),
		Action:  tasks.ActionDeleteBucket,
		Args:    []byte(bucket.String()),
	}
}

// runDeleteBucket is queue-tenant.delete-bucket. It deletes the subject
// tenant's bucket named in the task's arguments. Its caller has asked the
// upload service that the bucket's space is empty before queueing it. A
// bucket the tenant does not have is left alone and the task succeeds, which
// is also what a second run of a task that committed does.
//
// Everything it writes commits together:
//
//   - Every delegation the tenant issued over the bucket, whichever key
//     holds it, leaves the delegation store and is recorded as a revocation
//     owed. Powerline delegations, which carry no subject, reach the
//     tenant's other buckets and are left alone.
//   - The bucket's other delegations leave the store unrevoked: its root
//     delegation to the tenant, which the bucket's own key signed and which
//     no witness path lets the tenant revoke, is of no use once the bucket is
//     gone.
//   - The bucket is deleted, which takes its policy and the policy's index
//     rows with it, and its owner is kept for the usage reported late.
//   - The publishing of the revocations is queued.
func (q *Queue) runDeleteBucket(ctx context.Context, ex *taskrunner.Exec, t taskrunner.Task) ([]byte, error) {
	tenantID, err := did.Parse(t.Subject)
	if err != nil {
		return nil, taskrunner.Permanent(fmt.Errorf("parsing the tenant in the task's subject: %w", err))
	}
	bucketID, err := did.Parse(string(t.Args))
	if err != nil {
		return nil, taskrunner.Permanent(fmt.Errorf("parsing the bucket in the task's arguments: %w", err))
	}
	log := q.logger.With(zap.Stringer("tenant", tenantID), zap.Stringer("task", t.ID), zap.Stringer("bucket", bucketID))

	if err := q.checkBuckets(ctx, tenantID, []did.DID{bucketID}); errors.Is(err, ErrUnknownBucket) {
		return nil, nil
	} else if err != nil {
		return nil, err
	}

	writes := append(q.delegations.WithdrawSubjectStatements(tenantID, bucketID), q.buckets.DeleteStatement(tenantID, bucketID))
	for _, st := range writes {
		if err := ex.Write(ctx, st.SQL, st.Args...); err != nil {
			return nil, err
		}
	}
	// How many grants the commit withdraws is not known here, so the publish
	// is queued either way and finds nothing when none were.
	if _, err := ex.Submit(ctx, revocationqueue.PublishSpec(tenantID)); err != nil {
		return nil, fmt.Errorf("queueing the publishing of the tenant's revocations: %w", err)
	}
	log.Info("deleting a bucket")
	return nil, nil
}
