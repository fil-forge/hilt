package tenantqueue

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"slices"
	"time"

	s3bkt "github.com/fil-forge/libforge/commands/s3/bucket"

	"github.com/fil-forge/hilt/pkg/bucketpolicy"
	"github.com/fil-forge/hilt/pkg/grant"
	"github.com/fil-forge/hilt/pkg/store"
	"github.com/fil-forge/hilt/pkg/store/accesskey"
	bucketpolicystore "github.com/fil-forge/hilt/pkg/store/bucketpolicy"
	"github.com/fil-forge/hilt/pkg/tasks"
	"github.com/fil-forge/hilt/pkg/tasks/revocationqueue"
	"github.com/fil-forge/hilt/pkg/tasks/tenantqueue/datamodel"
	"github.com/fil-forge/hilt/pkg/vault"
	"github.com/fil-forge/libforge/taskrunner"
	"github.com/fil-forge/ucantone/did"
	"github.com/fil-forge/ucantone/ucan"
	"go.uber.org/zap"
)

// ErrPolicyNotFound is the outcome of a queue-tenant.delete-policy task for a
// bucket that has no policy.
var ErrPolicyNotFound = errors.New("bucket has no policy")

// PolicyCondition is the condition a policy write is sent with, as If-Match
// and If-None-Match state it.
type PolicyCondition struct {
	// Conditional makes the write check IfMatch. Unset, the write replaces
	// whatever is stored and creates when nothing is.
	Conditional bool
	// IfMatch is the ETag the bucket's current policy must carry for a
	// Conditional write to proceed. Nil means the bucket must have no policy.
	IfMatch *string
}

// PutPolicySpec returns the queue-tenant.put-policy task that stores doc as
// the policy of the tenant's bucket, which name addresses, under cond.
func PutPolicySpec(tenant, bucket did.DID, name string, doc s3bkt.PolicyDocument, cond PolicyCondition) (taskrunner.Spec, error) {
	args := datamodel.PutPolicyArgs{
		Bucket:      bucket,
		Name:        name,
		Document:    doc,
		Conditional: cond.Conditional,
		IfMatch:     cond.IfMatch,
	}
	var buf bytes.Buffer
	if err := args.MarshalCBOR(&buf); err != nil {
		return taskrunner.Spec{}, fmt.Errorf("encoding the arguments of %s.%s: %w", tasks.QueueTenant, tasks.ActionPutPolicy, err)
	}
	return taskrunner.Spec{
		Queue:   tasks.QueueTenant,
		Subject: tenant.String(),
		Action:  tasks.ActionPutPolicy,
		Args:    buf.Bytes(),
	}, nil
}

// DecodePutPolicyResult returns the new ETag a queue-tenant.put-policy task
// reported, and whether the bucket had no policy before.
func DecodePutPolicyResult(result []byte) (etag string, created bool, err error) {
	var model datamodel.PutPolicyResult
	if err := model.UnmarshalCBOR(bytes.NewReader(result)); err != nil {
		return "", false, fmt.Errorf("decoding the result of %s.%s: %w", tasks.QueueTenant, tasks.ActionPutPolicy, err)
	}
	return model.ETag, model.Created, nil
}

// DeletePolicySpec returns the queue-tenant.delete-policy task that removes
// the policy of the tenant's bucket, which name addresses. A non-nil ifMatch
// is the ETag the policy must carry.
func DeletePolicySpec(tenant, bucket did.DID, name string, ifMatch *string) (taskrunner.Spec, error) {
	args := datamodel.DeletePolicyArgs{Bucket: bucket, Name: name, IfMatch: ifMatch}
	var buf bytes.Buffer
	if err := args.MarshalCBOR(&buf); err != nil {
		return taskrunner.Spec{}, fmt.Errorf("encoding the arguments of %s.%s: %w", tasks.QueueTenant, tasks.ActionDeletePolicy, err)
	}
	return taskrunner.Spec{
		Queue:   tasks.QueueTenant,
		Subject: tenant.String(),
		Action:  tasks.ActionDeletePolicy,
		Args:    buf.Bytes(),
	}, nil
}

// runPutPolicy is queue-tenant.put-policy. It stores the document in the
// task's arguments as the policy of the subject tenant's bucket, and reports
// the new ETag and whether the bucket had no policy before
// ([DecodePutPolicyResult]). [Queue.changePolicy] has the commit.
//
// It fails for good when the bucket is not the tenant's
// ([*UnknownBucketError]), when the bucket's policy is not in the state the
// write is conditioned on (an error wrapping [store.ErrPreconditionFailed]),
// and when the document may not be stored for the bucket, or names a
// principal the tenant does not have (an error wrapping
// [s3bkt.ErrInvalidPolicy]).
func (q *Queue) runPutPolicy(ctx context.Context, ex *taskrunner.Exec, t taskrunner.Task) ([]byte, error) {
	tenantID, err := did.Parse(t.Subject)
	if err != nil {
		return nil, taskrunner.Permanent(fmt.Errorf("parsing the tenant in the task's subject: %w", err))
	}
	var args datamodel.PutPolicyArgs
	if err := args.UnmarshalCBOR(bytes.NewReader(t.Args)); err != nil {
		return nil, taskrunner.Permanent(fmt.Errorf("decoding the arguments of %s.%s: %w", tasks.QueueTenant, tasks.ActionPutPolicy, err))
	}
	log := q.logger.With(zap.Stringer("tenant", tenantID), zap.Stringer("task", t.ID), zap.Stringer("bucket", args.Bucket))

	old, err := q.currentPolicy(ctx, tenantID, args.Bucket)
	if err != nil {
		return nil, err
	}
	if args.Conditional {
		if err := bucketpolicystore.CheckPrecondition(old, args.IfMatch); err != nil {
			return nil, taskrunner.Permanent(err)
		}
	}
	principals, err := q.principals.ListIDsByTenant(ctx, tenantID)
	if err != nil {
		return nil, fmt.Errorf("listing the tenant's principals: %w", err)
	}
	if err := bucketpolicy.Validate(args.Document, args.Name, func(p string) bool { return slices.Contains(principals, p) }); err != nil {
		return nil, taskrunner.Permanent(err)
	}

	issued, err := q.changePolicy(ctx, ex, tenantID, args.Bucket, old, &args.Document, principals)
	if err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	result := datamodel.PutPolicyResult{ETag: s3bkt.ETag(args.Document), Created: old == nil}
	if err := result.MarshalCBOR(&buf); err != nil {
		return nil, taskrunner.Permanent(fmt.Errorf("encoding the result of %s.%s: %w", tasks.QueueTenant, tasks.ActionPutPolicy, err))
	}
	log.Info("writing a bucket policy", zap.Bool("created", result.Created), zap.Int("grants_issued", issued))
	return buf.Bytes(), nil
}

// runDeletePolicy is queue-tenant.delete-policy. It removes the policy of the
// subject tenant's bucket named in the task's arguments, so every principal
// the policy reached loses what it held over the bucket.
// [Queue.changePolicy] has the commit.
//
// It fails for good when the bucket is not the tenant's
// ([*UnknownBucketError]), when the bucket has no policy
// ([ErrPolicyNotFound]) and when the policy does not carry the ETag the
// removal is conditioned on (an error wrapping
// [store.ErrPreconditionFailed]).
func (q *Queue) runDeletePolicy(ctx context.Context, ex *taskrunner.Exec, t taskrunner.Task) ([]byte, error) {
	tenantID, err := did.Parse(t.Subject)
	if err != nil {
		return nil, taskrunner.Permanent(fmt.Errorf("parsing the tenant in the task's subject: %w", err))
	}
	var args datamodel.DeletePolicyArgs
	if err := args.UnmarshalCBOR(bytes.NewReader(t.Args)); err != nil {
		return nil, taskrunner.Permanent(fmt.Errorf("decoding the arguments of %s.%s: %w", tasks.QueueTenant, tasks.ActionDeletePolicy, err))
	}

	old, err := q.currentPolicy(ctx, tenantID, args.Bucket)
	if err != nil {
		return nil, err
	}
	if old == nil {
		return nil, taskrunner.Permanent(ErrPolicyNotFound)
	}
	if args.IfMatch != nil {
		if err := bucketpolicystore.CheckPrecondition(old, args.IfMatch); err != nil {
			return nil, taskrunner.Permanent(err)
		}
	}
	principals, err := q.principals.ListIDsByTenant(ctx, tenantID)
	if err != nil {
		return nil, fmt.Errorf("listing the tenant's principals: %w", err)
	}
	if _, err := q.changePolicy(ctx, ex, tenantID, args.Bucket, old, nil, principals); err != nil {
		return nil, err
	}
	q.logger.Info("removing a bucket policy", zap.Stringer("tenant", tenantID), zap.Stringer("task", t.ID), zap.Stringer("bucket", args.Bucket))
	return nil, nil
}

// currentPolicy returns the bucket's policy, nil when it has none, after
// checking that the bucket is the tenant's ([*UnknownBucketError], marked
// final, otherwise).
func (q *Queue) currentPolicy(ctx context.Context, tenantID, bucket did.DID) (*bucketpolicystore.Record, error) {
	if err := q.checkBuckets(ctx, tenantID, []did.DID{bucket}); err != nil {
		if errors.Is(err, ErrUnknownBucket) {
			return nil, taskrunner.Permanent(err)
		}
		return nil, err
	}
	rec, err := q.policies.Get(ctx, bucket)
	if errors.Is(err, store.ErrRecordNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("reading the bucket's policy: %w", err)
	}
	return &rec, nil
}

// changePolicy records the writes that replace the bucket's policy old (nil
// for none) with doc (nil to remove it) and returns how many grants it
// issued. principals are the tenant's. [Queue.policyWrites] builds the writes,
// and when the change alters a principal's actions the publishing of the
// revocations it records is queued with them.
func (q *Queue) changePolicy(ctx context.Context, ex *taskrunner.Exec, tenantID, bucket did.DID, old *bucketpolicystore.Record, doc *s3bkt.PolicyDocument, principals []string) (int, error) {
	change, err := q.policyWrites(ctx, tenantID, bucket, old, doc, principals)
	if err != nil {
		return 0, err
	}
	if err := record(ctx, ex, change.writes); err != nil {
		return 0, err
	}
	if change.affected {
		// How many grants the commit withdraws is not known here, so the
		// publish is queued for any change to a principal's actions and
		// finds nothing when none were.
		if _, err := ex.Submit(ctx, revocationqueue.PublishSpec(tenantID)); err != nil {
			return 0, fmt.Errorf("queueing the publishing of the tenant's revocations: %w", err)
		}
	}
	return change.issued, nil
}

// record records the writes in order.
func record(ctx context.Context, ex *taskrunner.Exec, writes []store.Statement) error {
	for _, w := range writes {
		if err := ex.Write(ctx, w.SQL, w.Args...); err != nil {
			return err
		}
	}
	return nil
}

// policyChange is the writes that replace one bucket's policy.
type policyChange struct {
	// writes are the statements to record, in order.
	writes []store.Statement
	// issued is how many grants the writes store.
	issued int
	// affected is whether the change alters any principal's actions, and so
	// may withdraw grants.
	affected bool
}

// policyWrites builds, without recording any, the writes that replace the
// bucket's policy old (nil for none) with doc (nil to remove it). principals
// are the tenant's principals whose grants the change may alter. Run
// together they:
//
//   - For every access key of each of principals whose effective actions on
//     the bucket the change alters ([bucketpolicy.Changed]), take the
//     delegations the tenant issued to the key over the bucket out of the
//     delegation store, record them as revocations owed, and store the key
//     the grants doc gives its principal there. Its delegations over other
//     buckets are left alone. A change that alters no principal's actions
//     withdraws and issues nothing.
//   - Write the document, or remove the policy, with its index rows.
//
// The grants issued are those the tenant's status keeps
// ([grant.LimitToTenantStatus]): a write-locked tenant's keys are stored the
// grants of the reads, listings and deletions doc gives their principals,
// and a disabled tenant's keys hold no grants, so for one the change
// withdraws and issues none. A change of the tenant's status issues every
// key the grants of the policies as they are then.
//
// The tenant's other changes are tasks on the same subject, so none commits
// between the handler's reads and its commit, and what the handler read
// decides.
func (q *Queue) policyWrites(ctx context.Context, tenantID, bucket did.DID, old *bucketpolicystore.Record, doc *s3bkt.PolicyDocument, principals []string) (policyChange, error) {
	var oldDoc *s3bkt.PolicyDocument
	if old != nil {
		oldDoc = &old.Policy
	}
	affected := slices.DeleteFunc(bucketpolicy.Changed(oldDoc, doc, principals), func(p string) bool {
		return !slices.Contains(principals, p)
	})
	var change policyChange
	if len(affected) > 0 {
		change.affected = true
		fresh, err := q.issueOver(ctx, tenantID, bucket, doc, affected)
		if err != nil {
			return policyChange{}, err
		}
		change.writes = append(change.writes, q.delegations.WithdrawGrantsOverStatement(tenantID, bucket, affected))
		if len(fresh) > 0 {
			put, err := q.delegations.PutStatement(fresh)
			if err != nil {
				return policyChange{}, fmt.Errorf("building the write of the keys' grants: %w", err)
			}
			change.writes = append(change.writes, put)
			change.issued = len(fresh)
		}
	}
	if doc != nil {
		put, index := q.policies.PutStatements(tenantID, bucket, *doc)
		change.writes = append(change.writes, put)
		change.writes = append(change.writes, index...)
	} else {
		del, index := q.policies.DeleteStatements(bucket)
		change.writes = append(change.writes, del, index)
	}
	return change, nil
}

// issueOver issues, signed by the tenant, the grants over the bucket that doc
// (nil for no policy) gives every access key of the principals: for each key,
// the delegations its principal's effective actions on the bucket map to. A
// key whose principal is left no action is issued nothing, and so is one that
// has expired, which authenticates no request. The actions are reduced to
// what the tenant's status keeps ([grant.LimitToTenantStatus]), so a
// write-locked tenant's keys are issued the grants of their reads, listings
// and deletions alone and a disabled tenant's keys nothing. It fails for
// good when grants are to be issued and the tenant's signing key is not in
// the vault.
func (q *Queue) issueOver(ctx context.Context, tenantID, bucket did.DID, doc *s3bkt.PolicyDocument, principals []string) ([]ucan.Delegation, error) {
	actions := make(map[string][]string, len(principals))
	granted := false
	for _, p := range principals {
		actions[p] = bucketpolicy.Effective(doc, p)
		granted = granted || len(actions[p]) > 0
	}
	if !granted {
		return nil, nil
	}
	rec, err := q.tenants.Get(ctx, tenantID)
	if errors.Is(err, store.ErrRecordNotFound) {
		return nil, taskrunner.Permanent(ErrTenantNotFound)
	}
	if err != nil {
		return nil, fmt.Errorf("looking up the tenant: %w", err)
	}
	granted = false
	for p, held := range actions {
		actions[p] = grant.LimitToTenantStatus(rec.Status, held)
		granted = granted || len(actions[p]) > 0
	}
	if !granted {
		return nil, nil
	}
	keys, err := q.accessKeys.ListByTenant(ctx, tenantID, accesskey.WithPrincipals(principals...))
	if err != nil {
		return nil, fmt.Errorf("listing the keys of %d principals: %w", len(principals), err)
	}

	now := time.Now()
	var issuer ucan.Issuer
	var fresh []ucan.Delegation
	for _, key := range keys {
		if key.Principal == nil || len(actions[*key.Principal]) == 0 {
			continue
		}
		if key.ExpiresAt != nil && !key.ExpiresAt.After(now) {
			continue
		}
		if issuer == nil {
			issuer, err = vault.TenantIssuer(ctx, q.secrets, tenantID)
			if errors.Is(err, vault.ErrNotFound) {
				return nil, taskrunner.Permanent(fmt.Errorf("the tenant's signing key is not in the vault: %w", err))
			}
			if err != nil {
				return nil, err
			}
		}
		dels, err := grant.Issue(issuer, key.ID, []did.DID{bucket}, actions[*key.Principal], key.ExpiresAt)
		if err != nil {
			return nil, fmt.Errorf("issuing the grants of %s: %w", key.ID, err)
		}
		fresh = append(fresh, dels...)
	}
	return fresh, nil
}
