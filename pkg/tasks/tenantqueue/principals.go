package tenantqueue

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"slices"

	s3bkt "github.com/fil-forge/libforge/commands/s3/bucket"

	"github.com/fil-forge/hilt/pkg/bucketpolicy"
	"github.com/fil-forge/hilt/pkg/store"
	"github.com/fil-forge/hilt/pkg/store/accesskey"
	"github.com/fil-forge/hilt/pkg/tasks"
	"github.com/fil-forge/hilt/pkg/tasks/revocationqueue"
	"github.com/fil-forge/hilt/pkg/tasks/tenantqueue/datamodel"
	"github.com/fil-forge/libforge/taskrunner"
	"github.com/fil-forge/ucantone/did"
	"go.uber.org/zap"
)

// RemovePrincipalSpec returns the queue-tenant.remove-principal task that
// removes the tenant's principal. Its arguments are the principal's id.
func RemovePrincipalSpec(tenant did.DID, principal string) taskrunner.Spec {
	return taskrunner.Spec{
		Queue:   tasks.QueueTenant,
		Subject: tenant.String(),
		Action:  tasks.ActionRemovePrincipal,
		Args:    []byte(principal),
	}
}

// DecodeRemovePrincipalResult returns the access keys a
// queue-tenant.remove-principal task deleted, from its result. An empty
// result, which a task that found no principal leaves, is no keys.
func DecodeRemovePrincipalResult(result []byte) ([]did.DID, error) {
	if len(result) == 0 {
		return nil, nil
	}
	var model datamodel.RemovePrincipalResult
	if err := model.UnmarshalCBOR(bytes.NewReader(result)); err != nil {
		return nil, fmt.Errorf("decoding the result of %s.%s: %w", tasks.QueueTenant, tasks.ActionRemovePrincipal, err)
	}
	return model.Keys, nil
}

// runRemovePrincipal is queue-tenant.remove-principal. It removes the subject
// tenant's principal named in the task's arguments, and reports the access
// keys it deleted ([DecodeRemovePrincipalResult]), whose secrets are the
// caller's to remove from the vault. A principal the tenant does not have,
// or has removed, is left alone and the task succeeds with no keys, which is
// also what a second run of a task that committed does.
//
// Everything it writes commits together:
//
//   - The principal leaves every statement naming it. A statement left with
//     no principal is deleted, and a policy left with no statement is
//     removed. Each rewritten policy changes the other principals' grants
//     over its bucket as a policy write does ([Queue.policyWrites]). A policy
//     that reaches the principal only through the wildcard is left as it is:
//     the wildcard names the tenant's principals, and this one stops being
//     one.
//   - Every delegation the tenant issued to one of the principal's keys
//     leaves the delegation store and is recorded as a revocation owed, and
//     the keys are deleted.
//   - The principal is tombstoned, so that a later creation under the same
//     id revives it with no keys and named in no statement.
//   - The publishing of the revocations is queued.
//
// It fails for good when grants are to be issued to another principal's keys
// and the tenant's signing key is not in the vault.
func (q *Queue) runRemovePrincipal(ctx context.Context, ex *taskrunner.Exec, t taskrunner.Task) ([]byte, error) {
	tenantID, err := did.Parse(t.Subject)
	if err != nil {
		return nil, taskrunner.Permanent(fmt.Errorf("parsing the tenant in the task's subject: %w", err))
	}
	principalID := string(t.Args)
	if principalID == "" {
		return nil, taskrunner.Permanent(errors.New("the task's arguments name no principal"))
	}
	log := q.logger.With(zap.Stringer("tenant", tenantID), zap.Stringer("task", t.ID), zap.String("principal", principalID))

	if _, err := q.principals.Get(ctx, tenantID, principalID); errors.Is(err, store.ErrRecordNotFound) {
		return nil, nil
	} else if err != nil {
		return nil, fmt.Errorf("looking up the principal: %w", err)
	}
	named, err := q.policies.ListByPrincipal(ctx, tenantID, principalID)
	if err != nil {
		return nil, fmt.Errorf("listing the policies naming the principal: %w", err)
	}
	keys, err := q.accessKeys.ListByTenant(ctx, tenantID, accesskey.WithPrincipal(principalID))
	if err != nil {
		return nil, fmt.Errorf("listing the principal's access keys: %w", err)
	}

	var writes []store.Statement
	affected := len(keys) > 0
	issued, rewritten := 0, 0
	var others []string
	for _, rec := range named {
		doc, changed := bucketpolicy.RemovePrincipal(rec.Policy, principalID)
		if !changed {
			continue
		}
		if others == nil {
			all, err := q.principals.ListIDsByTenant(ctx, tenantID)
			if err != nil {
				return nil, fmt.Errorf("listing the tenant's principals: %w", err)
			}
			others = slices.DeleteFunc(all, func(p string) bool { return p == principalID })
		}
		var next *s3bkt.PolicyDocument
		if len(doc.Statements) > 0 {
			next = &doc
		}
		change, err := q.policyWrites(ctx, tenantID, rec.Bucket, &rec, next, others)
		if err != nil {
			return nil, err
		}
		writes = append(writes, change.writes...)
		affected = affected || change.affected
		issued += change.issued
		rewritten++
	}

	result := datamodel.RemovePrincipalResult{Keys: make([]did.DID, len(keys))}
	for i, key := range keys {
		result.Keys[i] = key.ID
		writes = append(writes,
			q.delegations.WithdrawGrantsOfKeyStatement(tenantID, key.ID),
			q.accessKeys.DeleteStatement(tenantID, key.ID),
		)
	}
	writes = append(writes, q.principals.TombstoneStatement(tenantID, principalID))
	if err := record(ctx, ex, writes); err != nil {
		return nil, err
	}
	if affected {
		// How many grants the commit withdraws is not known here, so the
		// publish is queued for any change to a key's grants and finds
		// nothing when none were.
		if _, err := ex.Submit(ctx, revocationqueue.PublishSpec(tenantID)); err != nil {
			return nil, fmt.Errorf("queueing the publishing of the tenant's revocations: %w", err)
		}
	}

	var buf bytes.Buffer
	if err := result.MarshalCBOR(&buf); err != nil {
		return nil, taskrunner.Permanent(fmt.Errorf("encoding the result of %s.%s: %w", tasks.QueueTenant, tasks.ActionRemovePrincipal, err))
	}
	log.Info("removing a principal", zap.Int("access_keys", len(keys)), zap.Int("policies_rewritten", rewritten), zap.Int("grants_issued", issued))
	return buf.Bytes(), nil
}
