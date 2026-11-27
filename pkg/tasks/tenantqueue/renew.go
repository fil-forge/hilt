package tenantqueue

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/fil-forge/hilt/pkg/grant"
	"github.com/fil-forge/hilt/pkg/store"
	"github.com/fil-forge/hilt/pkg/store/accesskey"
	"github.com/fil-forge/hilt/pkg/store/tenant"
	"github.com/fil-forge/hilt/pkg/tasks"
	"github.com/fil-forge/libforge/taskrunner"
	"github.com/fil-forge/ucantone/did"
	"go.uber.org/zap"
)

// RenewGrantsSpec returns the queue-tenant.renew-grants task for the tenant.
// It takes no arguments: the task finds the keys to renew when it runs.
func RenewGrantsSpec(tenantID did.DID) taskrunner.Spec {
	return taskrunner.Spec{
		Queue:   tasks.QueueTenant,
		Subject: tenantID.String(),
		Action:  tasks.ActionRenewGrants,
	}
}

// runRenewGrants is queue-tenant.renew-grants. Every grant expires
// ([grant.Lifetime]), and this issues the next ones: each access key of the
// subject tenant that holds a grant expiring within [grant.RenewBefore] is
// stored the whole set its creation would issue it under the tenant's status
// ([grant.ForKey]), lasting a full lifetime from now.
//
// Nothing is withdrawn, so nothing is revoked. The grants a key held stay
// stored until they expire, and a later change that withdraws the key's
// grants revokes them with the new ones, so a gateway that cached either set
// hears of it. Until then the key's proof chains go through the new set,
// which lasts longer (delegation.Store.ProofChain).
//
// It succeeds without writing when no key has a grant due, which is also
// what a second run of a task that committed finds, and when the tenant is
// gone or disabled, whose keys hold no grants.
//
// Every other change to the tenant's keys, grants, policies and buckets is a
// task on the same subject, so what it reads here stands at the commit.
func (q *Queue) runRenewGrants(ctx context.Context, ex *taskrunner.Exec, t taskrunner.Task) ([]byte, error) {
	tenantID, err := did.Parse(t.Subject)
	if err != nil {
		return nil, taskrunner.Permanent(fmt.Errorf("parsing the tenant in the task's subject: %w", err))
	}
	log := q.logger.With(zap.Stringer("tenant", tenantID), zap.Stringer("task", t.ID))

	rec, err := q.tenants.Get(ctx, tenantID)
	if errors.Is(err, store.ErrRecordNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("looking up the tenant: %w", err)
	}
	if rec.Status == tenant.Disabled {
		return nil, nil
	}

	due, err := q.delegations.KeysWithGrantsDue(ctx, tenantID, time.Now().Add(grant.RenewBefore))
	if err != nil {
		return nil, fmt.Errorf("finding the keys whose grants are due: %w", err)
	}
	if len(due) == 0 {
		return nil, nil
	}
	keys, err := q.accessKeys.ListByTenant(ctx, tenantID, accesskey.WithIDs(due...))
	if err != nil {
		return nil, fmt.Errorf("listing the keys whose grants are due: %w", err)
	}
	fresh, err := q.issueGrantsOf(ctx, tenantID, rec.Status, keys)
	if err != nil {
		return nil, err
	}
	if len(fresh) == 0 {
		return nil, nil
	}

	put, err := q.delegations.PutStatement(fresh)
	if err != nil {
		return nil, fmt.Errorf("building the write of the keys' grants: %w", err)
	}
	if err := ex.Write(ctx, put.SQL, put.Args...); err != nil {
		return nil, err
	}
	log.Info("renewing the tenant's grants", zap.Int("keys", len(keys)), zap.Int("grants_issued", len(fresh)))
	return nil, nil
}

// RenewalInterval is how often [Queue.RenewDue] is run.
const RenewalInterval = time.Hour

// RenewDue queues queue-tenant.renew-grants for every tenant that has a
// grant due for renewal and no such task pending, then deletes the
// delegations that have expired. It returns how many tasks it queued and how
// many delegations it deleted.
//
// A task that failed for good is not pending, so its tenant is queued again
// on the next call, for as long as its grants stay due.
func (q *Queue) RenewDue(ctx context.Context, r *taskrunner.Runner) (queued int, deleted int64, err error) {
	now := time.Now()
	due, err := q.delegations.TenantsWithGrantsDue(ctx, now.Add(grant.RenewBefore))
	if err != nil {
		return 0, 0, fmt.Errorf("finding the tenants whose grants are due: %w", err)
	}
	if len(due) > 0 {
		subjects := make([]string, len(due))
		for i, id := range due {
			subjects[i] = id.String()
		}
		pending, err := r.Pending(ctx, tasks.QueueTenant, subjects, taskrunner.WithActions(tasks.ActionRenewGrants))
		if err != nil {
			return 0, 0, fmt.Errorf("listing the renewals pending: %w", err)
		}
		var specs []taskrunner.Spec
		for _, id := range due {
			if len(pending[id.String()]) == 0 {
				specs = append(specs, RenewGrantsSpec(id))
			}
		}
		if len(specs) > 0 {
			if _, err := r.SubmitAll(ctx, specs); err != nil {
				return 0, 0, fmt.Errorf("queueing %d renewals: %w", len(specs), err)
			}
		}
		queued = len(specs)
	}
	if deleted, err = q.delegations.DeleteExpired(ctx, now); err != nil {
		return queued, 0, err
	}
	return queued, deleted, nil
}
