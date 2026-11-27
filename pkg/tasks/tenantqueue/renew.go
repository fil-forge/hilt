package tenantqueue

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/fil-forge/hilt/pkg/grant"
	"github.com/fil-forge/hilt/pkg/store"
	"github.com/fil-forge/hilt/pkg/store/accesskey"
	"github.com/fil-forge/hilt/pkg/store/delegation"
	"github.com/fil-forge/hilt/pkg/store/tenant"
	"github.com/fil-forge/hilt/pkg/tasks"
	"github.com/fil-forge/libforge/taskrunner"
	"github.com/fil-forge/ucantone/did"
	"github.com/fil-forge/ucantone/ucan"
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

	due, err := q.delegations.GrantsDue(ctx, tenantID, time.Now().Add(grant.RenewBefore))
	if err != nil {
		return nil, fmt.Errorf("finding the keys whose grants are due: %w", err)
	}
	if len(due) == 0 {
		return nil, nil
	}
	var ids []did.DID
	for _, d := range due {
		if !slices.Contains(ids, d.Key) {
			ids = append(ids, d.Key)
		}
	}
	keys, err := q.accessKeys.ListByTenant(ctx, tenantID, accesskey.WithIDs(ids...))
	if err != nil {
		return nil, fmt.Errorf("listing the keys whose grants are due: %w", err)
	}
	fresh, err := q.issueGrantsOf(ctx, tenantID, rec.Status, keys)
	if err != nil {
		return nil, err
	}
	warnUnrenewed(log, keys, due, fresh)
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

// warnUnrenewed logs each live key and subject whose grants were due and that
// the renewal issued nothing over. Every write that takes a subject from a
// key withdraws its grants there, so such grants should not exist; they stay
// due, are never deleted, and the key is issued a whole new set on every
// pass. The log is repeated on each pass, so a cause such as a change to how
// keys' grants are derived shows up while it lasts.
func warnUnrenewed(log *zap.Logger, keys []accesskey.Record, due []delegation.DueGrant, fresh []ucan.Delegation) {
	now := time.Now()
	live := make(map[did.DID]bool, len(keys))
	for _, key := range keys {
		live[key.ID] = key.ExpiresAt == nil || key.ExpiresAt.After(now)
	}
	type held struct{ key, subject did.DID }
	issued := make(map[held]bool, len(fresh))
	for _, d := range fresh {
		issued[held{d.Audience(), d.Subject()}] = true
	}
	for _, d := range due {
		if live[d.Key] && !issued[held{d.Key, d.Subject}] {
			log.Warn("grants due for renewal were not issued again",
				zap.Stringer("access_key", d.Key), zap.Stringer("subject", d.Subject))
		}
	}
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
