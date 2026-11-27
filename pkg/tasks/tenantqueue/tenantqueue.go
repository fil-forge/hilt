// Package tenantqueue is queue-tenant: the changes to what a tenant's access
// keys may do, on the subject of the tenant's DID, so that two changes to one
// tenant never run at once. Authorization waits for a tenant's unfinished
// tasks here before it answers for that tenant.
//
// queue-tenant.set-status changes a tenant's status. A change into or out of
// disabled also changes the grants the tenant's keys hold, in the same
// commit as the status:
//
//   - Into disabled, every delegation the tenant issued to one of its access
//     keys leaves the delegation store and is recorded as a revocation owed.
//   - Out of disabled, the same happens to whatever the keys hold, and each
//     key is issued the grants its creation would issue it now
//     ([grant.ForKey]).
//
// A change between active and write-locked sets the status alone.
//
// queue-tenant.create-key creates an access key: its row and the grants it
// holds, in one commit. queue-tenant.delete-key deletes one: the delegations
// the tenant issued to it leave the delegation store and are recorded as
// revocations owed, in the commit that deletes its row (keys.go).
//
// Every change that records revocations queues queue-revocation.publish for
// the tenant, which publishes them after the commit.
//
// Policy writes, principal removal and bucket and tenant deletion do not run
// here: they write the same keys and grants under row and advisory locks. A
// task therefore chooses the grants it withdraws in the statements its
// commit runs, under the keys' delegation locks, and never from what its
// handler read, and a task that issues grants from what it read makes its
// commit conditional on that still holding.
package tenantqueue

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/fil-forge/hilt/pkg/grant"
	"github.com/fil-forge/hilt/pkg/store"
	"github.com/fil-forge/hilt/pkg/store/accesskey"
	"github.com/fil-forge/hilt/pkg/store/bucket"
	"github.com/fil-forge/hilt/pkg/store/bucketpolicy"
	"github.com/fil-forge/hilt/pkg/store/delegation"
	"github.com/fil-forge/hilt/pkg/store/principal"
	"github.com/fil-forge/hilt/pkg/store/tenant"
	"github.com/fil-forge/hilt/pkg/tasks"
	"github.com/fil-forge/hilt/pkg/tasks/revocationqueue"
	"github.com/fil-forge/hilt/pkg/vault"
	"github.com/fil-forge/libforge/taskrunner"
	"github.com/fil-forge/ucantone/did"
	"github.com/fil-forge/ucantone/ucan"
	"go.uber.org/zap"
)

// ErrTenantNotFound is the outcome of a queue-tenant.set-status or
// queue-tenant.create-key task whose subject tenant does not exist.
var ErrTenantNotFound = errors.New("tenant not found")

// Deps is what the queue's handlers need.
type Deps struct {
	// Tenants holds the tenants and their statuses.
	Tenants tenant.Store
	// AccessKeys holds the tenants' access keys.
	AccessKeys accesskey.Store
	// Principals holds the principals a key can be bound to.
	Principals principal.Store
	// Buckets holds the buckets a service key can be scoped to.
	Buckets bucket.Store
	// Policies holds the bucket policies a principal-bound key's grants come
	// from.
	Policies bucketpolicy.Store
	// Delegations builds the writes that withdraw and store the keys' grants.
	Delegations delegation.Store
	// Secrets holds the tenants' signing keys.
	Secrets vault.Vault
	// Logger is optional; defaults to zap.NewNop().
	Logger *zap.Logger
}

// Queue runs queue-tenant.
type Queue struct {
	tenants     tenant.Store
	accessKeys  accesskey.Store
	principals  principal.Store
	buckets     bucket.Store
	policies    bucketpolicy.Store
	delegations delegation.Store
	secrets     vault.Vault
	logger      *zap.Logger
}

// New registers the queue's handlers with r, which must not have started.
func New(r *taskrunner.Runner, d Deps) (*Queue, error) {
	q := &Queue{
		tenants:     d.Tenants,
		accessKeys:  d.AccessKeys,
		principals:  d.Principals,
		buckets:     d.Buckets,
		policies:    d.Policies,
		delegations: d.Delegations,
		secrets:     d.Secrets,
		logger:      d.Logger,
	}
	if q.logger == nil {
		q.logger = zap.NewNop()
	}
	if err := r.Handle(tasks.QueueTenant, tasks.ActionSetStatus, q.runSetStatus); err != nil {
		return nil, fmt.Errorf("registering %s.%s: %w", tasks.QueueTenant, tasks.ActionSetStatus, err)
	}
	for action, h := range map[string]taskrunner.Handler{
		tasks.ActionCreateKey: q.runCreateKey,
		tasks.ActionDeleteKey: q.runDeleteKey,
	} {
		if err := r.Handle(tasks.QueueTenant, action, h); err != nil {
			return nil, fmt.Errorf("registering %s.%s: %w", tasks.QueueTenant, action, err)
		}
	}
	return q, nil
}

// SetStatusSpec returns the queue-tenant.set-status task that moves the
// tenant to status. Its arguments are the status and nothing else.
func SetStatusSpec(tenantID did.DID, status tenant.Status) taskrunner.Spec {
	return taskrunner.Spec{
		Queue:   tasks.QueueTenant,
		Subject: tenantID.String(),
		Action:  tasks.ActionSetStatus,
		Args:    []byte(status),
	}
}

// runSetStatus is queue-tenant.set-status. It moves the subject tenant to
// the status in the task's arguments, and succeeds without writing when the
// tenant has it already, which is also what makes a second run of a task
// that committed change nothing.
//
// Everything it writes commits together. A change into or out of disabled
// first withdraws every delegation the tenant issued to its keys, recording
// each as a revocation owed, and queues their publishing. A change out of
// disabled then stores fresh grants for every key: one created or rewritten
// while the tenant was disabled may hold some, and withdrawing first leaves
// each key with exactly one set. The status is written last, on the
// condition that it is still the one read here; when it is not, the commit
// fails and the task runs again from what is there then.
//
// It fails for good when the tenant is gone ([ErrTenantNotFound]), and when
// grants are to be issued and the tenant's signing key is not in the vault.
func (q *Queue) runSetStatus(ctx context.Context, ex *taskrunner.Exec, t taskrunner.Task) ([]byte, error) {
	tenantID, err := did.Parse(t.Subject)
	if err != nil {
		return nil, taskrunner.Permanent(fmt.Errorf("parsing the tenant in the task's subject: %w", err))
	}
	want := tenant.Status(t.Args)
	if !want.Valid() {
		return nil, taskrunner.Permanent(fmt.Errorf("invalid tenant status %q in the task's arguments", want))
	}
	log := q.logger.With(zap.Stringer("tenant", tenantID), zap.Stringer("task", t.ID), zap.String("status", string(want)))

	rec, err := q.tenants.Get(ctx, tenantID)
	if errors.Is(err, store.ErrRecordNotFound) {
		return nil, taskrunner.Permanent(ErrTenantNotFound)
	}
	if err != nil {
		return nil, fmt.Errorf("looking up the tenant: %w", err)
	}
	if rec.Status == want {
		return nil, nil
	}

	issued := 0
	if rec.Status == tenant.Disabled || want == tenant.Disabled {
		var fresh []ucan.Delegation
		if rec.Status == tenant.Disabled {
			if fresh, err = q.issueGrants(ctx, tenantID); err != nil {
				return nil, err
			}
			issued = len(fresh)
		}
		for _, st := range q.delegations.WithdrawKeyGrantsStatements(tenantID) {
			if err := ex.Write(ctx, st.SQL, st.Args...); err != nil {
				return nil, err
			}
		}
		if len(fresh) > 0 {
			st, err := q.delegations.PutForKeysStatement(fresh)
			if err != nil {
				return nil, fmt.Errorf("building the write of the keys' grants: %w", err)
			}
			if err := ex.Write(ctx, st.SQL, st.Args...); err != nil {
				return nil, err
			}
		}
		// How many grants the commit withdraws is not known here, so the
		// publish is queued either way and finds nothing when none were.
		if _, err := ex.Submit(ctx, revocationqueue.PublishSpec(tenantID)); err != nil {
			return nil, fmt.Errorf("queueing the publishing of the tenant's revocations: %w", err)
		}
	}

	st, err := q.tenants.SetStatusStatement(tenantID, rec.Status, want)
	if err != nil {
		return nil, taskrunner.Permanent(err)
	}
	if err := ex.WriteConditional(ctx, st.SQL, st.Args...); err != nil {
		return nil, err
	}
	log.Info("changing the tenant's status", zap.String("from", string(rec.Status)), zap.Int("grants_issued", issued))
	return nil, nil
}

// issueGrants issues, signed by the tenant, the grants every access key of
// the tenant holds: what [grant.ForKey] gives each from its stored
// permissions and buckets, or from the tenant's bucket policies as they are
// now. The policies are read once for each principal that has a key. A key
// that has expired authenticates no request and is issued nothing.
func (q *Queue) issueGrants(ctx context.Context, tenantID did.DID) ([]ucan.Delegation, error) {
	keys, err := q.accessKeys.ListByTenant(ctx, tenantID)
	if err != nil {
		return nil, fmt.Errorf("listing the tenant's access keys: %w", err)
	}
	if len(keys) == 0 {
		return nil, nil
	}

	now := time.Now()
	policies := map[string][]bucketpolicy.Record{}
	// The signing key is read for the first key that is to be issued grants,
	// so a tenant with none to issue needs no signing key.
	var issuer ucan.Issuer
	var fresh []ucan.Delegation
	for _, key := range keys {
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
		var named []bucketpolicy.Record
		if key.Principal != nil {
			var read bool
			if named, read = policies[*key.Principal]; !read {
				if named, err = q.policies.ListByPrincipal(ctx, tenantID, *key.Principal); err != nil {
					return nil, fmt.Errorf("listing the policies naming a principal: %w", err)
				}
				policies[*key.Principal] = named
			}
		}
		dels, err := grant.ForKey(issuer, key, named)
		if err != nil {
			return nil, fmt.Errorf("issuing the grants of %s: %w", key.ID, err)
		}
		fresh = append(fresh, dels...)
	}
	return fresh, nil
}
