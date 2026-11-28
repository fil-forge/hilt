// Package tenantqueue is queue-tenant: the changes to what a tenant's access
// keys may do, on the subject of the tenant's DID, so that two changes to one
// tenant never run at once. Authorization waits for a tenant's unfinished
// tasks here before it answers for that tenant.
//
// queue-tenant.set-status changes a tenant's status. What the tenant's keys
// may do differs in every status, so every change also replaces the grants
// they hold, in the same commit as the status:
//
//   - Every delegation the tenant issued to one of its access keys leaves
//     the delegation store and is recorded as a revocation owed.
//   - Each key is issued the grants its creation would issue it under the
//     new status ([grant.ForKey]): the full set when the tenant becomes
//     active, the grants of its reads, listings and deletions when it
//     becomes write-locked ([grant.LimitToTenantStatus]), and none when it
//     becomes disabled.
//
// queue-tenant.create-key creates an access key: its row and the grants it
// holds under the tenant's status, in one commit. queue-tenant.delete-key deletes one: the delegations
// the tenant issued to it leave the delegation store and are recorded as
// revocations owed, in the commit that deletes its row (keys.go).
//
// queue-tenant.put-policy writes a bucket's policy and
// queue-tenant.delete-policy removes one. In the commit that writes the
// document, every access key of each principal whose effective actions on
// the bucket change has its grants over the bucket withdrawn, recorded as
// revocations owed, and is stored the grants of the new document under the
// tenant's status (policies.go).
//
// queue-tenant.remove-principal removes a principal: in one commit it strips
// the principal from every policy naming it, changing the other principals'
// grants over each bucket as a policy write does, withdraws every grant of
// the principal's keys, deletes the keys and tombstones the principal
// (principals.go). queue-tenant.delete-bucket deletes an empty bucket: in
// one commit it withdraws every grant the tenant issued over the bucket and
// deletes the bucket's delegations and the bucket, which takes its policy
// (buckets.go).
//
// queue-tenant.renew-grants issues the keys whose grants are close to
// expiring the next set, and withdraws nothing (renew.go).
//
// Every change that records revocations queues queue-revocation.publish for
// the tenant, which publishes them after the commit.
//
// queue-tenant.delete-tenant deletes a disabled tenant: it publishes the
// revocations the tenant owes and those of every grant its keys hold,
// deactivates the tenant's DID, removes its keys from the vault, and in one
// commit deletes every row Hilt holds for it (tenants.go). A task queued
// for the tenant behind it finds the tenant, or what it names, gone.
//
// Every change to what a tenant's keys may do is a task here, so none runs
// between a handler's reads and its commit, and a handler decides from what
// it read.
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
	"github.com/fil-forge/hilt/pkg/store/bucket"
	"github.com/fil-forge/hilt/pkg/store/bucketpolicy"
	"github.com/fil-forge/hilt/pkg/store/delegation"
	"github.com/fil-forge/hilt/pkg/store/principal"
	"github.com/fil-forge/hilt/pkg/store/tenant"
	"github.com/fil-forge/hilt/pkg/store/wrapkey"
	"github.com/fil-forge/hilt/pkg/tasks"
	"github.com/fil-forge/hilt/pkg/tasks/revocationqueue"
	"github.com/fil-forge/hilt/pkg/vault"
	"github.com/fil-forge/libforge/taskrunner"
	"github.com/fil-forge/ucantone/did"
	"github.com/fil-forge/ucantone/ucan"
	"go.uber.org/zap"
)

// ErrTenantNotFound is the outcome of a queue-tenant.set-status or
// queue-tenant.create-key task, or of a policy change that issues grants,
// whose subject tenant does not exist, as after its deletion.
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
	// WrapKeys holds the tenants' wrap key records, which tenant deletion
	// removes with their vault entries.
	WrapKeys wrapkey.Store
	// Secrets holds the tenants' signing keys, and the vault entries tenant
	// deletion removes.
	Secrets vault.Vault
	// Directory is the did:plc directory tenant deletion deactivates the
	// tenant's DID in. Nil fails every tenant deletion.
	Directory Directory
	// Publisher is the revocation service tenant deletion publishes the
	// revocations of the tenant's keys' grants to. Nil fails every tenant
	// deletion.
	Publisher grant.RevocationPublisher
	// Grants is how long the grants the queue issues last and how far ahead
	// of their expiry they are renewed. The zero value is
	// [grant.DefaultTiming].
	Grants grant.Timing
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
	wrapKeys    wrapkey.Store
	secrets     vault.Vault
	directory   Directory
	publisher   grant.RevocationPublisher
	timing      grant.Timing
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
		wrapKeys:    d.WrapKeys,
		secrets:     d.Secrets,
		directory:   d.Directory,
		publisher:   d.Publisher,
		timing:      d.Grants,
		logger:      d.Logger,
	}
	if q.logger == nil {
		q.logger = zap.NewNop()
	}
	if q.timing == (grant.Timing{}) {
		q.timing = grant.DefaultTiming
	}
	if err := q.timing.Validate(); err != nil {
		return nil, err
	}
	if err := r.Handle(tasks.QueueTenant, tasks.ActionSetStatus, q.runSetStatus); err != nil {
		return nil, fmt.Errorf("registering %s.%s: %w", tasks.QueueTenant, tasks.ActionSetStatus, err)
	}
	for action, h := range map[string]taskrunner.Handler{
		tasks.ActionCreateKey:       q.runCreateKey,
		tasks.ActionDeleteKey:       q.runDeleteKey,
		tasks.ActionPutPolicy:       q.runPutPolicy,
		tasks.ActionDeletePolicy:    q.runDeletePolicy,
		tasks.ActionRemovePrincipal: q.runRemovePrincipal,
		tasks.ActionDeleteBucket:    q.runDeleteBucket,
		tasks.ActionDeleteTenant:    q.runDeleteTenant,
		tasks.ActionRenewGrants:     q.runRenewGrants,
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
// Everything it writes commits together. It first withdraws every
// delegation the tenant issued to its keys, recording each as a revocation
// owed, and queues their publishing. Unless the tenant is being disabled it
// then stores, for every key, the grants the new status gives it;
// withdrawing first leaves each key with exactly one set, whatever it held.
// The status is written last, on the condition that it is still the one
// read here; when it is not, the commit fails and the task runs again from
// what is there then.
//
// The grants are issued afresh on every change, a change to active from
// write-locked included: the ones withdrawn are revoked, and a revoked
// delegation is never stored again.
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

	var fresh []ucan.Delegation
	if want != tenant.Disabled {
		if fresh, err = q.issueGrants(ctx, tenantID, want); err != nil {
			return nil, err
		}
	}
	withdraw := q.delegations.WithdrawKeyGrantsStatement(tenantID)
	if err := ex.Write(ctx, withdraw.SQL, withdraw.Args...); err != nil {
		return nil, err
	}
	if len(fresh) > 0 {
		st, err := q.delegations.PutStatement(fresh)
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

	st, err := q.tenants.SetStatusStatement(tenantID, rec.Status, want)
	if err != nil {
		return nil, taskrunner.Permanent(err)
	}
	if err := ex.WriteConditional(ctx, st.SQL, st.Args...); err != nil {
		return nil, err
	}
	log.Info("changing the tenant's status", zap.String("from", string(rec.Status)), zap.Int("grants_issued", len(fresh)))
	return nil, nil
}

// issueGrants issues, signed by the tenant, the grants every access key of
// the tenant holds while the tenant has the status: what [grant.ForKey]
// gives each from its stored permissions and buckets, or from the tenant's
// bucket policies as they are now. The policies are read once for each
// principal that has a key. A key that has expired authenticates no request
// and is issued nothing.
func (q *Queue) issueGrants(ctx context.Context, tenantID did.DID, status tenant.Status) ([]ucan.Delegation, error) {
	keys, err := q.accessKeys.ListByTenant(ctx, tenantID)
	if err != nil {
		return nil, fmt.Errorf("listing the tenant's access keys: %w", err)
	}
	return q.issueGrantsOf(ctx, tenantID, status, keys)
}

// issueGrantsOf is [Queue.issueGrants] for the given keys of the tenant.
//
// A service key's bucket list still names a bucket that has been deleted:
// deleting a bucket withdraws the grants over it and leaves the lists alone.
// Such a bucket is left out, so a grant withdrawn by the deletion is never
// issued again, and a key whose buckets are all gone is issued nothing. It is
// never issued powerline grants, which an empty list would give it.
func (q *Queue) issueGrantsOf(ctx context.Context, tenantID did.DID, status tenant.Status, keys []accesskey.Record) ([]ucan.Delegation, error) {
	if len(keys) == 0 {
		return nil, nil
	}
	live, err := q.liveBuckets(ctx, tenantID, keys)
	if err != nil {
		return nil, err
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
		if key.Principal == nil && len(key.Buckets) > 0 {
			key.Buckets = slices.DeleteFunc(slices.Clone(key.Buckets), func(b did.DID) bool { return !live[b] })
			if len(key.Buckets) == 0 {
				continue
			}
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
		dels, err := grant.ForKey(issuer, status, key, named, grant.WithLifetime(q.timing.Lifetime))
		if err != nil {
			return nil, fmt.Errorf("issuing the grants of %s: %w", key.ID, err)
		}
		fresh = append(fresh, dels...)
	}
	return fresh, nil
}

// liveBuckets reports which of the buckets the service keys among keys are
// scoped to the tenant still has.
func (q *Queue) liveBuckets(ctx context.Context, tenantID did.DID, keys []accesskey.Record) (map[did.DID]bool, error) {
	var ids []did.DID
	for _, key := range keys {
		if key.Principal == nil {
			ids = append(ids, key.Buckets...)
		}
	}
	live := make(map[did.DID]bool, len(ids))
	if len(ids) == 0 {
		return live, nil
	}
	recs, err := store.Collect(ctx, func(ctx context.Context, opts store.PaginationConfig) (store.Page[bucket.Record], error) {
		listOpts := []bucket.ListOption{bucket.WithIDs(ids...)}
		if opts.Cursor != nil {
			listOpts = append(listOpts, bucket.WithCursor(*opts.Cursor))
		}
		return q.buckets.ListByTenant(ctx, tenantID, listOpts...)
	})
	if err != nil {
		return nil, fmt.Errorf("looking up the keys' buckets: %w", err)
	}
	for _, b := range recs {
		live[b.ID] = true
	}
	return live, nil
}
