package tenantqueue

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/fil-forge/hilt/pkg/grant"
	"github.com/fil-forge/hilt/pkg/s3perm"
	"github.com/fil-forge/hilt/pkg/store"
	"github.com/fil-forge/hilt/pkg/store/accesskey"
	"github.com/fil-forge/hilt/pkg/store/bucket"
	"github.com/fil-forge/hilt/pkg/store/bucketpolicy"
	"github.com/fil-forge/hilt/pkg/store/tenant"
	"github.com/fil-forge/hilt/pkg/tasks"
	"github.com/fil-forge/hilt/pkg/tasks/revocationqueue"
	"github.com/fil-forge/hilt/pkg/tasks/tenantqueue/datamodel"
	"github.com/fil-forge/hilt/pkg/vault"
	"github.com/fil-forge/libforge/taskrunner"
	"github.com/fil-forge/ucantone/did"
	"go.uber.org/zap"
)

// MaxKeyNameLength is the longest name an access key may have, in bytes.
const MaxKeyNameLength = 64

// The reasons a queue-tenant.create-key task refuses to create its key. Each
// fails the task for good.
var (
	// ErrTenantDisabled is a key for a disabled tenant. Nothing a disabled
	// tenant's key holds can be used, and a disabled tenant is on its way to
	// deletion.
	ErrTenantDisabled = errors.New("tenant is disabled")
	// ErrInvalidKeyName is a name that is empty or longer than
	// [MaxKeyNameLength].
	ErrInvalidKeyName = errors.New("access key name must be between 1 and 64 characters")
	// ErrNoPermissions is a service key with no permissions.
	ErrNoPermissions = errors.New("a service key needs at least one permission")
	// ErrInvalidPermission is a service key with a permission that is not an
	// S3 permission the service knows. It is wrapped with the permission.
	ErrInvalidPermission = errors.New("unknown permission")
	// ErrPrincipalScoped is a principal-bound key with permissions or buckets
	// of its own.
	ErrPrincipalScoped = errors.New("a principal-bound access key takes no permissions or buckets")
	// ErrUnknownPrincipal is a key bound to a principal the tenant does not
	// have, or has removed.
	ErrUnknownPrincipal = errors.New("unknown principal")
	// ErrUnknownBucket is a service key scoped to a bucket the tenant does
	// not have. The task's error is an [*UnknownBucketError], which names it.
	ErrUnknownBucket = errors.New("unknown bucket")
	// ErrKeyNameTaken is a key whose name another key already has: a service
	// key of the tenant for a service key, a key of the same principal for a
	// principal-bound one.
	ErrKeyNameTaken = errors.New("an access key with this name already exists")
)

// UnknownBucketError is the [ErrUnknownBucket] of one bucket.
type UnknownBucketError struct {
	// Bucket is the bucket the tenant does not have.
	Bucket did.DID
}

func (e *UnknownBucketError) Error() string {
	return fmt.Sprintf("%s: %s", ErrUnknownBucket, e.Bucket)
}

func (e *UnknownBucketError) Is(target error) bool { return target == ErrUnknownBucket }

// CreateKeySpec returns the queue-tenant.create-key task that creates the
// access key for its tenant. The arguments are the key as given and nothing
// else: the key's secret has no field in them, and the caller writes it to
// the vault itself before it submits the task. Times are kept to the
// microsecond, as the key's row keeps them. A zero CreatedAt is the time of
// the call.
func CreateKeySpec(key accesskey.Input) (taskrunner.Spec, error) {
	if err := key.Validate(); err != nil {
		return taskrunner.Spec{}, err
	}
	created := key.CreatedAt
	if created.IsZero() {
		created = time.Now()
	}
	args := datamodel.CreateKeyArgs{
		Key:         key.ID,
		Name:        key.Name,
		Permissions: key.Permissions,
		Buckets:     key.Buckets,
		Principal:   key.Principal,
		CreatedAt:   created.UnixMicro(),
	}
	if key.ExpiresAt != nil {
		micros := key.ExpiresAt.UnixMicro()
		args.ExpiresAt = &micros
	}
	var buf bytes.Buffer
	if err := args.MarshalCBOR(&buf); err != nil {
		return taskrunner.Spec{}, fmt.Errorf("encoding the arguments of %s.%s: %w", tasks.QueueTenant, tasks.ActionCreateKey, err)
	}
	return taskrunner.Spec{
		Queue:   tasks.QueueTenant,
		Subject: key.Tenant.String(),
		Action:  tasks.ActionCreateKey,
		Args:    buf.Bytes(),
	}, nil
}

// DecodeCreateKey returns the access key a queue-tenant.create-key task
// creates for tenant, from the task's arguments.
func DecodeCreateKey(tenant did.DID, args []byte) (accesskey.Input, error) {
	var model datamodel.CreateKeyArgs
	if err := model.UnmarshalCBOR(bytes.NewReader(args)); err != nil {
		return accesskey.Input{}, fmt.Errorf("decoding the arguments of %s.%s: %w", tasks.QueueTenant, tasks.ActionCreateKey, err)
	}
	key := accesskey.Input{
		ID:          model.Key,
		Tenant:      tenant,
		Name:        model.Name,
		Buckets:     model.Buckets,
		Permissions: model.Permissions,
		Principal:   model.Principal,
		CreatedAt:   time.UnixMicro(model.CreatedAt).UTC(),
	}
	if model.ExpiresAt != nil {
		expires := time.UnixMicro(*model.ExpiresAt).UTC()
		key.ExpiresAt = &expires
	}
	return key, nil
}

// DeleteKeySpec returns the queue-tenant.delete-key task that deletes the
// tenant's access key. Its arguments are the key's DID.
func DeleteKeySpec(tenant, key did.DID) taskrunner.Spec {
	return taskrunner.Spec{
		Queue:   tasks.QueueTenant,
		Subject: tenant.String(),
		Action:  tasks.ActionDeleteKey,
		Args:    []byte(key.String()),
	}
}

// runCreateKey is queue-tenant.create-key. It creates the access key in the
// task's arguments for the subject tenant: the key's row and the grants
// [grant.ForKey] gives it under the tenant's status, in one commit, so a key
// created for a write-locked tenant holds the grants of its reads, listings
// and deletions alone until the tenant is active again. The key's secret is
// the caller's to write to the vault before it submits the task, and to
// remove when the task fails.
//
// Every failure is final, and is marked so ([taskrunner.Permanent]). The
// caller alone holds the secret, so the creation is never finished by a
// later run on its behalf: the caller is told, and creates another key.
func (q *Queue) runCreateKey(ctx context.Context, ex *taskrunner.Exec, t taskrunner.Task) ([]byte, error) {
	return nil, taskrunner.Permanent(q.createKey(ctx, ex, t))
}

// createKey refuses a key that is invalid in itself, a disabled or missing
// tenant ([ErrTenantDisabled], [ErrTenantNotFound]), a name already taken
// ([ErrKeyNameTaken]), a principal the tenant does not have
// ([ErrUnknownPrincipal]) and a bucket it does not have
// ([*UnknownBucketError]). Every other change to the tenant's keys,
// principals, buckets and policies is a task on the same subject, so none
// runs between these reads and the commit, and the reads decide.
func (q *Queue) createKey(ctx context.Context, ex *taskrunner.Exec, t taskrunner.Task) error {
	tenantID, err := did.Parse(t.Subject)
	if err != nil {
		return fmt.Errorf("parsing the tenant in the task's subject: %w", err)
	}
	key, err := DecodeCreateKey(tenantID, t.Args)
	if err != nil {
		return err
	}
	if err := checkNewKey(key); err != nil {
		return err
	}
	log := q.logger.With(zap.Stringer("tenant", tenantID), zap.Stringer("task", t.ID), zap.Stringer("access_key", key.ID))

	rec, err := q.tenants.Get(ctx, tenantID)
	if errors.Is(err, store.ErrRecordNotFound) {
		return ErrTenantNotFound
	}
	if err != nil {
		return fmt.Errorf("looking up the tenant: %w", err)
	}
	if rec.Status == tenant.Disabled {
		return ErrTenantDisabled
	}

	taken, err := q.accessKeys.HasName(ctx, tenantID, key.Principal, key.Name)
	if err != nil {
		return err
	}
	if taken {
		return ErrKeyNameTaken
	}

	var policies []bucketpolicy.Record
	if key.Principal != nil {
		if _, err := q.principals.Get(ctx, tenantID, *key.Principal); errors.Is(err, store.ErrRecordNotFound) {
			return ErrUnknownPrincipal
		} else if err != nil {
			return fmt.Errorf("looking up the principal: %w", err)
		}
		if policies, err = q.policies.ListByPrincipal(ctx, tenantID, *key.Principal); err != nil {
			return fmt.Errorf("listing the policies naming the principal: %w", err)
		}
	} else if err := q.checkBuckets(ctx, tenantID, key.Buckets); err != nil {
		return err
	}

	issuer, err := vault.TenantIssuer(ctx, q.secrets, tenantID)
	if err != nil {
		return err
	}
	dels, err := grant.ForKey(issuer, rec.Status, accesskey.Record{
		ID:          key.ID,
		Buckets:     key.Buckets,
		Permissions: key.Permissions,
		Principal:   key.Principal,
		ExpiresAt:   key.ExpiresAt,
	}, policies, grant.WithLifetime(q.timing.Lifetime))
	if err != nil {
		return fmt.Errorf("issuing the key's grants: %w", err)
	}

	add, err := q.accessKeys.AddStatement(key)
	if err != nil {
		return fmt.Errorf("building the write of the key: %w", err)
	}
	if err := ex.Write(ctx, add.SQL, add.Args...); err != nil {
		return err
	}
	if len(dels) > 0 {
		put, err := q.delegations.PutStatement(dels)
		if err != nil {
			return fmt.Errorf("building the write of the key's grants: %w", err)
		}
		if err := ex.Write(ctx, put.SQL, put.Args...); err != nil {
			return err
		}
	}
	log.Info("creating an access key", zap.Int("grants_issued", len(dels)))
	return nil
}

// checkNewKey refuses a key whose own fields rule it out, whatever the
// tenant holds.
func checkNewKey(key accesskey.Input) error {
	if key.Name == "" || len(key.Name) > MaxKeyNameLength {
		return ErrInvalidKeyName
	}
	if key.Principal != nil {
		if len(key.Permissions) > 0 || len(key.Buckets) > 0 {
			return ErrPrincipalScoped
		}
		return nil
	}
	if len(key.Permissions) == 0 {
		return ErrNoPermissions
	}
	for _, p := range key.Permissions {
		if !s3perm.Valid(p) {
			return fmt.Errorf("%w: %s", ErrInvalidPermission, p)
		}
	}
	return nil
}

// checkBuckets returns an [*UnknownBucketError] for the first of ids that is
// not a bucket of the tenant.
func (q *Queue) checkBuckets(ctx context.Context, tenantID did.DID, ids []did.DID) error {
	if len(ids) == 0 {
		return nil
	}
	recs, err := store.Collect(ctx, func(ctx context.Context, opts store.PaginationConfig) (store.Page[bucket.Record], error) {
		listOpts := []bucket.ListOption{bucket.WithIDs(ids...)}
		if opts.Cursor != nil {
			listOpts = append(listOpts, bucket.WithCursor(*opts.Cursor))
		}
		return q.buckets.ListByTenant(ctx, tenantID, listOpts...)
	})
	if err != nil {
		return fmt.Errorf("looking up the key's buckets: %w", err)
	}
	found := make(map[did.DID]bool, len(recs))
	for _, b := range recs {
		found[b.ID] = true
	}
	for _, id := range ids {
		if !found[id] {
			return &UnknownBucketError{Bucket: id}
		}
	}
	return nil
}

// runDeleteKey is queue-tenant.delete-key. In one commit it takes the
// delegations the tenant issued to the key out of the delegation store,
// records each as a revocation owed, deletes the key's row and queues the
// publishing of the revocations. A key the tenant does not have is left
// alone and the task succeeds, which is also what a second run of a task
// that committed does.
//
// The grants are chosen by the commit's statement
// (delegation.Store.WithdrawGrantsOfKeyStatement), so the task withdraws
// what the key holds when it commits.
func (q *Queue) runDeleteKey(ctx context.Context, ex *taskrunner.Exec, t taskrunner.Task) ([]byte, error) {
	tenantID, err := did.Parse(t.Subject)
	if err != nil {
		return nil, taskrunner.Permanent(fmt.Errorf("parsing the tenant in the task's subject: %w", err))
	}
	keyID, err := did.Parse(string(t.Args))
	if err != nil {
		return nil, taskrunner.Permanent(fmt.Errorf("parsing the access key in the task's arguments: %w", err))
	}
	rec, err := q.accessKeys.Get(ctx, keyID)
	if errors.Is(err, store.ErrRecordNotFound) || (err == nil && rec.Tenant != tenantID) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("looking up the access key: %w", err)
	}

	for _, st := range []store.Statement{
		q.delegations.WithdrawGrantsOfKeyStatement(tenantID, keyID),
		q.accessKeys.DeleteStatement(tenantID, keyID),
	} {
		if err := ex.Write(ctx, st.SQL, st.Args...); err != nil {
			return nil, err
		}
	}
	// How many grants the commit withdraws is not known here, so the publish
	// is queued either way and finds nothing when none were.
	if _, err := ex.Submit(ctx, revocationqueue.PublishSpec(tenantID)); err != nil {
		return nil, fmt.Errorf("queueing the publishing of the tenant's revocations: %w", err)
	}
	q.logger.Info("deleting an access key", zap.Stringer("tenant", tenantID), zap.Stringer("task", t.ID), zap.Stringer("access_key", keyID))
	return nil, nil
}
