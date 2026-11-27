package tenantqueue

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/fil-forge/hilt/pkg/grant"
	"github.com/fil-forge/hilt/pkg/store"
	"github.com/fil-forge/hilt/pkg/store/tenant"
	"github.com/fil-forge/hilt/pkg/tasks"
	"github.com/fil-forge/hilt/pkg/tasks/revocationqueue"
	"github.com/fil-forge/hilt/pkg/vault"
	"github.com/fil-forge/libforge/taskrunner"
	"github.com/fil-forge/ucantone/did"
	"github.com/fil-forge/ucantone/did/plc"
	"github.com/fil-forge/ucantone/multikey/secp256k1"
	"github.com/fil-forge/ucantone/ucan"
	"github.com/fil-forge/ucantone/validator"
	"go.uber.org/zap"
)

// The outcomes of a queue-tenant.delete-tenant task that leaves the tenant in
// place.
var (
	// ErrTenantNotDisabled is a tenant that is not disabled. It fails the
	// task for good.
	ErrTenantNotDisabled = errors.New("tenant must be disabled before deletion")
	// ErrDIDDeactivation is a failure to read the tenant DID's last
	// operation from the DID directory or to publish its tombstone. It wraps
	// the cause.
	ErrDIDDeactivation = errors.New("deactivating the tenant's DID failed")
)

// Directory is what queue-tenant.delete-tenant needs of the did:plc
// directory. [*plc.DirectoryClient] satisfies it.
type Directory interface {
	// Last returns the DID's last operation. It returns a
	// [*plc.DeactivatedDIDError] when the DID is deactivated.
	Last(ctx context.Context, d did.DID) (*plc.SignedOperation, error)
	// Deactivate publishes the DID's tombstone.
	Deactivate(ctx context.Context, d did.DID, op *plc.SignedTombstone) error
}

// DeleteTenantSpec returns the queue-tenant.delete-tenant task that deletes
// the tenant. It carries no arguments.
func DeleteTenantSpec(tenant did.DID) taskrunner.Spec {
	return taskrunner.Spec{
		Queue:   tasks.QueueTenant,
		Subject: tenant.String(),
		Action:  tasks.ActionDeleteTenant,
	}
}

// runDeleteTenant is queue-tenant.delete-tenant. It deletes the subject
// tenant, which must be disabled, with everything Hilt holds for it. A tenant
// that does not exist is left alone and the task succeeds, which is also
// what a run after one that committed does.
//
// Unless the tenant's DID is already deactivated, it first publishes, signed
// by the tenant, every revocation the tenant owes and a revocation of every
// grant its access keys still hold, and then deactivates the DID. The order
// matters: the revocation service verifies a revocation against the DID, so
// nothing can be revoked once it is deactivated. The revocations owed are
// published by a queue-revocation.publish child ([revocationqueue.Drain]),
// which holds the tenant's subject on that queue until this task commits, so
// no publish task of the tenant runs between this one's publish and its
// commit, and those still queued find nothing owed when they run.
//
// A DID found deactivated skips the publish and the deactivation: an
// earlier run published before it deactivated, and the revocation service
// could not verify a publish now. A tenant whose DID was deactivated without
// its revocations being published first is the one case nothing here can
// revoke for: the copies of its keys' grants the gateway has cached last
// until they expire.
//
// It then removes, best effort, the vault entries of the tenant's access
// keys, its wrap keys and its signing key. Nothing after this point reads
// them: a run after a failed commit finds the DID deactivated and needs
// none.
//
// Everything it writes commits together: the delegations of the tenant, its
// keys and its buckets, the keys, the principals, the buckets with their
// policies, the wrap key records and the tenant row, which takes the
// revocations owed, the usage counts and the deleted buckets' owners with it
// by cascade.
//
// A failure before the deactivation leaves the DID live and every row in
// place, so a later run publishes again (the revocation service records a
// repeat once) and deactivates. A failure after it leaves the rows for a
// later run, which skips straight to deleting them.
func (q *Queue) runDeleteTenant(ctx context.Context, ex *taskrunner.Exec, t taskrunner.Task) ([]byte, error) {
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
	if rec.Status != tenant.Disabled {
		return nil, taskrunner.Permanent(ErrTenantNotDisabled)
	}
	if q.directory == nil {
		return nil, taskrunner.Permanent(errors.New("no DID directory to deactivate the tenant's DID in"))
	}
	if q.publisher == nil {
		return nil, taskrunner.Permanent(errors.New("no revocation service to publish the tenant's revocations to"))
	}
	keys, err := q.accessKeys.ListByTenant(ctx, tenantID)
	if err != nil {
		return nil, fmt.Errorf("listing the tenant's access keys: %w", err)
	}
	wraps, err := q.wrapKeys.List(ctx, tenantID)
	if err != nil {
		return nil, fmt.Errorf("listing the tenant's wrap keys: %w", err)
	}

	last, err := q.directory.Last(ctx, tenantID)
	if _, deactivated := errors.AsType[*plc.DeactivatedDIDError](err); deactivated {
		log.Info("the tenant's DID is already deactivated; nothing is published and no tombstone is sent")
	} else {
		if err != nil {
			return nil, fmt.Errorf("%w: reading the DID's last operation: %w", ErrDIDDeactivation, err)
		}
		if _, err := ex.Run(ctx, revocationqueue.PublishSpec(tenantID)); err != nil {
			return nil, fmt.Errorf("publishing the tenant's revocations owed: %w", err)
		}
		if err := q.revokeKeyGrants(ctx, log, tenantID); err != nil {
			return nil, err
		}
		if err := q.deactivate(ctx, tenantID, last); err != nil {
			return nil, fmt.Errorf("%w: %w", ErrDIDDeactivation, err)
		}
	}

	paths := make([]string, 0, len(keys)+len(wraps)+1)
	for _, key := range keys {
		paths = append(paths, vault.AccessKeyPath(tenantID, key.ID))
	}
	for _, wk := range wraps {
		paths = append(paths, wk.VaultKey)
	}
	paths = append(paths, vault.TenantKeyPath(tenantID))
	for _, path := range paths {
		if err := q.secrets.Delete(ctx, path); err != nil {
			log.Warn("removing a key of the tenant from the vault", zap.String("path", path), zap.Error(err))
		}
	}

	// The delegations go first: the statement finds them through the rows
	// of the keys and buckets. The keys go before the principals they
	// reference, and every row referencing the tenant without a cascade
	// before the tenant.
	if err := record(ctx, ex, []store.Statement{
		q.delegations.DeleteTenantStatement(tenantID),
		q.accessKeys.DeleteByTenantStatement(tenantID),
		q.principals.DeleteByTenantStatement(tenantID),
		q.buckets.DeleteByTenantStatement(tenantID),
		q.wrapKeys.DeleteStatement(tenantID),
		q.tenants.DeleteStatement(tenantID),
	}); err != nil {
		return nil, err
	}
	log.Info("deleting the tenant", zap.Int("access_keys", len(keys)), zap.Int("wrap_keys", len(wraps)))
	return nil, nil
}

// revokeKeyGrants publishes, signed by the tenant, a revocation of every
// grant the tenant's access keys hold that has not expired, a batch of
// [revocationqueue.BatchSize] at a time. The grants stay in the store; the
// task's commit deletes them. The signing key is read only when there is a
// grant to revoke.
func (q *Queue) revokeKeyGrants(ctx context.Context, log *zap.Logger, tenantID did.DID) error {
	held, err := q.delegations.ListKeyGrants(ctx, tenantID)
	if err != nil {
		return err
	}
	now := ucan.UnixTimestamp(time.Now().Unix())
	live := make([]ucan.Delegation, 0, len(held))
	for _, d := range held {
		if validator.ValidateNotExpired(d, now) == nil {
			live = append(live, d)
		}
	}
	if len(live) == 0 {
		return nil
	}
	issuer, err := vault.TenantIssuer(ctx, q.secrets, tenantID)
	if err != nil {
		return fmt.Errorf("reading the tenant's signing key: %w", err)
	}
	for start := 0; start < len(live); start += revocationqueue.BatchSize {
		batch := live[start:min(start+revocationqueue.BatchSize, len(live))]
		if err := grant.PublishRevocations(ctx, log, q.publisher, issuer, batch); err != nil {
			return fmt.Errorf("revoking the grants of the tenant's access keys: %w", err)
		}
	}
	log.Info("revoked the grants the tenant's access keys held", zap.Int("published", len(live)))
	return nil
}

// deactivate publishes a tombstone for the tenant's did:plc after its last
// operation, signed with its rotation key from the vault.
func (q *Queue) deactivate(ctx context.Context, tenantID did.DID, last *plc.SignedOperation) error {
	keyBytes, err := q.secrets.Read(ctx, vault.TenantKeyPath(tenantID))
	if err != nil {
		return fmt.Errorf("reading the tenant's rotation key: %w", err)
	}
	signer, err := secp256k1.Decode(keyBytes)
	if err != nil {
		return fmt.Errorf("decoding the tenant's rotation key: %w", err)
	}
	tomb, err := plc.NewTombstoneFromPrevious(last)
	if err != nil {
		return fmt.Errorf("building the tombstone: %w", err)
	}
	signed, err := plc.SignTombstone(signer, tomb)
	if err != nil {
		return fmt.Errorf("signing the tombstone: %w", err)
	}
	if err := q.directory.Deactivate(ctx, tenantID, signed); err != nil {
		return fmt.Errorf("publishing the tombstone: %w", err)
	}
	return nil
}
