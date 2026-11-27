// Package tenant provides the tenant-management business logic for the REST API:
// provisioning (did:plc key generation + PLC publication + upload-service
// registration), status updates, and deletion (with cascade + DID deactivation).
// It returns the known errors in errors.go so handlers can map them to HTTP
// responses; unexpected failures are returned wrapped for the handler to log.
package tenant

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/fil-forge/hilt/pkg/client/upload"
	"github.com/fil-forge/hilt/pkg/store"
	tenantstore "github.com/fil-forge/hilt/pkg/store/tenant"
	wrapkeystore "github.com/fil-forge/hilt/pkg/store/wrapkey"
	"github.com/fil-forge/hilt/pkg/tasks/tenantqueue"
	"github.com/fil-forge/hilt/pkg/vault"
	"github.com/fil-forge/hilt/pkg/wrapkey"
	"github.com/fil-forge/libforge/taskrunner"
	"github.com/fil-forge/ucantone/did"
	"github.com/fil-forge/ucantone/did/plc"
	"github.com/fil-forge/ucantone/multikey/secp256k1"
	"go.uber.org/zap"
)

// fragment is the fixed DID document verification-method name under which a
// tenant's signing key is published, for discovery of the current key. It is
// replaced in place on rotation.
const fragment = "hilt"

// DeleteTimeout is the longest a tenant deletion waits for its turn on the
// tenant's queue. A deletion that has not started by then is abandoned with
// nothing done, and the caller repeats the call.
const DeleteTimeout = 30 * time.Second

// Service implements tenant-management operations shared by the REST handlers.
type Service struct {
	logger    *zap.Logger
	tenants   tenantstore.Store
	secrets   vault.Vault
	wrapKeys  wrapkeystore.Store
	plcClient *plc.DirectoryClient
	upload    *upload.Client
	runner    *taskrunner.Runner
}

// New constructs the tenant service. runner runs the tenant's status
// changes and its deletion, and must have the handlers of queue-tenant
// ([tenantqueue.New]) and queue-revocation registered and be started before
// SetStatus or Delete is called.
func New(
	logger *zap.Logger,
	tenants tenantstore.Store,
	secrets vault.Vault,
	wrapKeys wrapkeystore.Store,
	plcClient *plc.DirectoryClient,
	upload *upload.Client,
	runner *taskrunner.Runner,
) *Service {
	return &Service{
		logger:    logger,
		tenants:   tenants,
		secrets:   secrets,
		wrapKeys:  wrapKeys,
		plcClient: plcClient,
		upload:    upload,
		runner:    runner,
	}
}

// ValidID reports whether id can be a tenantId. The id travels as one path
// segment of the Tenant API, so it must not hold a character that delimits or
// escapes a segment, nor be a dot segment a client could resolve away.
func ValidID(id string) bool {
	return !strings.ContainsAny(id, "/;,?%") && id != "." && id != ".."
}

// Provision provisions (or, idempotently, returns) the tenant for externalID: it
// generates a rotatable did:plc key, publishes it, registers the tenant with the
// upload service, and records it. created is false when an existing tenant is
// returned (including the concurrent-create winner).
//
// A tenant is region-free: each of its buckets is bound to the provider (region)
// it is created through, so one tenant may hold buckets in several regions.
func (s *Service) Provision(ctx context.Context, externalID string) (tenantstore.Record, bool, error) {
	// Idempotent: return the existing tenant if already provisioned.
	if existing, err := s.tenants.GetByExternalID(ctx, externalID); err == nil {
		return existing, false, nil
	} else if !errors.Is(err, store.ErrRecordNotFound) {
		return tenantstore.Record{}, false, fmt.Errorf("looking up tenant: %w", err)
	}

	// Generate the tenant's rotatable did:plc key (secp256k1 rotation key).
	signer, err := secp256k1.Generate()
	if err != nil {
		return tenantstore.Record{}, false, fmt.Errorf("generating tenant key: %w", err)
	}
	key := signer.KeyDID()

	// Generate the tenant's X25519 FEE wrap key. This is distinct from the
	// signing/rotation key above: it is only ever used as an ECDH recipient
	// for wrapping content-encryption keys, never for signing. It is published
	// in the genesis operation at the fixed fragment #wrap for discovery of
	// the current key; recovery keys off the fingerprint (kid), not the
	// fragment.
	wrapKeyPair, err := wrapkey.Generate()
	if err != nil {
		return tenantstore.Record{}, false, fmt.Errorf("generating wrap key: %w", err)
	}

	tenantID, genesis, err := plc.New(
		signer,
		plc.WithRotationKeys(key),
		plc.WithVerificationMethods(map[string]did.DID{
			fragment:         key,
			wrapkey.Fragment: wrapKeyPair.KeyDID(),
		}),
	)
	if err != nil {
		return tenantstore.Record{}, false, fmt.Errorf("building genesis operation: %w", err)
	}

	log := s.logger.With(zap.String("external_id", externalID), zap.Stringer("tenant", tenantID))

	signingVaultKey := vault.TenantKeyPath(tenantID)
	wrapVaultKey := wrapkeystore.VaultKey(tenantID, 1)

	// cleanups accumulates best-effort rollbacks for the durable state written
	// so far. A later failure calls runCleanups, which unwinds them in reverse
	// (LIFO) order under a detached context so a client disconnect can't cancel
	// the rollback.
	var cleanups []func(context.Context)
	runCleanups := func() {
		dctx := context.WithoutCancel(ctx)
		for i := len(cleanups) - 1; i >= 0; i-- {
			cleanups[i](dctx)
		}
	}

	// Persist the private keys before publishing so they are never lost, signing
	// key then wrap key. Store the multiformat-tagged bytes (Bytes()) so each key
	// type is recoverable on decode rather than assumed.
	if err := s.secrets.Write(ctx, signingVaultKey, signer.Bytes()); err != nil {
		log.Error("storing signing key", zap.Error(err))
		return tenantstore.Record{}, false, fmt.Errorf("storing signing key: %w", err)
	}
	cleanups = append(cleanups, func(ctx context.Context) {
		s.cleanupKey(ctx, log, signingVaultKey)
	})

	if err := s.secrets.Write(ctx, wrapVaultKey, wrapKeyPair.Bytes()); err != nil {
		log.Error("storing wrap key", zap.Error(err))
		runCleanups()
		return tenantstore.Record{}, false, fmt.Errorf("storing wrap key: %w", err)
	}
	cleanups = append(cleanups, func(ctx context.Context) {
		s.cleanupKey(ctx, log, wrapVaultKey)
	})

	// Publish the genesis operation to register the did:plc.
	if err := s.plcClient.Update(ctx, tenantID, genesis); err != nil {
		log.Error("publishing genesis operation", zap.Error(err))
		runCleanups()
		return tenantstore.Record{}, false, ErrDIDRegistration
	}

	// Register the tenant as a customer with the upload service (Sprue). Done
	// before recording the tenant so a failed registration returns an error and is
	// retried on the next call, rather than being short-circuited by the
	// idempotency check above (which keys on the stored tenant record).
	details := map[string]string{"external_id": externalID}
	if err := s.upload.RegisterCustomer(ctx, tenantID, s.upload.Product, details); err != nil {
		log.Error("registering tenant with upload service", zap.Error(err))
		runCleanups()
		return tenantstore.Record{}, false, ErrUploadRegistration
	}

	// Record the active wrap key (version 1) before the tenant row. The tenant
	// row is the final "commit" write and the key the idempotency check reads,
	// so recording the wrap key first guarantees a persisted tenant always has
	// a wrap-key entry. Its kid is the public-key fingerprint (the multibase
	// multicodec-tagged X25519 public key); the private half stays sealed in
	// the vault.
	if err := s.wrapKeys.Add(ctx, wrapkeystore.Input{
		Tenant:   tenantID,
		Version:  1,
		KID:      wrapKeyPair.Public().String(),
		VaultKey: wrapVaultKey,
	}); err != nil {
		log.Error("storing wrap key record", zap.Error(err))
		runCleanups()
		return tenantstore.Record{}, false, fmt.Errorf("storing wrap key record: %w", err)
	}
	cleanups = append(cleanups, func(ctx context.Context) {
		if err := s.wrapKeys.Delete(ctx, tenantID); err != nil {
			log.Error("cleaning up orphaned wrap key record", zap.Error(err))
		}
	})

	// Record the tenant.
	if err := s.tenants.Add(ctx, tenantID, externalID, tenantstore.Active); err != nil {
		runCleanups()
		// Concurrent create with the same external id: return the winner.
		if errors.Is(err, store.ErrRecordExists) {
			if winner, gerr := s.tenants.GetByExternalID(ctx, externalID); gerr == nil {
				return winner, false, nil
			}
		}
		return tenantstore.Record{}, false, fmt.Errorf("storing tenant: %w", err)
	}

	rec, err := s.tenants.Get(ctx, tenantID)
	if err != nil {
		return tenantstore.Record{}, false, fmt.Errorf("loading created tenant: %w", err)
	}
	log.Info("provisioned tenant")
	return rec, true, nil
}

// Get returns the tenant for externalID.
func (s *Service) Get(ctx context.Context, externalID string) (tenantstore.Record, error) {
	rec, err := s.tenants.GetByExternalID(ctx, externalID)
	if errors.Is(err, store.ErrRecordNotFound) {
		return tenantstore.Record{}, ErrTenantNotFound
	} else if err != nil {
		return tenantstore.Record{}, fmt.Errorf("looking up tenant: %w", err)
	}
	return rec, nil
}

// SetStatus updates the tenant's access mode. status must be a recognized
// status.
//
// The change runs as a queue-tenant.set-status task on the tenant, behind
// any other change to the tenant queued before it, and SetStatus returns
// once it has committed or failed. Every change withdraws the grants the
// tenant's access keys hold and issues each key those of the new status, in
// the same commit as the status ([tenantqueue]): all of them for active,
// the grants of its reads, listings and deletions for write-locked, and none
// for disabled. The revocations are published after it. An authorization for the tenant that arrives while the
// task is queued or running waits for it. If ctx ends first the task stays
// queued and a worker finishes it.
func (s *Service) SetStatus(ctx context.Context, externalID, status string) error {
	if !validStatus(tenantstore.Status(status)) {
		return ErrInvalidStatus
	}
	rec, err := s.tenants.GetByExternalID(ctx, externalID)
	if errors.Is(err, store.ErrRecordNotFound) {
		return ErrTenantNotFound
	} else if err != nil {
		return fmt.Errorf("looking up tenant: %w", err)
	}
	if _, err := s.runner.Run(ctx, tenantqueue.SetStatusSpec(rec.ID, tenantstore.Status(status))); err != nil {
		if errors.Is(err, tenantqueue.ErrTenantNotFound) {
			return ErrTenantNotFound
		}
		return fmt.Errorf("updating tenant status: %w", err)
	}
	return nil
}

// Delete permanently deletes a tenant, which must be disabled, with its
// buckets and their policies, access keys, principals, wrap keys and
// delegations, and deactivates its did:plc. It is idempotent: a missing
// tenant is a no-op.
//
// The deletion runs as a queue-tenant.delete-tenant task on the tenant
// ([tenantqueue]), behind any other change to the tenant queued before it,
// and Delete returns once it has committed or failed. Unless the tenant's
// DID is already deactivated, the task publishes every revocation the
// tenant owes and a revocation of every grant its keys hold, then
// deactivates the DID, then removes the tenant's keys from the vault and
// deletes its rows in one commit. The task runs on a context detached from
// ctx, so a client that disconnects does not stop a deletion part way; it
// finishes, and a repeated call finds nothing left. A deletion still
// waiting for its turn after [DeleteTimeout], or at ctx's deadline, is
// abandoned with nothing done. A deletion whose handler fails is not
// retried: the caller repeats the call, and the repeat carries on from where
// the failure left the tenant.
//
// A tenant that is not disabled when the task runs is refused with
// [ErrTenantNotDisabled], and a failure to read or deactivate the DID is
// [ErrDIDDeactivation].
//
// Out of scope: deprovisioning the tenant's spaces from the Forge upload service
// (Sprue), for which there is no facility per the RFC.
func (s *Service) Delete(ctx context.Context, externalID string) error {
	rec, err := s.tenants.GetByExternalID(ctx, externalID)
	if errors.Is(err, store.ErrRecordNotFound) {
		return nil // idempotent
	} else if err != nil {
		return fmt.Errorf("looking up tenant: %w", err)
	}
	log := s.logger.With(zap.String("external_id", rec.ExternalID), zap.Stringer("tenant", rec.ID))

	spec := tenantqueue.DeleteTenantSpec(rec.ID)
	expires := time.Now().Add(DeleteTimeout)
	if deadline, ok := ctx.Deadline(); ok && deadline.Before(expires) {
		expires = deadline
	}
	spec.Expires = &expires
	if _, err := s.runner.Run(context.WithoutCancel(ctx), spec); err != nil {
		switch {
		case errors.Is(err, tenantqueue.ErrTenantNotDisabled):
			return ErrTenantNotDisabled
		case errors.Is(err, tenantqueue.ErrDIDDeactivation):
			log.Error("deactivating the tenant's DID", zap.Error(err))
			return ErrDIDDeactivation
		}
		return fmt.Errorf("deleting tenant: %w", err)
	}
	log.Info("deleted tenant")
	return nil
}

// cleanupKey removes an orphaned tenant key after a provisioning failure. It runs
// on a context detached from the request so a client disconnect — which cancels
// ctx — cannot abort the cleanup partway.
func (s *Service) cleanupKey(ctx context.Context, log *zap.Logger, vaultKey string) {
	if err := s.secrets.Delete(context.WithoutCancel(ctx), vaultKey); err != nil {
		log.Error("cleaning up orphaned tenant key", zap.Error(err))
	}
}

// validStatus reports whether s is a recognized tenant status.
func validStatus(s tenantstore.Status) bool {
	switch s {
	case tenantstore.Active, tenantstore.WriteLocked, tenantstore.Disabled:
		return true
	default:
		return false
	}
}
