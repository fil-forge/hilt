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

	"github.com/fil-forge/hilt/pkg/client/upload"
	"github.com/fil-forge/hilt/pkg/store"
	"github.com/fil-forge/hilt/pkg/store/accesskey"
	"github.com/fil-forge/hilt/pkg/store/bucket"
	"github.com/fil-forge/hilt/pkg/store/delegation"
	"github.com/fil-forge/hilt/pkg/store/provider"
	tenantstore "github.com/fil-forge/hilt/pkg/store/tenant"
	"github.com/fil-forge/hilt/pkg/vault"
	"github.com/fil-forge/ucantone/did"
	"github.com/fil-forge/ucantone/did/plc"
	"github.com/fil-forge/ucantone/multikey/secp256k1"
	"go.uber.org/zap"
)

// Service implements tenant-management operations shared by the REST handlers.
type Service struct {
	logger      *zap.Logger
	tenants     tenantstore.Store
	providers   provider.Store
	buckets     bucket.Store
	accessKeys  accesskey.Store
	delegations delegation.Store
	secrets     vault.Vault
	plcClient   *plc.DirectoryClient
	upload      *upload.Client
}

// New constructs the tenant service.
func New(
	logger *zap.Logger,
	tenants tenantstore.Store,
	providers provider.Store,
	buckets bucket.Store,
	accessKeys accesskey.Store,
	delegations delegation.Store,
	secrets vault.Vault,
	plcClient *plc.DirectoryClient,
	upload *upload.Client,
) *Service {
	return &Service{
		logger:      logger,
		tenants:     tenants,
		providers:   providers,
		buckets:     buckets,
		accessKeys:  accessKeys,
		delegations: delegations,
		secrets:     secrets,
		plcClient:   plcClient,
		upload:      upload,
	}
}

// Provision provisions (or, idempotently, returns) the tenant for externalID: it
// generates a rotatable did:plc key, publishes it, registers the tenant with the
// upload service, and records it. created is false when an existing tenant is
// returned (including the concurrent-create winner).
func (s *Service) Provision(ctx context.Context, externalID, region string) (tenantstore.Record, bool, error) {
	if region == "" {
		return tenantstore.Record{}, false, ErrRegionRequired
	}

	// Idempotent: return the existing tenant if already provisioned.
	if existing, err := s.tenants.GetByExternalID(ctx, externalID); err == nil {
		return existing, false, nil
	} else if !errors.Is(err, store.ErrRecordNotFound) {
		return tenantstore.Record{}, false, fmt.Errorf("looking up tenant: %w", err)
	}

	// Resolve the provider for the requested region.
	prov, err := s.providers.GetByRegion(ctx, region)
	if errors.Is(err, store.ErrRecordNotFound) {
		return tenantstore.Record{}, false, ErrUnknownRegion
	} else if err != nil {
		return tenantstore.Record{}, false, fmt.Errorf("resolving provider: %w", err)
	}

	// Generate the tenant's rotatable did:plc key (secp256k1 rotation key).
	signer, err := secp256k1.Generate()
	if err != nil {
		return tenantstore.Record{}, false, fmt.Errorf("generating tenant key: %w", err)
	}
	key := signer.KeyDID()
	tenantID, genesis, err := plc.New(
		signer,
		plc.WithRotationKeys(key),
		plc.WithVerificationMethods(map[string]did.DID{"hilt": key}),
	)
	if err != nil {
		return tenantstore.Record{}, false, fmt.Errorf("building genesis operation: %w", err)
	}

	log := s.logger.With(zap.String("external_id", externalID), zap.Stringer("tenant", tenantID))

	// Persist the private key before publishing so it is never lost. Store the
	// multiformat-tagged bytes (signer.Bytes()) so the key type is recoverable on
	// decode rather than assuming secp256k1.
	vaultKey := vault.TenantKeyPath(tenantID)
	if err := s.secrets.Write(ctx, vaultKey, signer.Bytes()); err != nil {
		return tenantstore.Record{}, false, fmt.Errorf("storing tenant key: %w", err)
	}

	// Publish the genesis operation to register the did:plc.
	if err := s.plcClient.Update(ctx, tenantID, genesis); err != nil {
		log.Error("publishing genesis operation", zap.Error(err))
		s.cleanupKey(ctx, log, vaultKey)
		return tenantstore.Record{}, false, ErrDIDRegistration
	}

	// Register the tenant as a customer with the upload service (Sprue). Done
	// before recording the tenant so a failed registration returns an error and is
	// retried on the next call, rather than being short-circuited by the
	// idempotency check above (which keys on the stored tenant record).
	details := map[string]string{"external_id": externalID, "region": region}
	if err := s.upload.RegisterCustomer(ctx, tenantID, s.upload.Product, details); err != nil {
		log.Error("registering tenant with upload service", zap.Error(err))
		s.cleanupKey(ctx, log, vaultKey)
		return tenantstore.Record{}, false, ErrUploadRegistration
	}

	// Record the tenant.
	if err := s.tenants.Add(ctx, tenantID, externalID, prov.ID, tenantstore.Active); err != nil {
		// The tenant was not recorded, so its key is now orphaned; clean it up.
		s.cleanupKey(ctx, log, vaultKey)
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

// SetStatus updates the tenant's access mode. status must be a recognized status.
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
	if err := s.tenants.SetStatus(ctx, rec.ID, tenantstore.Status(status)); err != nil {
		if errors.Is(err, store.ErrRecordNotFound) {
			return ErrTenantNotFound
		}
		return fmt.Errorf("updating tenant status: %w", err)
	}
	return nil
}

// Delete permanently deletes a tenant (which must be disabled), cascading to its
// buckets, access keys, and delegations, and deactivating its did:plc. It is
// idempotent: a missing tenant is a no-op.
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

	if rec.Status != tenantstore.Disabled {
		return ErrTenantNotDisabled
	}

	tenantKey := vault.TenantKeyPath(rec.ID)

	// Deactivate the did:plc first — it requires the (still-present) tenant key.
	// Aborting here leaves all local state intact for a retry.
	if err := deactivateTenantDID(ctx, s.plcClient, s.secrets, tenantKey, rec.ID); err != nil {
		log.Error("deactivating tenant DID", zap.Error(err))
		return ErrDIDDeactivation
	}

	// Cascade: access keys (records + their delegations + vault keys).
	keys, err := s.accessKeys.ListByTenant(ctx, rec.ID)
	if err != nil {
		return fmt.Errorf("listing access keys: %w", err)
	}
	for _, ak := range keys {
		if err := s.delegations.DeleteByAudience(ctx, ak.ID); err != nil {
			return fmt.Errorf("deleting access key delegations: %w", err)
		}
		if err := s.secrets.Delete(ctx, vault.AccessKeyPath(rec.ID, ak.ID)); err != nil {
			log.Warn("removing access key from vault", zap.Error(err))
		}
		if err := s.accessKeys.Delete(ctx, ak.ID); err != nil {
			return fmt.Errorf("deleting access key: %w", err)
		}
	}

	// Cascade: buckets (records; bucket keys are discarded at creation).
	bucketIDs, err := store.Collect(ctx, func(ctx context.Context, opts store.PaginationConfig) (store.Page[did.DID], error) {
		var listOpts []bucket.ListOption
		if opts.Cursor != nil {
			listOpts = append(listOpts, bucket.WithCursor(*opts.Cursor))
		}
		page, err := s.buckets.ListByTenant(ctx, rec.ID, listOpts...)
		if err != nil {
			return store.Page[did.DID]{}, err
		}
		ids := make([]did.DID, 0, len(page.Results))
		for _, r := range page.Results {
			ids = append(ids, r.ID)
		}
		return store.Page[did.DID]{Results: ids, Cursor: page.Cursor}, nil
	})
	if err != nil {
		return fmt.Errorf("listing buckets: %w", err)
	}
	for _, id := range bucketIDs {
		if err := s.buckets.Delete(ctx, id); err != nil {
			return fmt.Errorf("deleting bucket: %w", err)
		}
	}

	// Delegations addressed to the tenant (the bucket -> tenant grants).
	if err := s.delegations.DeleteByAudience(ctx, rec.ID); err != nil {
		return fmt.Errorf("deleting tenant delegations: %w", err)
	}

	if err := s.tenants.Delete(ctx, rec.ID); err != nil {
		return fmt.Errorf("deleting tenant: %w", err)
	}
	// Best-effort removal of the tenant's key material.
	if err := s.secrets.Delete(ctx, tenantKey); err != nil {
		log.Warn("removing tenant key from vault", zap.Error(err))
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

// deactivateTenantDID publishes a tombstone for the tenant's did:plc, signed with
// its rotation key from the vault. If the DID is already deactivated it is a no-op.
func deactivateTenantDID(ctx context.Context, plcClient *plc.DirectoryClient, secrets vault.Vault, vaultKey string, tenantID did.DID) error {
	last, err := plcClient.Last(ctx, tenantID)
	if err != nil {
		if _, ok := errors.AsType[*plc.DeactivatedDIDError](err); ok {
			return nil // already deactivated
		}
		return fmt.Errorf("fetching last operation: %w", err)
	}

	keyBytes, err := secrets.Read(ctx, vaultKey)
	if err != nil {
		return fmt.Errorf("reading tenant key: %w", err)
	}
	signer, err := secp256k1.Decode(keyBytes)
	if err != nil {
		return fmt.Errorf("decoding tenant key: %w", err)
	}

	tomb, err := plc.NewTombstoneFromPrevious(last)
	if err != nil {
		return fmt.Errorf("building tombstone: %w", err)
	}
	signed, err := plc.SignTombstone(signer, tomb)
	if err != nil {
		return fmt.Errorf("signing tombstone: %w", err)
	}
	if err := plcClient.Deactivate(ctx, tenantID, signed); err != nil {
		return fmt.Errorf("publishing tombstone: %w", err)
	}
	return nil
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
