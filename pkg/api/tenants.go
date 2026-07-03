package api

import (
	"context"
	"errors"
	"fmt"
	"net/http"

	"github.com/fil-forge/hilt/pkg/client"
	"github.com/fil-forge/hilt/pkg/store"
	"github.com/fil-forge/hilt/pkg/store/accesskey"
	"github.com/fil-forge/hilt/pkg/store/bucket"
	"github.com/fil-forge/hilt/pkg/store/delegation"
	"github.com/fil-forge/hilt/pkg/store/provider"
	"github.com/fil-forge/hilt/pkg/store/tenant"
	"github.com/fil-forge/hilt/pkg/store/wrapkey"
	"github.com/fil-forge/hilt/pkg/vault"
	"github.com/fil-forge/ucantone/did"
	"github.com/fil-forge/ucantone/did/plc"
	"github.com/fil-forge/ucantone/multikey/secp256k1"
	"github.com/fil-forge/ucantone/multikey/x25519"
	"github.com/labstack/echo/v4"
	"go.uber.org/zap"
)

// NewProvisionTenantHandler handles PUT /tenants/{tenantId} — provision a
// tenant: generate a rotatable did:plc tenant key and a per-tenant X25519 wrap
// key, publish them to the PLC directory, seal both private halves in the vault,
// register the tenant with the upload service, and persist the tenant and
// wrap-key records. It is idempotent on the external {tenantId}.
func NewProvisionTenantHandler(
	logger *zap.Logger,
	tenants tenant.Store,
	providers provider.Store,
	wrapKeys wrapkey.Store,
	secrets vault.Vault,
	plcClient *plc.DirectoryClient,
	upload *client.UploadClient,
) Route {
	log := logger.With(zap.String("handler", "ProvisionTenant"))
	return NewRoute(http.MethodPut, "/tenants/:tenantId", func(c echo.Context) error {
		ctx := c.Request().Context()

		externalID := c.Param("tenantId")
		if externalID == "" {
			return echo.NewHTTPError(http.StatusBadRequest, "missing tenant id")
		}

		var req ProvisionTenantRequest
		if err := c.Bind(&req); err != nil {
			return echo.NewHTTPError(http.StatusBadRequest, "invalid request body")
		}
		if req.Region == "" {
			return echo.NewHTTPError(http.StatusBadRequest, "region is required")
		}

		// Idempotent: return the existing tenant if already provisioned.
		if rec, err := tenants.GetByExternalID(ctx, externalID); err == nil {
			return c.JSON(http.StatusOK, tenantResponse(rec))
		} else if !errors.Is(err, store.ErrRecordNotFound) {
			log.Error("looking up tenant", zap.Error(err))
			return echo.NewHTTPError(http.StatusInternalServerError, "internal error")
		}

		// Resolve the provider for the requested region.
		prov, err := providers.GetByRegion(ctx, req.Region)
		if errors.Is(err, store.ErrRecordNotFound) {
			return echo.NewHTTPError(http.StatusBadRequest, "unknown region")
		} else if err != nil {
			log.Error("resolving provider", zap.Error(err))
			return echo.NewHTTPError(http.StatusInternalServerError, "internal error")
		}

		// Generate the tenant's rotatable did:plc key (secp256k1 rotation key).
		signer, err := secp256k1.Generate()
		if err != nil {
			log.Error("generating tenant key", zap.Error(err))
			return echo.NewHTTPError(http.StatusInternalServerError, "internal error")
		}
		key := signer.KeyDID()

		// Generate the tenant's X25519 FEE wrap key. This is distinct from the
		// signing/rotation key above: it is only ever used as an ECDH recipient
		// for wrapping content-encryption keys, never for signing. It is published
		// in the genesis operation at the fixed fragment #wrap for discovery of
		// the current key; recovery keys off the fingerprint (kid), not the
		// fragment.
		wrapKeyPair, err := x25519.Generate()
		if err != nil {
			log.Error("generating wrap key", zap.Error(err))
			return echo.NewHTTPError(http.StatusInternalServerError, "internal error")
		}

		tenantID, genesis, err := plc.New(
			signer,
			plc.WithRotationKeys(key),
			plc.WithVerificationMethods(map[string]did.DID{
				"hilt":           key,
				wrapkey.Fragment: wrapKeyPair.KeyDID(),
			}),
		)
		if err != nil {
			log.Error("building genesis operation", zap.Error(err))
			return echo.NewHTTPError(http.StatusInternalServerError, "internal error")
		}

		log := log.With(zap.String("external_id", externalID), zap.Stringer("tenant", tenantID))

		vaultKey := vault.TenantKeyPath(tenantID)
		wrapKeyVault := wrapkey.VaultKey(tenantID, 1)

		// cleanupKeys best-effort removes both sealed private halves after a
		// failure once they have been written. Detached context so a client
		// disconnect can't cancel the cleanup.
		cleanupKeys := func() {
			dctx := context.WithoutCancel(ctx)
			if err := secrets.Delete(dctx, wrapKeyVault); err != nil {
				log.Error("cleaning up orphaned wrap key", zap.Error(err))
			}
			if err := secrets.Delete(dctx, vaultKey); err != nil {
				log.Error("cleaning up orphaned tenant key", zap.Error(err))
			}
		}

		// Persist the private keys before publishing so they are never lost. Store
		// the multiformat-tagged bytes (Bytes()) so each key type is recoverable
		// on decode rather than assumed.
		if err := secrets.Write(ctx, vaultKey, signer.Bytes()); err != nil {
			log.Error("storing tenant key", zap.Error(err))
			return echo.NewHTTPError(http.StatusInternalServerError, "internal error")
		}
		if err := secrets.Write(ctx, wrapKeyVault, wrapKeyPair.Bytes()); err != nil {
			log.Error("storing wrap key", zap.Error(err))
			// Detached context so a client disconnect can't cancel the cleanup.
			if derr := secrets.Delete(context.WithoutCancel(ctx), vaultKey); derr != nil {
				log.Error("cleaning up orphaned tenant key", zap.Error(derr))
			}
			return echo.NewHTTPError(http.StatusInternalServerError, "internal error")
		}

		// Publish the genesis operation to register the did:plc.
		if err := plcClient.Update(ctx, tenantID, genesis); err != nil {
			log.Error("publishing genesis operation", zap.Error(err))
			cleanupKeys()
			return echo.NewHTTPError(http.StatusBadGateway, "failed to register tenant DID")
		}

		// Register the tenant as a customer with the upload service (Sprue). Done
		// before recording the tenant so a failed registration returns an error
		// and is retried on the next call, rather than being short-circuited by
		// the idempotency check above (which keys on the stored tenant record).
		details := map[string]string{"external_id": externalID, "region": req.Region}
		if err := upload.RegisterCustomer(ctx, tenantID, upload.Product, details); err != nil {
			log.Error("registering tenant with upload service", zap.Error(err))
			cleanupKeys()
			return echo.NewHTTPError(http.StatusBadGateway, "failed to register tenant with upload service")
		}

		// Record the active wrap key (version 1) before the tenant row. The tenant
		// row is the final "commit" write and the key the idempotency check reads,
		// so recording the wrap key first guarantees a persisted tenant always has
		// a wrap-key entry. Its kid is the public-key fingerprint (the multibase
		// multicodec-tagged X25519 public key); the private half stays sealed in
		// the vault.
		if err := wrapKeys.Add(ctx, wrapkey.Record{
			Tenant:   tenantID,
			Version:  1,
			KID:      wrapKeyPair.Public().String(),
			Status:   wrapkey.Active,
			VaultKey: wrapKeyVault,
		}); err != nil {
			log.Error("storing wrap key record", zap.Error(err))
			cleanupKeys()
			return echo.NewHTTPError(http.StatusInternalServerError, "internal error")
		}

		// Record the tenant.
		if err := tenants.Add(ctx, tenantID, externalID, prov.ID, tenant.Active); err != nil {
			// The tenant was not recorded; clean up its now-orphaned keys and
			// wrap-key record.
			cleanupKeys()
			if derr := wrapKeys.DeleteByTenant(context.WithoutCancel(ctx), tenantID); derr != nil {
				log.Error("cleaning up orphaned wrap key record", zap.Error(derr))
			}
			// Concurrent create with the same external id: return the winner.
			if errors.Is(err, store.ErrRecordExists) {
				if rec, gerr := tenants.GetByExternalID(ctx, externalID); gerr == nil {
					return c.JSON(http.StatusOK, tenantResponse(rec))
				}
			}
			log.Error("storing tenant", zap.Error(err))
			return echo.NewHTTPError(http.StatusInternalServerError, "internal error")
		}

		rec, err := tenants.Get(ctx, tenantID)
		if err != nil {
			log.Error("loading created tenant", zap.Error(err))
			return echo.NewHTTPError(http.StatusInternalServerError, "internal error")
		}
		log.Info("provisioned tenant")
		return c.JSON(http.StatusCreated, tenantResponse(rec))
	})
}

// tenantResponse builds the Tenant API representation from a stored record. The
// caller-facing tenantId is the external id; the did:plc stays internal. Quota
// counts/limits are not tracked yet and are returned as zero.
func tenantResponse(rec tenant.Record) Tenant {
	return Tenant{
		TenantID:  rec.ExternalID,
		Status:    TenantStatus(rec.Status),
		CreatedAt: rec.CreatedAt,
	}
}

// NewGetTenantHandler handles GET /tenants/{tenantId} — retrieve tenant
// operational state and quotas.
func NewGetTenantHandler(logger *zap.Logger, tenants tenant.Store) Route {
	log := logger.With(zap.String("handler", "GetTenant"))
	return NewRoute(http.MethodGet, "/tenants/:tenantId", func(c echo.Context) error {
		rec, err := tenants.GetByExternalID(c.Request().Context(), c.Param("tenantId"))
		if errors.Is(err, store.ErrRecordNotFound) {
			return echo.NewHTTPError(http.StatusNotFound, "tenant not found")
		} else if err != nil {
			log.Error("looking up tenant", zap.Error(err))
			return echo.NewHTTPError(http.StatusInternalServerError, "internal error")
		}
		return c.JSON(http.StatusOK, tenantResponse(rec))
	})
}

// NewUpdateTenantStatusHandler handles POST /tenants/{tenantId}/status — update
// tenant access mode.
func NewUpdateTenantStatusHandler(logger *zap.Logger, tenants tenant.Store) Route {
	log := logger.With(zap.String("handler", "UpdateTenantStatus"))
	return NewRoute(http.MethodPost, "/tenants/:tenantId/status", func(c echo.Context) error {
		ctx := c.Request().Context()

		var req UpdateTenantStatusRequest
		if err := c.Bind(&req); err != nil {
			return echo.NewHTTPError(http.StatusBadRequest, "invalid request body")
		}
		if !validTenantStatus(req.Status) {
			return echo.NewHTTPError(http.StatusUnprocessableEntity, "invalid status")
		}

		rec, err := tenants.GetByExternalID(ctx, c.Param("tenantId"))
		if errors.Is(err, store.ErrRecordNotFound) {
			return echo.NewHTTPError(http.StatusNotFound, "tenant not found")
		} else if err != nil {
			log.Error("looking up tenant", zap.Error(err))
			return echo.NewHTTPError(http.StatusInternalServerError, "internal error")
		}

		if err := tenants.SetStatus(ctx, rec.ID, tenant.Status(req.Status)); err != nil {
			if errors.Is(err, store.ErrRecordNotFound) {
				return echo.NewHTTPError(http.StatusNotFound, "tenant not found")
			}
			log.Error("updating tenant status", zap.Error(err))
			return echo.NewHTTPError(http.StatusInternalServerError, "internal error")
		}
		return c.NoContent(http.StatusNoContent)
	})
}

// NewDeleteTenantHandler handles DELETE /tenants/{tenantId} — permanently
// delete a tenant (must be disabled first), cascading to its buckets, access
// keys, and delegations, and deactivating the tenant's did:plc. Idempotent.
//
// Out of scope: deprovisioning the tenant's spaces from the Forge upload
// service (Sprue), for which there is no facility per the RFC.
func NewDeleteTenantHandler(
	logger *zap.Logger,
	tenants tenant.Store,
	buckets bucket.Store,
	accessKeys accesskey.Store,
	delegations delegation.Store,
	wrapKeys wrapkey.Store,
	secrets vault.Vault,
	plcClient *plc.DirectoryClient,
) Route {
	log := logger.With(zap.String("handler", "DeleteTenant"))
	return NewRoute(http.MethodDelete, "/tenants/:tenantId", func(c echo.Context) error {
		ctx := c.Request().Context()

		rec, err := tenants.GetByExternalID(ctx, c.Param("tenantId"))
		if errors.Is(err, store.ErrRecordNotFound) {
			return c.NoContent(http.StatusNoContent) // idempotent
		} else if err != nil {
			log.Error("looking up tenant", zap.Error(err))
			return echo.NewHTTPError(http.StatusInternalServerError, "internal error")
		}
		log := log.With(zap.String("external_id", rec.ExternalID), zap.Stringer("tenant", rec.ID))

		if rec.Status != tenant.Disabled {
			return echo.NewHTTPError(http.StatusConflict, "tenant must be disabled before deletion")
		}

		tenantKey := vault.TenantKeyPath(rec.ID)

		// Deactivate the did:plc first — it requires the (still-present) tenant
		// key. Aborting here leaves all local state intact for a retry.
		if err := deactivateTenantDID(ctx, plcClient, secrets, tenantKey, rec.ID); err != nil {
			log.Error("deactivating tenant DID", zap.Error(err))
			return echo.NewHTTPError(http.StatusBadGateway, "failed to deactivate tenant DID")
		}

		// Cascade: access keys (records + their delegations + vault keys).
		keys, err := accessKeys.ListByTenant(ctx, rec.ID)
		if err != nil {
			log.Error("listing access keys", zap.Error(err))
			return echo.NewHTTPError(http.StatusInternalServerError, "internal error")
		}
		for _, ak := range keys {
			if err := delegations.DeleteByAudience(ctx, ak.ID); err != nil {
				log.Error("deleting access key delegations", zap.Error(err))
				return echo.NewHTTPError(http.StatusInternalServerError, "internal error")
			}
			if err := secrets.Delete(ctx, vault.AccessKeyPath(rec.ID, ak.ID)); err != nil {
				log.Warn("removing access key from vault", zap.Error(err))
			}
			if err := accessKeys.Delete(ctx, ak.ID); err != nil {
				log.Error("deleting access key", zap.Error(err))
				return echo.NewHTTPError(http.StatusInternalServerError, "internal error")
			}
		}

		// Cascade: wrap keys (registry rows + their sealed private halves). Every
		// version, active and archived, is destroyed — tenant deletion is the
		// "true deletion" that ends the envelope-recovery path, so archive-don't-
		// destroy (which governs rotation) does not apply.
		wrapKeyRecs, err := wrapKeys.List(ctx, rec.ID)
		if err != nil {
			log.Error("listing wrap keys", zap.Error(err))
			return echo.NewHTTPError(http.StatusInternalServerError, "internal error")
		}
		for _, wk := range wrapKeyRecs {
			if err := secrets.Delete(ctx, wk.VaultKey); err != nil {
				log.Warn("removing wrap key from vault", zap.Error(err))
			}
		}
		if err := wrapKeys.DeleteByTenant(ctx, rec.ID); err != nil {
			log.Error("deleting wrap keys", zap.Error(err))
			return echo.NewHTTPError(http.StatusInternalServerError, "internal error")
		}

		// Cascade: buckets (records; bucket keys are discarded at creation).
		bucketIDs, err := store.Collect(ctx, func(ctx context.Context, opts store.PaginationConfig) (store.Page[did.DID], error) {
			var listOpts []bucket.ListOption
			if opts.Cursor != nil {
				listOpts = append(listOpts, bucket.WithCursor(*opts.Cursor))
			}
			page, err := buckets.ListByTenant(ctx, rec.ID, listOpts...)
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
			log.Error("listing buckets", zap.Error(err))
			return echo.NewHTTPError(http.StatusInternalServerError, "internal error")
		}
		for _, id := range bucketIDs {
			if err := buckets.Delete(ctx, id); err != nil {
				log.Error("deleting bucket", zap.Error(err))
				return echo.NewHTTPError(http.StatusInternalServerError, "internal error")
			}
		}

		// Delegations addressed to the tenant (the bucket -> tenant grants).
		if err := delegations.DeleteByAudience(ctx, rec.ID); err != nil {
			log.Error("deleting tenant delegations", zap.Error(err))
			return echo.NewHTTPError(http.StatusInternalServerError, "internal error")
		}

		if err := tenants.Delete(ctx, rec.ID); err != nil {
			log.Error("deleting tenant", zap.Error(err))
			return echo.NewHTTPError(http.StatusInternalServerError, "internal error")
		}
		// Best-effort removal of the tenant's key material.
		if err := secrets.Delete(ctx, tenantKey); err != nil {
			log.Warn("removing tenant key from vault", zap.Error(err))
		}
		log.Info("deleted tenant")
		return c.NoContent(http.StatusNoContent)
	})
}

// deactivateTenantDID publishes a tombstone for the tenant's did:plc, signed
// with its rotation key from the vault. If the DID is already deactivated it is
// a no-op.
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

// validTenantStatus reports whether s is a recognized tenant status.
func validTenantStatus(s TenantStatus) bool {
	switch s {
	case TenantStatusActive, TenantStatusWriteLocked, TenantStatusDisabled:
		return true
	default:
		return false
	}
}
