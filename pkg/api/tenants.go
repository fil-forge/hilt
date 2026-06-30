package api

import (
	"errors"
	"net/http"

	"github.com/fil-forge/hilt/pkg/store"
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
// key, publish them to the PLC directory, seal both private halves in the
// vault, and persist the tenant and wrap-key records. It is idempotent on the
// external {tenantId}.
func NewProvisionTenantHandler(
	logger *zap.Logger,
	tenants tenant.Store,
	providers provider.Store,
	wrapKeys wrapkey.Store,
	secrets vault.Vault,
	plcClient *plc.DirectoryClient,
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
		if req.DisplayName == "" {
			return echo.NewHTTPError(http.StatusBadRequest, "displayName is required")
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
		// for wrapping content-encryption keys, never for signing. It is
		// published in the genesis operation as a verification method at the
		// versioned fragment (wrap-1) so envelope holders can resolve it by kid.
		wrapKeyPair, err := x25519.Generate()
		if err != nil {
			log.Error("generating wrap key", zap.Error(err))
			return echo.NewHTTPError(http.StatusInternalServerError, "internal error")
		}
		wrapFragment := wrapkey.Fragment(1)

		tenantID, genesis, err := plc.New(
			signer,
			plc.WithRotationKeys(key),
			plc.WithVerificationMethods(map[string]did.DID{
				"hilt":       key,
				wrapFragment: wrapKeyPair.KeyDID(),
			}),
		)
		if err != nil {
			log.Error("building genesis operation", zap.Error(err))
			return echo.NewHTTPError(http.StatusInternalServerError, "internal error")
		}

		log := log.With(zap.String("external_id", externalID), zap.Stringer("tenant", tenantID))

		// Persist the private keys before publishing so they are never lost.
		// Store the multiformat-tagged bytes (Bytes()) so each key type is
		// recoverable on decode rather than assumed.
		tenantKeyVault := "/tenant/" + tenantID.String()
		if err := secrets.Write(ctx, tenantKeyVault, signer.Bytes()); err != nil {
			log.Error("storing tenant key", zap.Error(err))
			return echo.NewHTTPError(http.StatusInternalServerError, "internal error")
		}
		wrapKeyVault := wrapkey.VaultKey(tenantID, 1)
		if err := secrets.Write(ctx, wrapKeyVault, wrapKeyPair.Bytes()); err != nil {
			log.Error("storing wrap key", zap.Error(err))
			_ = secrets.Delete(ctx, tenantKeyVault) // best-effort cleanup of the orphaned key
			return echo.NewHTTPError(http.StatusInternalServerError, "internal error")
		}

		// Publish the genesis operation to register the did:plc.
		if err := plcClient.Update(ctx, tenantID, genesis); err != nil {
			log.Error("publishing genesis operation", zap.Error(err))
			// Best-effort cleanup of the orphaned keys.
			_ = secrets.Delete(ctx, wrapKeyVault)
			_ = secrets.Delete(ctx, tenantKeyVault)
			return echo.NewHTTPError(http.StatusBadGateway, "failed to register tenant DID")
		}

		// Record the tenant.
		if err := tenants.Add(ctx, tenantID, externalID, prov.ID, req.DisplayName, tenant.Active); err != nil {
			if errors.Is(err, store.ErrRecordExists) {
				// Best-effort cleanup of the orphaned keys.
				_ = secrets.Delete(ctx, wrapKeyVault)
				_ = secrets.Delete(ctx, tenantKeyVault)
				// Concurrent create with the same external id: return the winner.
				if rec, gerr := tenants.GetByExternalID(ctx, externalID); gerr == nil {
					return c.JSON(http.StatusOK, tenantResponse(rec))
				}
			}
			log.Error("storing tenant", zap.Error(err))
			return echo.NewHTTPError(http.StatusInternalServerError, "internal error")
		}

		// Record the active wrap key (version 1). The private half stays sealed
		// in the vault; only metadata is registered here.
		wrapRec := wrapkey.Record{
			Tenant:    tenantID,
			Version:   1,
			KID:       wrapkey.KID(tenantID, 1),
			PublicKey: wrapKeyPair.Public().String(),
			Status:    wrapkey.Active,
			VaultKey:  wrapKeyVault,
		}
		if err := wrapKeys.Add(ctx, wrapRec); err != nil {
			log.Error("storing wrap key record", zap.Error(err))
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
		TenantID:    rec.ExternalID,
		DisplayName: rec.Name,
		Status:      TenantStatus(rec.Status),
		CreatedAt:   rec.CreatedAt,
	}
}

// NewGetTenantHandler handles GET /tenants/{tenantId} — retrieve tenant
// operational state and quotas.
func NewGetTenantHandler(logger *zap.Logger) Route {
	return NewRoute(http.MethodGet, "/tenants/:tenantId", notImplemented(logger, "GetTenant"))
}

// NewDeleteTenantHandler handles DELETE /tenants/{tenantId} — permanently
// delete a tenant (must be disabled first).
func NewDeleteTenantHandler(logger *zap.Logger) Route {
	return NewRoute(http.MethodDelete, "/tenants/:tenantId", notImplemented(logger, "DeleteTenant"))
}

// NewUpdateTenantStatusHandler handles POST /tenants/{tenantId}/status — update
// tenant access mode.
func NewUpdateTenantStatusHandler(logger *zap.Logger) Route {
	return NewRoute(http.MethodPost, "/tenants/:tenantId/status", notImplemented(logger, "UpdateTenantStatus"))
}
