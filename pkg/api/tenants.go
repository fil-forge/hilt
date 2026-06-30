package api

import (
	"errors"
	"net/http"

	"github.com/fil-forge/hilt/pkg/store"
	"github.com/fil-forge/hilt/pkg/store/provider"
	"github.com/fil-forge/hilt/pkg/store/tenant"
	"github.com/fil-forge/hilt/pkg/vault"
	"github.com/fil-forge/ucantone/did"
	"github.com/fil-forge/ucantone/did/plc"
	"github.com/fil-forge/ucantone/multikey/secp256k1"
	"github.com/labstack/echo/v4"
	"go.uber.org/zap"
)

// NewProvisionTenantHandler handles PUT /tenants/{tenantId} — provision a
// tenant: generate a rotatable did:plc tenant key, publish it to the PLC
// directory, store the private key in the vault, and persist the tenant record.
// It is idempotent on the external {tenantId}.
func NewProvisionTenantHandler(
	logger *zap.Logger,
	tenants tenant.Store,
	providers provider.Store,
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
		tenantID, genesis, err := plc.New(
			signer,
			plc.WithRotationKeys([]did.DID{key}),
			plc.WithVerificationMethods(map[string]did.DID{"hilt": key}),
		)
		if err != nil {
			log.Error("building genesis operation", zap.Error(err))
			return echo.NewHTTPError(http.StatusInternalServerError, "internal error")
		}

		log := log.With(zap.String("external_id", externalID), zap.Stringer("tenant", tenantID))

		// Persist the private key before publishing so it is never lost. Store
		// the multiformat-tagged bytes (signer.Bytes()) so the key type is
		// recoverable on decode rather than assuming secp256k1.
		vaultKey := "/tenant/" + tenantID.String()
		if err := secrets.Write(ctx, vaultKey, signer.Bytes()); err != nil {
			log.Error("storing tenant key", zap.Error(err))
			return echo.NewHTTPError(http.StatusInternalServerError, "internal error")
		}

		// Publish the genesis operation to register the did:plc.
		if err := plcClient.Update(ctx, tenantID, genesis); err != nil {
			log.Error("publishing genesis operation", zap.Error(err))
			_ = secrets.Delete(ctx, vaultKey) // best-effort cleanup of the orphaned key
			return echo.NewHTTPError(http.StatusBadGateway, "failed to register tenant DID")
		}

		// Record the tenant.
		if err := tenants.Add(ctx, tenantID, externalID, prov.ID, req.DisplayName, tenant.Active); err != nil {
			if errors.Is(err, store.ErrRecordExists) {
				_ = secrets.Delete(ctx, vaultKey) // best-effort cleanup of the orphaned key
				// Concurrent create with the same external id: return the winner.
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
