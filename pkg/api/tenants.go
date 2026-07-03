package api

import (
	"errors"
	"net/http"

	tenantsvc "github.com/fil-forge/hilt/pkg/api/service/tenant"
	"github.com/fil-forge/hilt/pkg/store/tenant"
	"github.com/labstack/echo/v4"
	"go.uber.org/zap"
)

// tenantHTTPError maps a tenant-service error to an echo HTTP error. Known errors
// (see the tenant service's errors.go) become their mapped status with the error's
// own message; anything else is logged and returned as a 500.
func tenantHTTPError(log *zap.Logger, err error) error {
	switch {
	case errors.Is(err, tenantsvc.ErrTenantNotFound):
		return echo.NewHTTPError(http.StatusNotFound, err.Error())
	case errors.Is(err, tenantsvc.ErrRegionRequired), errors.Is(err, tenantsvc.ErrUnknownRegion):
		return echo.NewHTTPError(http.StatusBadRequest, err.Error())
	case errors.Is(err, tenantsvc.ErrInvalidStatus):
		return echo.NewHTTPError(http.StatusUnprocessableEntity, err.Error())
	case errors.Is(err, tenantsvc.ErrTenantNotDisabled):
		return echo.NewHTTPError(http.StatusConflict, err.Error())
	case errors.Is(err, tenantsvc.ErrDIDRegistration),
		errors.Is(err, tenantsvc.ErrUploadRegistration),
		errors.Is(err, tenantsvc.ErrDIDDeactivation):
		return echo.NewHTTPError(http.StatusBadGateway, err.Error())
	default:
		log.Error("request failed", zap.Error(err))
		return echo.NewHTTPError(http.StatusInternalServerError, "internal error")
	}
}

// NewProvisionTenantHandler handles PUT /tenants/{tenantId} — provision a tenant
// (idempotent on the external {tenantId}).
func NewProvisionTenantHandler(logger *zap.Logger, tenants *tenantsvc.Service) Route {
	log := logger.With(zap.String("handler", "ProvisionTenant"))
	return NewRoute(http.MethodPut, "/tenants/:tenantId", func(c echo.Context) error {
		externalID := c.Param("tenantId")
		if externalID == "" {
			return echo.NewHTTPError(http.StatusBadRequest, "missing tenant id")
		}
		var req ProvisionTenantRequest
		if err := c.Bind(&req); err != nil {
			return echo.NewHTTPError(http.StatusBadRequest, "invalid request body")
		}

		rec, created, err := tenants.Provision(c.Request().Context(), externalID, req.Region)
		if err != nil {
			return tenantHTTPError(log, err)
		}
		if created {
			return c.JSON(http.StatusCreated, tenantResponse(rec))
		}
		return c.JSON(http.StatusOK, tenantResponse(rec))
	})
}

// NewGetTenantHandler handles GET /tenants/{tenantId} — retrieve tenant
// operational state and quotas.
func NewGetTenantHandler(logger *zap.Logger, tenants *tenantsvc.Service) Route {
	log := logger.With(zap.String("handler", "GetTenant"))
	return NewRoute(http.MethodGet, "/tenants/:tenantId", func(c echo.Context) error {
		rec, err := tenants.Get(c.Request().Context(), c.Param("tenantId"))
		if err != nil {
			return tenantHTTPError(log, err)
		}
		return c.JSON(http.StatusOK, tenantResponse(rec))
	})
}

// NewUpdateTenantStatusHandler handles POST /tenants/{tenantId}/status — update
// tenant access mode.
func NewUpdateTenantStatusHandler(logger *zap.Logger, tenants *tenantsvc.Service) Route {
	log := logger.With(zap.String("handler", "UpdateTenantStatus"))
	return NewRoute(http.MethodPost, "/tenants/:tenantId/status", func(c echo.Context) error {
		var req UpdateTenantStatusRequest
		if err := c.Bind(&req); err != nil {
			return echo.NewHTTPError(http.StatusBadRequest, "invalid request body")
		}
		if err := tenants.SetStatus(c.Request().Context(), c.Param("tenantId"), string(req.Status)); err != nil {
			return tenantHTTPError(log, err)
		}
		return c.NoContent(http.StatusNoContent)
	})
}

// NewDeleteTenantHandler handles DELETE /tenants/{tenantId} — permanently delete a
// tenant (must be disabled first). Idempotent.
func NewDeleteTenantHandler(logger *zap.Logger, tenants *tenantsvc.Service) Route {
	log := logger.With(zap.String("handler", "DeleteTenant"))
	return NewRoute(http.MethodDelete, "/tenants/:tenantId", func(c echo.Context) error {
		if err := tenants.Delete(c.Request().Context(), c.Param("tenantId")); err != nil {
			return tenantHTTPError(log, err)
		}
		return c.NoContent(http.StatusNoContent)
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
