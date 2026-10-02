package api

import (
	"errors"
	"net/http"
	"net/url"

	tenantsvc "github.com/fil-forge/hilt/pkg/api/service/tenant"
	"github.com/fil-forge/hilt/pkg/store/tenant"
	"github.com/labstack/echo/v4"
	"go.uber.org/zap"
)

// tenantHTTPError maps a tenant-service error to an echo HTTP error. Known errors
// (see the tenant service's errors.go) become their mapped status with the error's
// own message and code; anything else is logged and returned as a 500.
func tenantHTTPError(log *zap.Logger, err error) error {
	switch {
	case errors.Is(err, tenantsvc.ErrTenantNotFound):
		return httpError(http.StatusNotFound, err)
	case errors.Is(err, tenantsvc.ErrRegionRequired), errors.Is(err, tenantsvc.ErrUnknownRegion):
		return httpError(http.StatusBadRequest, err)
	case errors.Is(err, tenantsvc.ErrInvalidStatus):
		return httpError(http.StatusUnprocessableEntity, err)
	case errors.Is(err, tenantsvc.ErrTenantNotDisabled):
		return httpError(http.StatusConflict, err)
	case errors.Is(err, tenantsvc.ErrDIDRegistration),
		errors.Is(err, tenantsvc.ErrUploadRegistration),
		errors.Is(err, tenantsvc.ErrDIDDeactivation):
		return httpError(http.StatusBadGateway, err)
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
		externalID := tenantParam(c)
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

// pathParam returns a route parameter decoded. The management client escapes
// each path segment, so an id holding "/" or a space arrives escaped; Echo
// matches on the raw path when the request has one and hands the parameter
// over as it came, and then it is decoded here. A request with no raw path was
// routed on the decoded path, and its parameter is already decoded: decoding
// it again would turn an id holding "%25" into one holding "%".
func pathParam(c echo.Context, name string) string {
	raw := c.Param(name)
	if c.Request().URL.RawPath == "" {
		return raw
	}
	if id, err := url.PathUnescape(raw); err == nil {
		return id
	}
	return raw
}

// tenantParam returns the tenantId route parameter decoded, see pathParam.
// Without it an id holding "/" or a space would be looked up, and
// provisioned, in its escaped form.
func tenantParam(c echo.Context) string { return pathParam(c, "tenantId") }

// NewGetTenantHandler handles GET /tenants/{tenantId} — retrieve tenant
// operational state and quotas.
func NewGetTenantHandler(logger *zap.Logger, tenants *tenantsvc.Service) Route {
	log := logger.With(zap.String("handler", "GetTenant"))
	return NewRoute(http.MethodGet, "/tenants/:tenantId", func(c echo.Context) error {
		rec, err := tenants.Get(c.Request().Context(), tenantParam(c))
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
		if err := tenants.SetStatus(c.Request().Context(), tenantParam(c), string(req.Status)); err != nil {
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
		if err := tenants.Delete(c.Request().Context(), tenantParam(c)); err != nil {
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
