package api

import (
	"net/http"

	"go.uber.org/zap"
)

// NewProvisionTenantHandler handles PUT /tenants/{tenantId} — provision a
// tenant with full setup.
func NewProvisionTenantHandler(logger *zap.Logger) Route {
	return NewRoute(http.MethodPut, "/tenants/:tenantId", notImplemented(logger, "ProvisionTenant"))
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
