package api

import (
	"errors"
	"net/http"
	"net/url"

	principalsvc "github.com/fil-forge/hilt/pkg/api/service/principal"
	principalstore "github.com/fil-forge/hilt/pkg/store/principal"
	"github.com/labstack/echo/v4"
	"go.uber.org/zap"
)

// principalHTTPError maps a principal-service error to an echo HTTP error. Known
// errors (see the principal service's errors.go) become their mapped status with
// the error's own message and code; anything else is logged and returned as a 500.
func principalHTTPError(log *zap.Logger, err error) error {
	switch {
	case errors.Is(err, principalsvc.ErrTenantNotFound),
		errors.Is(err, principalsvc.ErrPrincipalNotFound):
		return httpError(http.StatusNotFound, err)
	case errors.Is(err, principalsvc.ErrInvalidPrincipalID):
		return httpError(http.StatusUnprocessableEntity, err)
	case errors.Is(err, principalsvc.ErrConcurrentChange):
		return httpError(http.StatusConflict, err)
	default:
		log.Error("request failed", zap.Error(err))
		return echo.NewHTTPError(http.StatusInternalServerError, "internal error")
	}
}

// principalParam returns the principalId route parameter decoded. Echo matches
// on the raw path and hands parameters over as they came, and the management
// client escapes each segment, so an id holding "/" arrives as "%2F". A value
// that is not a valid encoding is returned as it came.
func principalParam(c echo.Context) string {
	raw := c.Param("principalId")
	if id, err := url.PathUnescape(raw); err == nil {
		return id
	}
	return raw
}

// NewCreatePrincipalHandler handles PUT /tenants/{tenantId}/principals/{principalId}
// — record a principal of the tenant. It is idempotent: 201 when the call
// created the principal, 200 when it already existed.
func NewCreatePrincipalHandler(logger *zap.Logger, principals *principalsvc.Service) Route {
	log := logger.With(zap.String("handler", "CreatePrincipal"))
	return NewRoute(http.MethodPut, "/tenants/:tenantId/principals/:principalId", func(c echo.Context) error {
		rec, created, err := principals.Create(c.Request().Context(), c.Param("tenantId"), principalParam(c))
		if err != nil {
			return principalHTTPError(log, err)
		}
		status := http.StatusOK
		if created {
			status = http.StatusCreated
		}
		return c.JSON(status, principalResponse(rec))
	})
}

// NewListPrincipalsHandler handles GET /tenants/{tenantId}/principals — list the
// tenant's principals.
func NewListPrincipalsHandler(logger *zap.Logger, principals *principalsvc.Service) Route {
	log := logger.With(zap.String("handler", "ListPrincipals"))
	return NewRoute(http.MethodGet, "/tenants/:tenantId/principals", func(c echo.Context) error {
		recs, err := principals.List(c.Request().Context(), c.Param("tenantId"))
		if err != nil {
			return principalHTTPError(log, err)
		}
		items := make([]Principal, 0, len(recs))
		for _, rec := range recs {
			items = append(items, principalResponse(rec))
		}
		return c.JSON(http.StatusOK, PrincipalList{Items: items})
	})
}

// NewGetPrincipalHandler handles GET /tenants/{tenantId}/principals/{principalId} —
// retrieve one principal of the tenant.
func NewGetPrincipalHandler(logger *zap.Logger, principals *principalsvc.Service) Route {
	log := logger.With(zap.String("handler", "GetPrincipal"))
	return NewRoute(http.MethodGet, "/tenants/:tenantId/principals/:principalId", func(c echo.Context) error {
		rec, err := principals.Get(c.Request().Context(), c.Param("tenantId"), principalParam(c))
		if err != nil {
			return principalHTTPError(log, err)
		}
		return c.JSON(http.StatusOK, principalResponse(rec))
	})
}

// NewDeletePrincipalHandler handles DELETE /tenants/{tenantId}/principals/{principalId}
// — remove the principal, its access to every bucket, and its access keys. It
// answers 204 when the principal is already gone.
func NewDeletePrincipalHandler(logger *zap.Logger, principals *principalsvc.Service) Route {
	log := logger.With(zap.String("handler", "DeletePrincipal"))
	return NewRoute(http.MethodDelete, "/tenants/:tenantId/principals/:principalId", func(c echo.Context) error {
		if err := principals.Delete(c.Request().Context(), c.Param("tenantId"), principalParam(c)); err != nil {
			return principalHTTPError(log, err)
		}
		return c.NoContent(http.StatusNoContent)
	})
}

// principalResponse builds the API representation of a principal.
func principalResponse(rec principalstore.Record) Principal {
	return Principal{PrincipalID: rec.ExternalID, CreatedAt: rec.CreatedAt}
}
