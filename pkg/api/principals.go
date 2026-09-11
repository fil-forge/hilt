package api

import (
	"errors"
	"net/http"

	principalsvc "github.com/fil-forge/hilt/pkg/api/service/principal"
	principalstore "github.com/fil-forge/hilt/pkg/store/principal"
	"github.com/labstack/echo/v4"
	"go.uber.org/zap"
)

// principalHTTPError maps a principal-service error to an echo HTTP error. Known
// errors (see the principal service's errors.go) become their mapped status with
// the error's own message; anything else is logged and returned as a 500.
func principalHTTPError(log *zap.Logger, err error) error {
	switch {
	case errors.Is(err, principalsvc.ErrTenantNotFound),
		errors.Is(err, principalsvc.ErrPrincipalNotFound):
		return echo.NewHTTPError(http.StatusNotFound, err.Error())
	case errors.Is(err, principalsvc.ErrInvalidUserID):
		return echo.NewHTTPError(http.StatusUnprocessableEntity, err.Error())
	case errors.Is(err, principalsvc.ErrConcurrentChange):
		return echo.NewHTTPError(http.StatusConflict, err.Error())
	default:
		log.Error("request failed", zap.Error(err))
		return echo.NewHTTPError(http.StatusInternalServerError, "internal error")
	}
}

// NewCreatePrincipalHandler handles PUT /tenants/{tenantId}/principals/{userId}
// — record a principal of the tenant. It is idempotent: 201 when the call
// created the principal, 200 when it already existed.
func NewCreatePrincipalHandler(logger *zap.Logger, principals *principalsvc.Service) Route {
	log := logger.With(zap.String("handler", "CreatePrincipal"))
	return NewRoute(http.MethodPut, "/tenants/:tenantId/principals/:userId", func(c echo.Context) error {
		rec, created, err := principals.Create(c.Request().Context(), c.Param("tenantId"), c.Param("userId"))
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

// NewGetPrincipalHandler handles GET /tenants/{tenantId}/principals/{userId} —
// retrieve one principal of the tenant.
func NewGetPrincipalHandler(logger *zap.Logger, principals *principalsvc.Service) Route {
	log := logger.With(zap.String("handler", "GetPrincipal"))
	return NewRoute(http.MethodGet, "/tenants/:tenantId/principals/:userId", func(c echo.Context) error {
		rec, err := principals.Get(c.Request().Context(), c.Param("tenantId"), c.Param("userId"))
		if err != nil {
			return principalHTTPError(log, err)
		}
		return c.JSON(http.StatusOK, principalResponse(rec))
	})
}

// NewDeletePrincipalHandler handles DELETE /tenants/{tenantId}/principals/{userId}
// — remove the principal, its access to every bucket, and its access keys. It
// answers 204 when the principal is already gone.
func NewDeletePrincipalHandler(logger *zap.Logger, principals *principalsvc.Service) Route {
	log := logger.With(zap.String("handler", "DeletePrincipal"))
	return NewRoute(http.MethodDelete, "/tenants/:tenantId/principals/:userId", func(c echo.Context) error {
		if err := principals.Delete(c.Request().Context(), c.Param("tenantId"), c.Param("userId")); err != nil {
			return principalHTTPError(log, err)
		}
		return c.NoContent(http.StatusNoContent)
	})
}

// NewListPrincipalAccessKeysHandler handles
// GET /tenants/{tenantId}/principals/{userId}/access-keys — list the keys bound
// to the principal (excludes secrets).
func NewListPrincipalAccessKeysHandler(logger *zap.Logger, principals *principalsvc.Service) Route {
	log := logger.With(zap.String("handler", "ListPrincipalAccessKeys"))
	return NewRoute(http.MethodGet, "/tenants/:tenantId/principals/:userId/access-keys", func(c echo.Context) error {
		recs, err := principals.ListAccessKeys(c.Request().Context(), c.Param("tenantId"), c.Param("userId"))
		if err != nil {
			return principalHTTPError(log, err)
		}
		// A principal-bound key references no bucket, so no name map is needed.
		items := make([]AccessKey, 0, len(recs))
		for _, rec := range recs {
			items = append(items, accessKeyResponse(rec, nil))
		}
		return c.JSON(http.StatusOK, AccessKeyList{Items: items})
	})
}

// principalResponse builds the API representation of a principal.
func principalResponse(rec principalstore.Record) Principal {
	return Principal{UserID: rec.ExternalID, CreatedAt: rec.CreatedAt}
}
