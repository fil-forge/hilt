package api

import (
	"errors"
	"net/http"

	accesskeysvc "github.com/fil-forge/hilt/pkg/api/service/accesskey"
	"github.com/fil-forge/hilt/pkg/store/accesskey"
	"github.com/fil-forge/ucantone/did"
	"github.com/labstack/echo/v4"
	"go.uber.org/zap"
)

// accessKeyHTTPError maps an access-key-service error to an echo HTTP error. Known
// errors (see the access-key service's errors.go) become their mapped status with
// the error's own message; anything else is logged and returned as a 500.
func accessKeyHTTPError(log *zap.Logger, err error) error {
	switch {
	case errors.Is(err, accesskeysvc.ErrTenantNotFound), errors.Is(err, accesskeysvc.ErrAccessKeyNotFound):
		return echo.NewHTTPError(http.StatusNotFound, err.Error())
	case errors.Is(err, accesskeysvc.ErrInvalidName),
		errors.Is(err, accesskeysvc.ErrNoPermissions),
		errors.Is(err, accesskeysvc.ErrInvalidPermission),
		errors.Is(err, accesskeysvc.ErrUnknownBucket):
		return echo.NewHTTPError(http.StatusUnprocessableEntity, err.Error())
	case errors.Is(err, accesskeysvc.ErrNameConflict):
		return echo.NewHTTPError(http.StatusConflict, err.Error())
	default:
		log.Error("request failed", zap.Error(err))
		return echo.NewHTTPError(http.StatusInternalServerError, "internal error")
	}
}

// NewCreateAccessKeyHandler handles POST /tenants/{tenantId}/access-keys — create
// an S3 access-key pair (returns the secret once only) and issue the
// tenant→access-key UCAN delegations for the requested permissions.
func NewCreateAccessKeyHandler(logger *zap.Logger, accessKeys *accesskeysvc.Service) Route {
	log := logger.With(zap.String("handler", "CreateAccessKey"))
	return NewRoute(http.MethodPost, "/tenants/:tenantId/access-keys", func(c echo.Context) error {
		var req CreateAccessKeyRequest
		if err := c.Bind(&req); err != nil {
			return echo.NewHTTPError(http.StatusBadRequest, "invalid request body")
		}

		rec, secret, err := accessKeys.Create(c.Request().Context(), c.Param("tenantId"), req.Name, req.Permissions, req.Buckets, req.ExpiresAt)
		if err != nil {
			return accessKeyHTTPError(log, err)
		}
		return c.JSON(http.StatusCreated, CreatedAccessKey{
			AccessKey: AccessKey{
				AccessKeyID: rec.ID.Identifier(),
				Name:        rec.Name,
				Permissions: rec.Permissions,
				Buckets:     req.Buckets,
				ExpiresAt:   rec.ExpiresAt,
				CreatedAt:   rec.CreatedAt,
			},
			SecretAccessKey: secret,
		})
	})
}

// NewListAccessKeysHandler handles GET /tenants/{tenantId}/access-keys — list all
// S3 access keys for a tenant (excludes secrets).
func NewListAccessKeysHandler(logger *zap.Logger, accessKeys *accesskeysvc.Service) Route {
	log := logger.With(zap.String("handler", "ListAccessKeys"))
	return NewRoute(http.MethodGet, "/tenants/:tenantId/access-keys", func(c echo.Context) error {
		recs, bucketNames, err := accessKeys.List(c.Request().Context(), c.Param("tenantId"))
		if err != nil {
			return accessKeyHTTPError(log, err)
		}
		items := make([]AccessKey, 0, len(recs))
		for _, rec := range recs {
			items = append(items, accessKeyResponse(rec, bucketNames))
		}
		return c.JSON(http.StatusOK, AccessKeyList{Items: items})
	})
}

// NewGetAccessKeyHandler handles GET /tenants/{tenantId}/access-keys/{accessKeyId}
// — retrieve access-key metadata (secret never returned).
func NewGetAccessKeyHandler(logger *zap.Logger, accessKeys *accesskeysvc.Service) Route {
	log := logger.With(zap.String("handler", "GetAccessKey"))
	return NewRoute(http.MethodGet, "/tenants/:tenantId/access-keys/:accessKeyId", func(c echo.Context) error {
		rec, bucketNames, err := accessKeys.Get(c.Request().Context(), c.Param("tenantId"), c.Param("accessKeyId"))
		if err != nil {
			return accessKeyHTTPError(log, err)
		}
		return c.JSON(http.StatusOK, accessKeyResponse(rec, bucketNames))
	})
}

// NewDeleteAccessKeyHandler handles DELETE /tenants/{tenantId}/access-keys/{accessKeyId}
// — revoke an S3 access key.
func NewDeleteAccessKeyHandler(logger *zap.Logger, accessKeys *accesskeysvc.Service) Route {
	log := logger.With(zap.String("handler", "DeleteAccessKey"))
	return NewRoute(http.MethodDelete, "/tenants/:tenantId/access-keys/:accessKeyId", func(c echo.Context) error {
		if err := accessKeys.Delete(c.Request().Context(), c.Param("tenantId"), c.Param("accessKeyId")); err != nil {
			return accessKeyHTTPError(log, err)
		}
		return c.NoContent(http.StatusNoContent)
	})
}

// accessKeyResponse builds the API representation of an access key, resolving
// stored bucket DIDs back to their names (a DID with no known name is rendered as
// the DID string). The secret is never included.
func accessKeyResponse(rec accesskey.Record, bucketNames map[did.DID]string) AccessKey {
	var bucketList []string
	for _, b := range rec.Buckets {
		if name, ok := bucketNames[b]; ok {
			bucketList = append(bucketList, name)
		} else {
			bucketList = append(bucketList, b.String())
		}
	}
	return AccessKey{
		AccessKeyID: rec.ID.Identifier(),
		Name:        rec.Name,
		Permissions: rec.Permissions,
		Buckets:     bucketList,
		ExpiresAt:   rec.ExpiresAt,
		CreatedAt:   rec.CreatedAt,
	}
}
