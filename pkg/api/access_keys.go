package api

import (
	"net/http"

	"go.uber.org/zap"
)

// NewCreateAccessKeyHandler handles POST /tenants/{tenantId}/access-keys —
// create an S3 access-key pair (returns the secret once only).
func NewCreateAccessKeyHandler(logger *zap.Logger) Route {
	return NewRoute(http.MethodPost, "/tenants/:tenantId/access-keys", notImplemented(logger, "CreateAccessKey"))
}

// NewListAccessKeysHandler handles GET /tenants/{tenantId}/access-keys — list
// all S3 access keys for a tenant (excludes secrets).
func NewListAccessKeysHandler(logger *zap.Logger) Route {
	return NewRoute(http.MethodGet, "/tenants/:tenantId/access-keys", notImplemented(logger, "ListAccessKeys"))
}

// NewGetAccessKeyHandler handles GET /tenants/{tenantId}/access-keys/{accessKeyId}
// — retrieve access-key metadata (secret never returned).
func NewGetAccessKeyHandler(logger *zap.Logger) Route {
	return NewRoute(http.MethodGet, "/tenants/:tenantId/access-keys/:accessKeyId", notImplemented(logger, "GetAccessKey"))
}

// NewDeleteAccessKeyHandler handles DELETE /tenants/{tenantId}/access-keys/{accessKeyId}
// — revoke an S3 access key (idempotent).
func NewDeleteAccessKeyHandler(logger *zap.Logger) Route {
	return NewRoute(http.MethodDelete, "/tenants/:tenantId/access-keys/:accessKeyId", notImplemented(logger, "DeleteAccessKey"))
}
