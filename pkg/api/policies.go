package api

import (
	"errors"
	"net/http"

	bucketpolicysvc "github.com/fil-forge/hilt/pkg/api/service/bucketpolicy"
	"github.com/fil-forge/hilt/pkg/bucketpolicy"
	"github.com/labstack/echo/v4"
	"go.uber.org/zap"
)

// policyHTTPError maps a policy-service error to an echo HTTP error. Known
// errors (see the policy service's errors.go) become their mapped status with
// the error's own message and code; anything else is logged and returned as a
// 500. The code is what tells a bucket with no policy from a bucket that is not
// there, since both are 404.
func policyHTTPError(log *zap.Logger, err error) error {
	switch {
	case errors.Is(err, bucketpolicysvc.ErrTenantNotFound),
		errors.Is(err, bucketpolicysvc.ErrBucketNotFound),
		errors.Is(err, bucketpolicysvc.ErrPolicyNotFound),
		errors.Is(err, bucketpolicysvc.ErrPrincipalNotFound):
		return httpError(http.StatusNotFound, err)
	case errors.Is(err, bucketpolicysvc.ErrInvalidPrecondition):
		return httpError(http.StatusBadRequest, err)
	case errors.Is(err, bucketpolicysvc.ErrPreconditionFailed):
		return httpError(http.StatusPreconditionFailed, err)
	case errors.Is(err, bucketpolicysvc.ErrConcurrentChange):
		return httpError(http.StatusConflict, err)
	case errors.Is(err, bucketpolicy.ErrInvalidPolicy):
		return httpError(http.StatusUnprocessableEntity, err)
	default:
		log.Error("request failed", zap.Error(err))
		return echo.NewHTTPError(http.StatusInternalServerError, "internal error")
	}
}

// NewListPrincipalPoliciesHandler handles
// GET /tenants/{tenantId}/principals/{principalId}/policies — every policy of the
// tenant with a statement naming the principal or the wildcard.
func NewListPrincipalPoliciesHandler(logger *zap.Logger, policies *bucketpolicysvc.Service) Route {
	log := logger.With(zap.String("handler", "ListPrincipalPolicies"))
	return NewRoute(http.MethodGet, "/tenants/:tenantId/principals/:principalId/policies", func(c echo.Context) error {
		recs, err := policies.ListByPrincipal(c.Request().Context(), tenantParam(c), principalParam(c))
		if err != nil {
			return policyHTTPError(log, err)
		}
		items := make([]PrincipalPolicy, len(recs))
		for i, r := range recs {
			items[i] = PrincipalPolicy{BucketName: r.BucketName, ETag: r.ETag, Policy: r.Policy}
		}
		return c.JSON(http.StatusOK, PrincipalPolicyList{Items: items})
	})
}

// NewGetPrincipalAccessHandler handles
// GET /tenants/{tenantId}/principals/{principalId}/access — the principal's
// effective actions per bucket, computed from the tenant's stored policies.
// Buckets the principal has no action on are omitted.
func NewGetPrincipalAccessHandler(logger *zap.Logger, policies *bucketpolicysvc.Service) Route {
	log := logger.With(zap.String("handler", "GetPrincipalAccess"))
	return NewRoute(http.MethodGet, "/tenants/:tenantId/principals/:principalId/access", func(c echo.Context) error {
		access, err := policies.Access(c.Request().Context(), tenantParam(c), principalParam(c))
		if err != nil {
			return policyHTTPError(log, err)
		}
		buckets := make([]BucketAccess, len(access))
		for i, a := range access {
			buckets[i] = BucketAccess{Name: a.Name, Actions: a.Actions}
		}
		return c.JSON(http.StatusOK, PrincipalAccess{Buckets: buckets})
	})
}
