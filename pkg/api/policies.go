package api

import (
	"errors"
	"net/http"
	"strings"

	bucketpolicysvc "github.com/fil-forge/hilt/pkg/api/service/bucketpolicy"
	"github.com/fil-forge/hilt/pkg/bucketpolicy"
	"github.com/labstack/echo/v4"
	"go.uber.org/zap"
)

// headerETag is the response header carrying the strong entity tag of a stored
// policy. echo names most headers but not this one.
const headerETag = "ETag"

// policyHTTPError maps a policy-service error to an echo HTTP error. Known
// errors (see the policy service's errors.go) become their mapped status with
// the error's own message; anything else is logged and returned as a 500.
func policyHTTPError(log *zap.Logger, err error) error {
	switch {
	case errors.Is(err, bucketpolicysvc.ErrTenantNotFound),
		errors.Is(err, bucketpolicysvc.ErrBucketNotFound),
		errors.Is(err, bucketpolicysvc.ErrPolicyNotFound),
		errors.Is(err, bucketpolicysvc.ErrPrincipalNotFound):
		return echo.NewHTTPError(http.StatusNotFound, err.Error())
	case errors.Is(err, bucketpolicysvc.ErrInvalidPrecondition):
		return echo.NewHTTPError(http.StatusBadRequest, err.Error())
	case errors.Is(err, bucketpolicysvc.ErrPreconditionFailed):
		return echo.NewHTTPError(http.StatusPreconditionFailed, err.Error())
	case errors.Is(err, bucketpolicysvc.ErrConcurrentChange):
		return echo.NewHTTPError(http.StatusConflict, err.Error())
	case errors.Is(err, bucketpolicy.ErrInvalidPolicy):
		return echo.NewHTTPError(http.StatusUnprocessableEntity, err.Error())
	default:
		log.Error("request failed", zap.Error(err))
		return echo.NewHTTPError(http.StatusInternalServerError, "internal error")
	}
}

// precondition reads the request's conditional headers. A write states the
// version it expects: If-Match with the current ETag replaces or deletes, and
// If-None-Match: * creates (reported as a nil tag). Anything else, including
// neither header and both, is [bucketpolicysvc.ErrInvalidPrecondition].
func precondition(c echo.Context) (*string, error) {
	ifMatch := strings.TrimSpace(c.Request().Header.Get("If-Match"))
	ifNoneMatch := strings.TrimSpace(c.Request().Header.Get("If-None-Match"))
	switch {
	case ifMatch != "" && ifNoneMatch != "":
		return nil, bucketpolicysvc.ErrInvalidPrecondition
	case ifNoneMatch == "*":
		return nil, nil
	case ifMatch != "" && ifNoneMatch == "":
		return &ifMatch, nil
	default:
		return nil, bucketpolicysvc.ErrInvalidPrecondition
	}
}

// NewGetBucketPolicyHandler handles
// GET /tenants/{tenantId}/buckets/{bucketName}/policy — read the bucket's
// policy. The ETag response header carries the tag the next write conditions
// on. A bucket that does not exist or belongs to another tenant is 404, as is
// a bucket with no policy, under its own error name.
func NewGetBucketPolicyHandler(logger *zap.Logger, policies *bucketpolicysvc.Service) Route {
	log := logger.With(zap.String("handler", "GetBucketPolicy"))
	return NewRoute(http.MethodGet, "/tenants/:tenantId/buckets/:bucketName/policy", func(c echo.Context) error {
		rec, err := policies.Get(c.Request().Context(), c.Param("tenantId"), c.Param("bucketName"))
		if err != nil {
			return policyHTTPError(log, err)
		}
		c.Response().Header().Set(headerETag, rec.ETag)
		return c.JSON(http.StatusOK, BucketPolicy(rec.Policy))
	})
}

// NewPutBucketPolicyHandler handles
// PUT /tenants/{tenantId}/buckets/{bucketName}/policy — create or replace the
// bucket's policy. It answers 201 for the create and 200 for a replace, with
// the new tag in the ETag header, 412 when the stored policy is not in the
// state the request conditioned on, and 422 for a document that names an
// unknown principal, an action outside the policy vocabulary, or no statement.
func NewPutBucketPolicyHandler(logger *zap.Logger, policies *bucketpolicysvc.Service) Route {
	log := logger.With(zap.String("handler", "PutBucketPolicy"))
	return NewRoute(http.MethodPut, "/tenants/:tenantId/buckets/:bucketName/policy", func(c echo.Context) error {
		ifMatch, err := precondition(c)
		if err != nil {
			return policyHTTPError(log, err)
		}
		var doc BucketPolicy
		if err := c.Bind(&doc); err != nil {
			return echo.NewHTTPError(http.StatusBadRequest, "invalid request body")
		}
		etag, created, err := policies.Put(c.Request().Context(),
			c.Param("tenantId"), c.Param("bucketName"), bucketpolicy.Policy(doc), ifMatch)
		if err != nil {
			return policyHTTPError(log, err)
		}
		c.Response().Header().Set(headerETag, etag)
		status := http.StatusOK
		if created {
			status = http.StatusCreated
		}
		return c.NoContent(status)
	})
}

// NewDeleteBucketPolicyHandler handles
// DELETE /tenants/{tenantId}/buckets/{bucketName}/policy — remove the bucket's
// policy. It requires If-Match and answers 412 on a mismatch. Every principal
// the policy reached loses its access to the bucket.
func NewDeleteBucketPolicyHandler(logger *zap.Logger, policies *bucketpolicysvc.Service) Route {
	log := logger.With(zap.String("handler", "DeleteBucketPolicy"))
	return NewRoute(http.MethodDelete, "/tenants/:tenantId/buckets/:bucketName/policy", func(c echo.Context) error {
		ifMatch, err := precondition(c)
		if err != nil || ifMatch == nil {
			// A delete has nothing to create, so If-None-Match: * is not a
			// precondition it can honour.
			return policyHTTPError(log, bucketpolicysvc.ErrInvalidPrecondition)
		}
		if err := policies.Delete(c.Request().Context(),
			c.Param("tenantId"), c.Param("bucketName"), *ifMatch); err != nil {
			return policyHTTPError(log, err)
		}
		return c.NoContent(http.StatusNoContent)
	})
}

// NewListPrincipalPoliciesHandler handles
// GET /tenants/{tenantId}/principals/{userId}/policies — every policy of the
// tenant with a statement naming the principal or the wildcard.
func NewListPrincipalPoliciesHandler(logger *zap.Logger, policies *bucketpolicysvc.Service) Route {
	log := logger.With(zap.String("handler", "ListPrincipalPolicies"))
	return NewRoute(http.MethodGet, "/tenants/:tenantId/principals/:userId/policies", func(c echo.Context) error {
		recs, err := policies.ListByPrincipal(c.Request().Context(), c.Param("tenantId"), c.Param("userId"))
		if err != nil {
			return policyHTTPError(log, err)
		}
		items := make([]PrincipalPolicy, 0, len(recs))
		for _, rec := range recs {
			items = append(items, PrincipalPolicy{BucketName: rec.BucketName, ETag: rec.ETag, Policy: rec.Policy})
		}
		return c.JSON(http.StatusOK, PrincipalPolicyList{Items: items})
	})
}

// NewGetPrincipalAccessHandler handles
// GET /tenants/{tenantId}/principals/{userId}/access — the principal's
// effective actions per bucket, computed from the tenant's stored policies.
// Buckets the principal has no action on are omitted.
func NewGetPrincipalAccessHandler(logger *zap.Logger, policies *bucketpolicysvc.Service) Route {
	log := logger.With(zap.String("handler", "GetPrincipalAccess"))
	return NewRoute(http.MethodGet, "/tenants/:tenantId/principals/:userId/access", func(c echo.Context) error {
		access, err := policies.Access(c.Request().Context(), c.Param("tenantId"), c.Param("userId"))
		if err != nil {
			return policyHTTPError(log, err)
		}
		buckets := make([]BucketAccess, 0, len(access))
		for _, a := range access {
			buckets = append(buckets, BucketAccess{Name: a.BucketName, Actions: a.Actions})
		}
		return c.JSON(http.StatusOK, PrincipalAccess{Buckets: buckets})
	})
}
