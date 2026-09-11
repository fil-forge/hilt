package api_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/fil-forge/hilt/internal/testutil"
	"github.com/fil-forge/hilt/pkg/api"
	bucketpolicysvc "github.com/fil-forge/hilt/pkg/api/service/bucketpolicy"
	"github.com/fil-forge/hilt/pkg/bucketpolicy"
	bucketmemory "github.com/fil-forge/hilt/pkg/store/bucket/memory"
	bucketpolicymemory "github.com/fil-forge/hilt/pkg/store/bucketpolicy/memory"
	principalmemory "github.com/fil-forge/hilt/pkg/store/principal/memory"
	"github.com/fil-forge/hilt/pkg/store/tenant"
	tenantmemory "github.com/fil-forge/hilt/pkg/store/tenant/memory"
	"github.com/fil-forge/ucantone/did"
	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

const policyPath = "/tenants/tenant-1/buckets/photos/policy"

type policyDeps struct {
	buckets       *bucketmemory.Store
	principals    *principalmemory.Store
	invalidations *recordingInvalidations
	tenantID      did.DID // "tenant-1"
}

// setupPolicies serves every policy route over memory stores, with two tenants
// and one bucket, "photos", owned by "tenant-1".
func setupPolicies(t *testing.T) (*echo.Echo, *policyDeps) {
	t.Helper()
	tenants := tenantmemory.New()
	deps := &policyDeps{
		buckets:       bucketmemory.New(),
		principals:    principalmemory.New(),
		invalidations: &recordingInvalidations{},
		tenantID:      testutil.RandomDID(t),
	}
	require.NoError(t, tenants.Add(t.Context(), deps.tenantID, "tenant-1", testutil.RandomDID(t), tenant.Active))
	require.NoError(t, tenants.Add(t.Context(), testutil.RandomDID(t), "tenant-2", testutil.RandomDID(t), tenant.Active))
	require.NoError(t, deps.buckets.Add(t.Context(), testutil.RandomDID(t), deps.tenantID, "photos"))
	require.NoError(t, deps.principals.Add(t.Context(), deps.tenantID, "user-1"))

	svc := bucketpolicysvc.New(zap.NewNop(), tenants, deps.buckets, deps.principals, bucketpolicymemory.New(), deps.invalidations)
	e := echo.New()
	for _, r := range []api.Route{
		api.NewGetBucketPolicyHandler(zap.NewNop(), svc),
		api.NewPutBucketPolicyHandler(zap.NewNop(), svc),
		api.NewDeleteBucketPolicyHandler(zap.NewNop(), svc),
		api.NewListPrincipalPoliciesHandler(zap.NewNop(), svc),
		api.NewGetPrincipalAccessHandler(zap.NewNop(), svc),
	} {
		e.Add(r.Method, r.Path, r.Handler)
	}
	return e, deps
}

// doConditional issues a request carrying the given conditional headers.
func doConditional(t *testing.T, e *echo.Echo, method, target string, headers map[string]string, body []byte) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, target, bytes.NewReader(body))
	if len(body) > 0 {
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)
	return rec
}

func policyBody(t *testing.T, statements ...bucketpolicy.Statement) []byte {
	t.Helper()
	data, err := json.Marshal(bucketpolicy.Policy{Statements: statements})
	require.NoError(t, err)
	return data
}

func allowUser1(actions ...string) bucketpolicy.Statement {
	return bucketpolicy.Statement{Effect: bucketpolicy.Allow, Principals: []string{"user-1"}, Actions: actions}
}

// createPolicy writes the bucket's first policy and returns its ETag.
func createPolicy(t *testing.T, e *echo.Echo, body []byte) string {
	t.Helper()
	rec := doConditional(t, e, http.MethodPut, policyPath, map[string]string{"If-None-Match": "*"}, body)
	require.Equal(t, http.StatusCreated, rec.Code, rec.Body.String())
	etag := rec.Header().Get("ETag")
	require.NotEmpty(t, etag)
	return etag
}

func TestBucketPolicyHandlers(t *testing.T) {
	t.Run("creates with If-None-Match and reads back the same strong ETag", func(t *testing.T) {
		e, _ := setupPolicies(t)
		body := policyBody(t, allowUser1("s3:GetObject"))
		etag := createPolicy(t, e, body)

		rec := doRequest(t, e, http.MethodGet, policyPath, nil)
		require.Equal(t, http.StatusOK, rec.Code)
		require.Equal(t, etag, rec.Header().Get("ETag"))
		require.NotContains(t, etag, "W/", "the tag must be strong")

		var got bucketpolicy.Policy
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &got))
		require.Equal(t, bucketpolicy.Policy{Statements: []bucketpolicy.Statement{allowUser1("s3:GetObject")}}, got)
	})

	t.Run("a create over an existing policy is 412", func(t *testing.T) {
		e, _ := setupPolicies(t)
		createPolicy(t, e, policyBody(t, allowUser1("s3:GetObject")))

		rec := doConditional(t, e, http.MethodPut, policyPath,
			map[string]string{"If-None-Match": "*"}, policyBody(t, allowUser1("s3:PutObject")))
		require.Equal(t, http.StatusPreconditionFailed, rec.Code)
	})

	t.Run("a replace with the current ETag is 200 and returns the new one", func(t *testing.T) {
		e, _ := setupPolicies(t)
		etag := createPolicy(t, e, policyBody(t, allowUser1("s3:GetObject")))

		rec := doConditional(t, e, http.MethodPut, policyPath,
			map[string]string{"If-Match": etag}, policyBody(t, allowUser1("s3:GetObject", "s3:PutObject")))
		require.Equal(t, http.StatusOK, rec.Code)
		require.NotEmpty(t, rec.Header().Get("ETag"))
		require.NotEqual(t, etag, rec.Header().Get("ETag"))
	})

	t.Run("a replace with a stale ETag is 412", func(t *testing.T) {
		e, _ := setupPolicies(t)
		createPolicy(t, e, policyBody(t, allowUser1("s3:GetObject")))

		rec := doConditional(t, e, http.MethodPut, policyPath,
			map[string]string{"If-Match": `"stale"`}, policyBody(t, allowUser1("s3:PutObject")))
		require.Equal(t, http.StatusPreconditionFailed, rec.Code)
	})

	t.Run("a write without a precondition is refused, and 428 is never used", func(t *testing.T) {
		e, _ := setupPolicies(t)
		body := policyBody(t, allowUser1("s3:GetObject"))

		for _, headers := range []map[string]string{
			nil,
			{"If-None-Match": `"not-a-wildcard"`},
			{"If-Match": `"x"`, "If-None-Match": "*"},
		} {
			rec := doConditional(t, e, http.MethodPut, policyPath, headers, body)
			require.Equal(t, http.StatusBadRequest, rec.Code)
		}

		rec := doConditional(t, e, http.MethodDelete, policyPath, nil, nil)
		require.Equal(t, http.StatusBadRequest, rec.Code)
		// If-None-Match is not a precondition a delete can honour.
		rec = doConditional(t, e, http.MethodDelete, policyPath, map[string]string{"If-None-Match": "*"}, nil)
		require.Equal(t, http.StatusBadRequest, rec.Code)
	})

	t.Run("deletes with If-Match and answers 404 once the policy is gone", func(t *testing.T) {
		e, _ := setupPolicies(t)
		etag := createPolicy(t, e, policyBody(t, allowUser1("s3:GetObject")))

		rec := doConditional(t, e, http.MethodDelete, policyPath, map[string]string{"If-Match": etag}, nil)
		require.Equal(t, http.StatusNoContent, rec.Code)

		rec = doConditional(t, e, http.MethodDelete, policyPath, map[string]string{"If-Match": etag}, nil)
		require.Equal(t, http.StatusNotFound, rec.Code)
		require.Contains(t, rec.Body.String(), "bucket has no policy")
	})

	t.Run("a delete with a stale ETag is 412", func(t *testing.T) {
		e, _ := setupPolicies(t)
		createPolicy(t, e, policyBody(t, allowUser1("s3:GetObject")))

		rec := doConditional(t, e, http.MethodDelete, policyPath, map[string]string{"If-Match": `"stale"`}, nil)
		require.Equal(t, http.StatusPreconditionFailed, rec.Code)
	})

	t.Run("a document the caller may not store is 422", func(t *testing.T) {
		e, _ := setupPolicies(t)
		create := map[string]string{"If-None-Match": "*"}

		for _, body := range [][]byte{
			policyBody(t, bucketpolicy.Statement{Effect: bucketpolicy.Allow, Principals: []string{"ghost"}, Actions: []string{"s3:GetObject"}}),
			policyBody(t, allowUser1("s3:CreateBucket")),
			policyBody(t),
		} {
			rec := doConditional(t, e, http.MethodPut, policyPath, create, body)
			require.Equal(t, http.StatusUnprocessableEntity, rec.Code, string(body))
		}
	})

	t.Run("a missing bucket, a foreign bucket and a bucket without a policy are 404", func(t *testing.T) {
		e, _ := setupPolicies(t)

		rec := doRequest(t, e, http.MethodGet, "/tenants/tenant-1/buckets/nope/policy", nil)
		require.Equal(t, http.StatusNotFound, rec.Code)
		require.Contains(t, rec.Body.String(), "bucket not found")

		rec = doRequest(t, e, http.MethodGet, "/tenants/tenant-2/buckets/photos/policy", nil)
		require.Equal(t, http.StatusNotFound, rec.Code)
		require.Contains(t, rec.Body.String(), "bucket not found")

		// A bucket with no policy is 404 under its own message, so a caller can
		// tell it from a bucket it may not see.
		rec = doRequest(t, e, http.MethodGet, policyPath, nil)
		require.Equal(t, http.StatusNotFound, rec.Code)
		require.Contains(t, rec.Body.String(), "bucket has no policy")
	})

	t.Run("an unknown tenant is 404", func(t *testing.T) {
		e, _ := setupPolicies(t)
		rec := doRequest(t, e, http.MethodGet, "/tenants/missing/buckets/photos/policy", nil)
		require.Equal(t, http.StatusNotFound, rec.Code)
		require.Contains(t, rec.Body.String(), "tenant not found")
	})
}

func TestPrincipalPolicyReadHandlers(t *testing.T) {
	t.Run("lists the policies naming the principal", func(t *testing.T) {
		e, _ := setupPolicies(t)
		etag := createPolicy(t, e, policyBody(t, allowUser1("s3:GetObject")))

		rec := doRequest(t, e, http.MethodGet, "/tenants/tenant-1/principals/user-1/policies", nil)
		require.Equal(t, http.StatusOK, rec.Code)
		var list api.PrincipalPolicyList
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &list))
		require.Len(t, list.Items, 1)
		require.Equal(t, "photos", list.Items[0].BucketName)
		require.Equal(t, etag, list.Items[0].ETag)
	})

	t.Run("reports the principal's effective actions per bucket", func(t *testing.T) {
		e, _ := setupPolicies(t)
		createPolicy(t, e, policyBody(t, allowUser1("s3:GetObject", "s3:ListBucket")))

		rec := doRequest(t, e, http.MethodGet, "/tenants/tenant-1/principals/user-1/access", nil)
		require.Equal(t, http.StatusOK, rec.Code)
		var access api.PrincipalAccess
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &access))
		require.Equal(t, []api.BucketAccess{
			{Name: "photos", Actions: []string{"s3:GetObject", "s3:ListBucket"}},
		}, access.Buckets)
	})

	t.Run("a bucket the principal cannot reach is omitted", func(t *testing.T) {
		e, deps := setupPolicies(t)
		require.NoError(t, deps.principals.Add(t.Context(), deps.tenantID, "user-2"))
		createPolicy(t, e, policyBody(t, allowUser1("s3:GetObject")))

		rec := doRequest(t, e, http.MethodGet, "/tenants/tenant-1/principals/user-2/access", nil)
		require.Equal(t, http.StatusOK, rec.Code)
		var access api.PrincipalAccess
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &access))
		require.Empty(t, access.Buckets)
	})

	t.Run("an unknown principal is 404", func(t *testing.T) {
		e, _ := setupPolicies(t)
		for _, path := range []string{
			"/tenants/tenant-1/principals/ghost/policies",
			"/tenants/tenant-1/principals/ghost/access",
		} {
			rec := doRequest(t, e, http.MethodGet, path, nil)
			require.Equal(t, http.StatusNotFound, rec.Code)
		}
	})
}
