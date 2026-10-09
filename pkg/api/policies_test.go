package api_test

import (
	"encoding/json"
	"maps"
	"net/http"
	"slices"
	"testing"

	"github.com/fil-forge/hilt/internal/testutil"
	"github.com/fil-forge/hilt/pkg/api"
	bucketpolicysvc "github.com/fil-forge/hilt/pkg/api/service/bucketpolicy"
	"github.com/fil-forge/hilt/pkg/bucketpolicy"
	"github.com/fil-forge/hilt/pkg/grant"
	accesskeymemory "github.com/fil-forge/hilt/pkg/store/accesskey/memory"
	bucketmemory "github.com/fil-forge/hilt/pkg/store/bucket/memory"
	bucketpolicymemory "github.com/fil-forge/hilt/pkg/store/bucketpolicy/memory"
	delegationmemory "github.com/fil-forge/hilt/pkg/store/delegation/memory"
	principalmemory "github.com/fil-forge/hilt/pkg/store/principal/memory"
	"github.com/fil-forge/hilt/pkg/store/tenant"
	tenantmemory "github.com/fil-forge/hilt/pkg/store/tenant/memory"
	vaultmemory "github.com/fil-forge/hilt/pkg/vault/memory"
	"github.com/fil-forge/ucantone/did"
	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

type policyDeps struct {
	buckets    *bucketmemory.Store
	principals *principalmemory.Store
	policies   *bucketpolicysvc.Service
	tenantID   did.DID // "tenant-1"
	photos     did.DID
}

// setupPolicies serves every policy route over memory stores, with two tenants
// and one bucket, "photos", owned by "tenant-1".
func setupPolicies(t *testing.T) (*echo.Echo, *policyDeps) {
	t.Helper()
	tenants := tenantmemory.New()
	deps := &policyDeps{
		buckets:    bucketmemory.New(),
		principals: principalmemory.New(),
		tenantID:   testutil.RandomDID(t),
		photos:     testutil.RandomDID(t),
	}
	require.NoError(t, tenants.Add(t.Context(), deps.tenantID, "tenant-1", testutil.RandomDID(t), tenant.Active))
	require.NoError(t, tenants.Add(t.Context(), testutil.RandomDID(t), "tenant-2", testutil.RandomDID(t), tenant.Active))
	require.NoError(t, deps.buckets.Add(t.Context(), deps.photos, deps.tenantID, "photos"))
	require.NoError(t, deps.principals.Add(t.Context(), deps.tenantID, "user-1"))

	// No principal holds a key here, so the grant rotator has nothing to
	// issue; the routes are what is under test.
	grants := grant.NewRotator(zap.NewNop(), delegationmemory.New(), accesskeymemory.New(), vaultmemory.New(), &testutil.FakeSwarf{})
	svc := bucketpolicysvc.New(zap.NewNop(), tenants, deps.buckets, deps.principals, bucketpolicymemory.New(), grants)
	deps.policies = svc
	e := echo.New()
	for _, r := range []api.Route{
		api.NewListPrincipalPoliciesHandler(zap.NewNop(), svc),
		api.NewGetPrincipalAccessHandler(zap.NewNop(), svc),
	} {
		e.Add(r.Method, r.Path, r.Handler)
	}
	return e, deps
}

func allowUser1(actions ...string) bucketpolicy.Statement {
	return bucketpolicy.Statement{Effect: bucketpolicy.Allow, Principal: bucketpolicy.Only("user-1"), Actions: actions}
}

// createPolicy writes the photos bucket's first policy through the service,
// as the S3 PutBucketPolicy path does, and returns its ETag.
func createPolicy(t *testing.T, deps *policyDeps, statements ...bucketpolicy.Statement) string {
	t.Helper()
	etag, _, err := deps.policies.Write(t.Context(), deps.tenantID, deps.photos, "photos", bucketpolicy.Policy{Statements: statements}, nil)
	require.NoError(t, err)
	return etag
}

func TestPrincipalPolicyReadHandlers(t *testing.T) {
	t.Run("lists the policies naming the principal", func(t *testing.T) {
		e, deps := setupPolicies(t)
		createPolicy(t, deps, allowUser1("s3:GetObject"))

		rec := doRequest(t, e, http.MethodGet, "/tenants/tenant-1/principals/user-1/policies", nil)
		require.Equal(t, http.StatusOK, rec.Code)
		var raw struct {
			Items []map[string]json.RawMessage `json:"items"`
		}
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &raw))
		require.Len(t, raw.Items, 1)
		require.ElementsMatch(t, []string{"bucketName", "policy"}, slices.Collect(maps.Keys(raw.Items[0])))

		var list api.PrincipalPolicyList
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &list))
		require.Equal(t, []api.PrincipalPolicy{
			{BucketName: "photos", Policy: bucketpolicy.Policy{Statements: []bucketpolicy.Statement{allowUser1("s3:GetObject")}}},
		}, list.Items)
	})

	t.Run("reports the principal's effective actions per bucket", func(t *testing.T) {
		e, deps := setupPolicies(t)
		createPolicy(t, deps, allowUser1("s3:GetObject", "s3:ListBucket"))

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
		createPolicy(t, deps, allowUser1("s3:GetObject"))

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

	t.Run("a principalId holding a slash is refused", func(t *testing.T) {
		e, _ := setupPolicies(t)
		for _, route := range []string{"access", "policies"} {
			rec := doRequest(t, e, http.MethodGet, "/tenants/tenant-1/principals/a%2Fb/"+route, nil)
			require.Equal(t, http.StatusUnprocessableEntity, rec.Code, route)
			require.Equal(t, "InvalidPrincipalID", decodeError(t, rec).Code, route)
		}
	})
}
