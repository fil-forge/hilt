package api_test

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/fil-forge/hilt/internal/testutil"
	"github.com/fil-forge/hilt/pkg/api"
	principalsvc "github.com/fil-forge/hilt/pkg/api/service/principal"
	"github.com/fil-forge/hilt/pkg/bucketpolicy"
	"github.com/fil-forge/hilt/pkg/store"
	accesskeystore "github.com/fil-forge/hilt/pkg/store/accesskey"
	accesskeymemory "github.com/fil-forge/hilt/pkg/store/accesskey/memory"
	bucketpolicystore "github.com/fil-forge/hilt/pkg/store/bucketpolicy"
	bucketpolicymemory "github.com/fil-forge/hilt/pkg/store/bucketpolicy/memory"
	principalmemory "github.com/fil-forge/hilt/pkg/store/principal/memory"
	"github.com/fil-forge/hilt/pkg/store/tenant"
	tenantmemory "github.com/fil-forge/hilt/pkg/store/tenant/memory"
	"github.com/fil-forge/hilt/pkg/vault"
	vaultmemory "github.com/fil-forge/hilt/pkg/vault/memory"
	"github.com/fil-forge/ucantone/did"
	"github.com/fil-forge/ucantone/multikey/ed25519"
	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

type principalDeps struct {
	principals    *principalmemory.Store
	policies      *bucketpolicymemory.Store
	accessKeys    *accesskeymemory.Store
	vault         *vaultmemory.Store
	invalidations *recordingInvalidations
	tenantID      did.DID // "tenant-1"
}

// setupPrincipals serves every principal route over memory stores with two
// tenants.
func setupPrincipals(t *testing.T) (*echo.Echo, *principalDeps) {
	t.Helper()
	tenants := tenantmemory.New()
	deps := &principalDeps{
		principals:    principalmemory.New(),
		policies:      bucketpolicymemory.New(),
		accessKeys:    accesskeymemory.New(),
		vault:         vaultmemory.New(),
		invalidations: &recordingInvalidations{},
		tenantID:      testutil.RandomDID(t),
	}
	require.NoError(t, tenants.Add(t.Context(), deps.tenantID, "tenant-1", testutil.RandomDID(t), tenant.Active))
	require.NoError(t, tenants.Add(t.Context(), testutil.RandomDID(t), "tenant-2", testutil.RandomDID(t), tenant.Active))

	svc := principalsvc.New(zap.NewNop(), tenants, deps.principals, deps.policies, deps.accessKeys, deps.vault, deps.invalidations)
	e := echo.New()
	for _, r := range []api.Route{
		api.NewCreatePrincipalHandler(zap.NewNop(), svc),
		api.NewListPrincipalsHandler(zap.NewNop(), svc),
		api.NewGetPrincipalHandler(zap.NewNop(), svc),
		api.NewDeletePrincipalHandler(zap.NewNop(), svc),
		api.NewListPrincipalAccessKeysHandler(zap.NewNop(), svc),
	} {
		e.Add(r.Method, r.Path, r.Handler)
	}
	return e, deps
}

// createPrincipal records a principal through the API and fails the test if the
// call does not create it.
func createPrincipal(t *testing.T, e *echo.Echo, userID string) {
	t.Helper()
	rec := doRequest(t, e, http.MethodPut, "/tenants/tenant-1/principals/"+userID, nil)
	require.Equal(t, http.StatusCreated, rec.Code)
}

// addPrincipalKey stores a principal-bound access key and its vault entry the
// way the access-key create route does, so the principal routes have one to
// list and to remove.
func addPrincipalKey(t *testing.T, deps *principalDeps, userID, name string) did.DID {
	t.Helper()
	ctx := t.Context()
	signer, err := ed25519.Generate()
	require.NoError(t, err)
	id := signer.KeyDID()
	require.NoError(t, deps.accessKeys.Add(ctx, accesskeystore.Input{
		ID: id, Tenant: deps.tenantID, Name: name, Principal: &userID,
	}))
	require.NoError(t, deps.vault.Write(ctx, vault.AccessKeyPath(deps.tenantID, id), signer.Bytes()))
	return id
}

func TestCreatePrincipalHandler(t *testing.T) {
	t.Run("creates with 201 and repeats with 200", func(t *testing.T) {
		e, _ := setupPrincipals(t)
		rec := doRequest(t, e, http.MethodPut, "/tenants/tenant-1/principals/user-1", nil)
		require.Equal(t, http.StatusCreated, rec.Code)
		var p api.Principal
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &p))
		require.Equal(t, "user-1", p.UserID)
		require.False(t, p.CreatedAt.IsZero())

		again := doRequest(t, e, http.MethodPut, "/tenants/tenant-1/principals/user-1", nil)
		require.Equal(t, http.StatusOK, again.Code)
		var repeat api.Principal
		require.NoError(t, json.Unmarshal(again.Body.Bytes(), &repeat))
		require.Equal(t, p.CreatedAt, repeat.CreatedAt)
	})

	t.Run("unknown tenant is 404", func(t *testing.T) {
		e, _ := setupPrincipals(t)
		rec := doRequest(t, e, http.MethodPut, "/tenants/missing/principals/user-1", nil)
		require.Equal(t, http.StatusNotFound, rec.Code)
	})

	t.Run("the policy wildcard is 422", func(t *testing.T) {
		e, deps := setupPrincipals(t)
		rec := doRequest(t, e, http.MethodPut, "/tenants/tenant-1/principals/"+bucketpolicy.Wildcard, nil)
		require.Equal(t, http.StatusUnprocessableEntity, rec.Code)
		recs, err := deps.principals.ListByTenant(t.Context(), deps.tenantID)
		require.NoError(t, err)
		require.Empty(t, recs)
	})
}

func TestListGetPrincipalHandlers(t *testing.T) {
	e, _ := setupPrincipals(t)
	createPrincipal(t, e, "user-2")
	createPrincipal(t, e, "user-1")

	t.Run("lists the tenant's principals", func(t *testing.T) {
		rec := doRequest(t, e, http.MethodGet, "/tenants/tenant-1/principals", nil)
		require.Equal(t, http.StatusOK, rec.Code)
		var list api.PrincipalList
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &list))
		require.Len(t, list.Items, 2)
		require.Equal(t, "user-1", list.Items[0].UserID)
		require.Equal(t, "user-2", list.Items[1].UserID)
	})

	t.Run("gets one principal", func(t *testing.T) {
		rec := doRequest(t, e, http.MethodGet, "/tenants/tenant-1/principals/user-1", nil)
		require.Equal(t, http.StatusOK, rec.Code)
		var p api.Principal
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &p))
		require.Equal(t, "user-1", p.UserID)
	})

	t.Run("unknown principal is 404", func(t *testing.T) {
		rec := doRequest(t, e, http.MethodGet, "/tenants/tenant-1/principals/user-9", nil)
		require.Equal(t, http.StatusNotFound, rec.Code)
	})

	t.Run("another tenant's principal is 404", func(t *testing.T) {
		rec := doRequest(t, e, http.MethodGet, "/tenants/tenant-2/principals/user-1", nil)
		require.Equal(t, http.StatusNotFound, rec.Code)
	})
}

func TestDeletePrincipalHandler(t *testing.T) {
	ctx := t.Context()

	t.Run("removes the principal, its keys and its access, and is idempotent", func(t *testing.T) {
		e, deps := setupPrincipals(t)
		createPrincipal(t, e, "user-1")
		keyID := addPrincipalKey(t, deps, "user-1", "laptop")
		bucket := testutil.RandomDID(t)
		_, err := deps.policies.Put(ctx, bucketpolicystore.Input{
			Bucket: bucket,
			Tenant: deps.tenantID,
			Policy: bucketpolicy.Policy{Statements: []bucketpolicy.Statement{
				{Effect: bucketpolicy.Allow, Principals: []string{"user-1"}, Actions: []string{"s3:GetObject"}},
			}},
		}, nil)
		require.NoError(t, err)

		rec := doRequest(t, e, http.MethodDelete, "/tenants/tenant-1/principals/user-1", nil)
		require.Equal(t, http.StatusNoContent, rec.Code)
		require.Equal(t, []string{"user-1"}, deps.invalidations.principals)

		_, err = deps.accessKeys.Get(ctx, keyID)
		require.ErrorIs(t, err, store.ErrRecordNotFound)
		_, err = deps.vault.Read(ctx, vault.AccessKeyPath(deps.tenantID, keyID))
		require.ErrorIs(t, err, vault.ErrNotFound)
		_, err = deps.policies.Get(ctx, bucket)
		require.ErrorIs(t, err, store.ErrRecordNotFound)

		again := doRequest(t, e, http.MethodDelete, "/tenants/tenant-1/principals/user-1", nil)
		require.Equal(t, http.StatusNoContent, again.Code, "a principal already gone is 204")
	})

	t.Run("a failed invalidation is 500 and changes nothing", func(t *testing.T) {
		e, deps := setupPrincipals(t)
		createPrincipal(t, e, "user-1")
		deps.invalidations.err = errAssertPublishFailed

		rec := doRequest(t, e, http.MethodDelete, "/tenants/tenant-1/principals/user-1", nil)
		require.Equal(t, http.StatusInternalServerError, rec.Code)

		get := doRequest(t, e, http.MethodGet, "/tenants/tenant-1/principals/user-1", nil)
		require.Equal(t, http.StatusOK, get.Code)
	})

	t.Run("unknown tenant is 404", func(t *testing.T) {
		e, _ := setupPrincipals(t)
		rec := doRequest(t, e, http.MethodDelete, "/tenants/missing/principals/user-1", nil)
		require.Equal(t, http.StatusNotFound, rec.Code)
	})
}

func TestListPrincipalAccessKeysHandler(t *testing.T) {
	t.Run("lists the principal's keys and never the secret", func(t *testing.T) {
		e, deps := setupPrincipals(t)
		createPrincipal(t, e, "user-1")
		keyID := addPrincipalKey(t, deps, "user-1", "laptop")

		list := doRequest(t, e, http.MethodGet, "/tenants/tenant-1/principals/user-1/access-keys", nil)
		require.Equal(t, http.StatusOK, list.Code)
		require.NotContains(t, list.Body.String(), "secretAccessKey")
		var keys api.AccessKeyList
		require.NoError(t, json.Unmarshal(list.Body.Bytes(), &keys))
		require.Len(t, keys.Items, 1)
		require.Equal(t, keyID.Identifier(), keys.Items[0].AccessKeyID)
		require.Equal(t, "laptop", keys.Items[0].Name)
		require.Equal(t, "user-1", keys.Items[0].Principal)
		require.Empty(t, keys.Items[0].Permissions, "a principal-bound key carries none")
		require.Empty(t, keys.Items[0].Buckets, "a principal-bound key carries none")
	})

	t.Run("an unknown principal is 404", func(t *testing.T) {
		e, _ := setupPrincipals(t)
		list := doRequest(t, e, http.MethodGet, "/tenants/tenant-1/principals/user-1/access-keys", nil)
		require.Equal(t, http.StatusNotFound, list.Code)
	})
}
