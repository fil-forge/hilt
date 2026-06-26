package api_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/fil-forge/hilt/internal/testutil"
	"github.com/fil-forge/hilt/pkg/api"
	"github.com/fil-forge/hilt/pkg/store/provider"
	providermemory "github.com/fil-forge/hilt/pkg/store/provider/memory"
	"github.com/fil-forge/hilt/pkg/store/tenant"
	tenantmemory "github.com/fil-forge/hilt/pkg/store/tenant/memory"
	"github.com/fil-forge/hilt/pkg/vault"
	vaultmemory "github.com/fil-forge/hilt/pkg/vault/memory"
	"github.com/fil-forge/ucantone/did/plc"
	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

type provisionDeps struct {
	tenants   tenant.Store
	providers provider.Store
	vault     vault.Vault
	plcPosts  int
}

// setupProvision builds an echo server with the provision handler wired to
// memory stores/vault and a PLC directory client pointed at an httptest server
// that accepts genesis operations (no real PLC network).
func setupProvision(t *testing.T) (*echo.Echo, *provisionDeps) {
	t.Helper()
	deps := &provisionDeps{
		tenants:   tenantmemory.New(),
		providers: providermemory.New(),
		vault:     vaultmemory.New(),
	}

	plcServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			deps.plcPosts++
		}
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(plcServer.Close)

	endpoint, err := url.Parse(plcServer.URL)
	require.NoError(t, err)
	plcClient, err := plc.NewDirectoryClient(*endpoint)
	require.NoError(t, err)

	route := api.NewProvisionTenantHandler(zap.NewNop(), deps.tenants, deps.providers, deps.vault, plcClient)
	e := echo.New()
	e.Add(route.Method, route.Path, route.Handler)
	return e, deps
}

func provisionRequest(t *testing.T, e *echo.Echo, tenantID string, body api.ProvisionTenantRequest) *httptest.ResponseRecorder {
	t.Helper()
	encoded, err := json.Marshal(body)
	require.NoError(t, err)
	req := httptest.NewRequest(http.MethodPut, "/tenants/"+tenantID, bytes.NewReader(encoded))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)
	return rec
}

func TestProvisionTenantHandler(t *testing.T) {
	ctx := t.Context()

	t.Run("provisions a new tenant", func(t *testing.T) {
		e, deps := setupProvision(t)
		require.NoError(t, deps.providers.Add(ctx, testutil.RandomDID(t), "us-east-1"))

		rec := provisionRequest(t, e, "tenant-1", api.ProvisionTenantRequest{DisplayName: "Acme", Region: "us-east-1"})
		require.Equal(t, http.StatusCreated, rec.Code)
		require.Contains(t, rec.Body.String(), `"tenantId":"tenant-1"`)
		require.Contains(t, rec.Body.String(), `"displayName":"Acme"`)

		// A tenant record exists, keyed by a did:plc, mapped to the external id.
		stored, err := deps.tenants.GetByExternalID(ctx, "tenant-1")
		require.NoError(t, err)
		require.Equal(t, "plc", stored.ID.Method())
		require.Equal(t, "tenant-1", stored.ExternalID)
		require.Equal(t, tenant.Active, stored.Status)

		// The private key was stored in the vault and the genesis op published.
		key, err := deps.vault.Read(ctx, "/tenant/"+stored.ID.String())
		require.NoError(t, err)
		require.NotEmpty(t, key)
		require.Equal(t, 1, deps.plcPosts)
	})

	t.Run("is idempotent on the external id", func(t *testing.T) {
		e, deps := setupProvision(t)
		require.NoError(t, deps.providers.Add(ctx, testutil.RandomDID(t), "us-east-1"))

		first := provisionRequest(t, e, "tenant-2", api.ProvisionTenantRequest{DisplayName: "Acme", Region: "us-east-1"})
		require.Equal(t, http.StatusCreated, first.Code)
		stored, err := deps.tenants.GetByExternalID(ctx, "tenant-2")
		require.NoError(t, err)

		second := provisionRequest(t, e, "tenant-2", api.ProvisionTenantRequest{DisplayName: "Acme", Region: "us-east-1"})
		require.Equal(t, http.StatusOK, second.Code)

		// No new key minted/published on the idempotent call.
		require.Equal(t, 1, deps.plcPosts)
		again, err := deps.tenants.GetByExternalID(ctx, "tenant-2")
		require.NoError(t, err)
		require.Equal(t, stored.ID, again.ID)
	})

	t.Run("unknown region is rejected", func(t *testing.T) {
		e, _ := setupProvision(t)
		rec := provisionRequest(t, e, "tenant-3", api.ProvisionTenantRequest{DisplayName: "Acme", Region: "nowhere"})
		require.Equal(t, http.StatusBadRequest, rec.Code)
	})

	t.Run("missing displayName is rejected", func(t *testing.T) {
		e, deps := setupProvision(t)
		require.NoError(t, deps.providers.Add(ctx, testutil.RandomDID(t), "us-east-1"))
		rec := provisionRequest(t, e, "tenant-4", api.ProvisionTenantRequest{Region: "us-east-1"})
		require.Equal(t, http.StatusBadRequest, rec.Code)
	})

	t.Run("missing region is rejected", func(t *testing.T) {
		e, _ := setupProvision(t)
		rec := provisionRequest(t, e, "tenant-5", api.ProvisionTenantRequest{DisplayName: "Acme"})
		require.Equal(t, http.StatusBadRequest, rec.Code)
	})
}
