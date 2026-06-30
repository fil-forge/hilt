package api_test

import (
	"bytes"
	"encoding/json"
	"io"
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
	"github.com/fil-forge/hilt/pkg/store/wrapkey"
	wrapkeymemory "github.com/fil-forge/hilt/pkg/store/wrapkey/memory"
	"github.com/fil-forge/hilt/pkg/vault"
	vaultmemory "github.com/fil-forge/hilt/pkg/vault/memory"
	"github.com/fil-forge/ucantone/did/plc"
	"github.com/fil-forge/ucantone/multikey/x25519"
	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

// parseSignedOp decodes a DagJSON-encoded signed PLC operation captured from the
// fake directory.
func parseSignedOp(t *testing.T, body []byte) *plc.SignedOperation {
	t.Helper()
	require.NotEmpty(t, body)
	var op plc.SignedOperation
	require.NoError(t, op.UnmarshalDagJSON(bytes.NewReader(body)))
	return &op
}

type provisionDeps struct {
	tenants   tenant.Store
	providers provider.Store
	wrapKeys  wrapkey.Store
	vault     vault.Vault
	plcPosts  int
	// lastOp is the body of the most recent operation POSTed to the fake PLC
	// directory (DagJSON-encoded signed operation).
	lastOp []byte
}

// setupProvision builds an echo server with the provision handler wired to
// memory stores/vault and a PLC directory client pointed at an httptest server
// that accepts (and captures) genesis operations (no real PLC network).
func setupProvision(t *testing.T) (*echo.Echo, *provisionDeps) {
	t.Helper()
	deps := &provisionDeps{
		tenants:   tenantmemory.New(),
		providers: providermemory.New(),
		wrapKeys:  wrapkeymemory.New(),
		vault:     vaultmemory.New(),
	}

	plcServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			deps.plcPosts++
			deps.lastOp, _ = io.ReadAll(r.Body)
		}
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(plcServer.Close)

	endpoint, err := url.Parse(plcServer.URL)
	require.NoError(t, err)
	plcClient, err := plc.NewDirectoryClient(*endpoint)
	require.NoError(t, err)

	route := api.NewProvisionTenantHandler(zap.NewNop(), deps.tenants, deps.providers, deps.wrapKeys, deps.vault, plcClient)
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

		// The tenant rotation key was stored in the vault and the genesis op
		// published.
		key, err := deps.vault.Read(ctx, "/tenant/"+stored.ID.String())
		require.NoError(t, err)
		require.NotEmpty(t, key)
		require.Equal(t, 1, deps.plcPosts)

		// An active wrap key (version 1) was registered for the tenant.
		wrapRec, err := deps.wrapKeys.GetActive(ctx, stored.ID)
		require.NoError(t, err)
		require.Equal(t, 1, wrapRec.Version)
		require.Equal(t, wrapkey.Active, wrapRec.Status)
		require.Equal(t, stored.ID.String()+"#wrap-1", wrapRec.KID)
		require.NotEmpty(t, wrapRec.PublicKey)

		// The wrap private half was sealed in the vault at its own path,
		// distinct from the tenant rotation key, and is recoverable as X25519.
		wrapVaultKey := wrapkey.VaultKey(stored.ID, 1)
		require.Equal(t, wrapVaultKey, wrapRec.VaultKey)
		sealed, err := deps.vault.Read(ctx, wrapVaultKey)
		require.NoError(t, err)
		require.NotEmpty(t, sealed)
		require.NotEqual(t, key, sealed, "wrap key must be distinct from the tenant rotation key")
		kp, err := x25519.Decode(sealed)
		require.NoError(t, err)
		require.Equal(t, "did:key:"+wrapRec.PublicKey, kp.KeyDID().String())

		// The published genesis operation carries the wrap public key as a
		// verification method at the versioned fragment, alongside the "hilt"
		// signing key.
		op := parseSignedOp(t, deps.lastOp)
		require.Contains(t, op.VerificationMethods, "hilt")
		wrapVM, ok := op.VerificationMethods["wrap-1"]
		require.True(t, ok, "genesis op missing wrap-1 verification method")
		require.Equal(t, "did:key:"+wrapRec.PublicKey, wrapVM.String())
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
