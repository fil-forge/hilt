package api_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"

	"github.com/fil-forge/hilt/internal/testutil"
	"github.com/fil-forge/hilt/pkg/api"
	"github.com/fil-forge/hilt/pkg/client"
	"github.com/fil-forge/hilt/pkg/store"
	accesskeymemory "github.com/fil-forge/hilt/pkg/store/accesskey/memory"
	bucketmemory "github.com/fil-forge/hilt/pkg/store/bucket/memory"
	delegationmemory "github.com/fil-forge/hilt/pkg/store/delegation/memory"
	"github.com/fil-forge/hilt/pkg/store/provider"
	providermemory "github.com/fil-forge/hilt/pkg/store/provider/memory"
	"github.com/fil-forge/hilt/pkg/store/tenant"
	tenantmemory "github.com/fil-forge/hilt/pkg/store/tenant/memory"
	"github.com/fil-forge/hilt/pkg/store/wrapkey"
	wrapkeymemory "github.com/fil-forge/hilt/pkg/store/wrapkey/memory"
	"github.com/fil-forge/hilt/pkg/vault"
	vaultmemory "github.com/fil-forge/hilt/pkg/vault/memory"
	customercmds "github.com/fil-forge/libforge/commands/customer"
	ucanlib "github.com/fil-forge/libforge/ucan"
	"github.com/fil-forge/ucantone/binding"
	"github.com/fil-forge/ucantone/did"
	"github.com/fil-forge/ucantone/did/plc"
	"github.com/fil-forge/ucantone/multikey/secp256k1"
	"github.com/fil-forge/ucantone/multikey/x25519"
	"github.com/fil-forge/ucantone/server"
	"github.com/fil-forge/ucantone/ucan"
	"github.com/fil-forge/ucantone/ucan/command"
	"github.com/fil-forge/ucantone/ucan/container"
	"github.com/fil-forge/ucantone/ucan/delegation"
	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

// spyVault wraps a vault and tracks which keys are currently live (written and
// not yet deleted) plus how many writes occurred, so tests can assert that a key
// was written and subsequently cleaned up.
type spyVault struct {
	vault.Vault
	mu     sync.Mutex
	live   map[string]bool
	writes int
}

func newSpyVault() *spyVault {
	return &spyVault{Vault: vaultmemory.New(), live: map[string]bool{}}
}

func (s *spyVault) Write(ctx context.Context, key string, value []byte) error {
	s.mu.Lock()
	s.live[key] = true
	s.writes++
	s.mu.Unlock()
	return s.Vault.Write(ctx, key, value)
}

func (s *spyVault) Delete(ctx context.Context, key string) error {
	fmt.Println("GOT A DELETE")
	s.mu.Lock()
	delete(s.live, key)
	s.mu.Unlock()
	return s.Vault.Delete(ctx, key)
}

func (s *spyVault) liveKeys() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.live)
}

// addFailTenantStore is a tenant.Store whose Add always fails. It embeds a real
// memory store so the handler's idempotency lookup (GetByExternalID) behaves.
type addFailTenantStore struct {
	tenant.Store
	err error
}

func (s addFailTenantStore) Add(context.Context, did.DID, string, did.DID, tenant.Status) error {
	return s.err
}

type setupConfig struct {
	plcStatus int
	tenants   tenant.Store
}

type provisionDeps struct {
	tenants   tenant.Store
	providers provider.Store
	wrapKeys  wrapkey.Store
	secrets   *spyVault
	plcPosts  int
	lastOp    []byte // body of the most recent op POSTed to the fake PLC directory

	// Sprue (upload service) stub state.
	product      did.DID
	customerAdds int
	lastAddArgs  *customercmds.AddArguments
	sprueFailure bool // when true the stub /customer/add handler returns a failure
}

// setupProvision builds an echo server with the provision handler wired to
// memory stores/vault, a PLC directory client pointed at an httptest server that
// accepts genesis operations, and an upload client pointed at an in-process
// Sprue stub that handles /customer/add (no real PLC or Sprue network).
func setupProvision(t *testing.T, cfg *setupConfig) (*echo.Echo, *provisionDeps) {
	t.Helper()
	var tenants tenant.Store
	if cfg != nil && cfg.tenants != nil {
		tenants = cfg.tenants
	} else {
		tenants = tenantmemory.New()
	}
	deps := &provisionDeps{
		tenants:   tenants,
		providers: providermemory.New(),
		wrapKeys:  wrapkeymemory.New(),
		secrets:   newSpyVault(),
		product:   testutil.RandomDID(t),
	}

	plcServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			deps.plcPosts++
			deps.lastOp, _ = io.ReadAll(r.Body)
		}
		status := http.StatusOK
		if cfg != nil && cfg.plcStatus != 0 {
			status = cfg.plcStatus
		}
		w.WriteHeader(status)
	}))
	t.Cleanup(plcServer.Close)

	endpoint, err := url.Parse(plcServer.URL)
	require.NoError(t, err)
	plcClient, err := plc.NewDirectoryClient(*endpoint)
	require.NoError(t, err)

	// Sprue stub: Hilt (the client's issuer) holds a /customer/add delegation
	// from Sprue, and the in-process server records each invocation.
	sprue := testutil.RandomIssuer(t)
	hilt := testutil.RandomIssuer(t)
	dlg, err := customercmds.Add.Delegate(sprue, hilt.DID(), sprue.DID())
	require.NoError(t, err)
	proofs := ucanlib.NewContainerProofStore(container.New(container.WithDelegations(dlg)))

	srv := server.NewHTTP(sprue)
	srv.Handle(customercmds.Add.Command, customercmds.Add.Handler(
		func(req *binding.Request[*customercmds.AddArguments], res *binding.Response[*customercmds.AddOK]) error {
			deps.customerAdds++
			deps.lastAddArgs = req.Task().Arguments()
			if deps.sprueFailure {
				return res.SetFailure(errors.New("sprue rejected"))
			}
			return res.SetSuccess(&customercmds.AddOK{})
		}))

	sprueURL, err := url.Parse("http://sprue.test")
	require.NoError(t, err)
	upload, err := client.NewUploadClient(sprue.DID(), *sprueURL, hilt, proofs,
		client.WithProduct(deps.product),
		client.WithHTTPClient(&http.Client{Transport: srv}))
	require.NoError(t, err)

	route := api.NewProvisionTenantHandler(zap.NewNop(), deps.tenants, deps.providers, deps.wrapKeys, deps.secrets, plcClient, upload)
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

// parseSignedOp decodes a DagJSON-encoded signed PLC operation captured from the
// fake directory.
func parseSignedOp(t *testing.T, body []byte) *plc.SignedOperation {
	t.Helper()
	require.NotEmpty(t, body)
	var op plc.SignedOperation
	require.NoError(t, op.UnmarshalDagJSON(bytes.NewReader(body)))
	return &op
}

func TestProvisionTenantHandler(t *testing.T) {
	ctx := t.Context()

	t.Run("provisions a new tenant", func(t *testing.T) {
		e, deps := setupProvision(t, nil)
		require.NoError(t, deps.providers.Add(ctx, testutil.RandomDID(t), "us-east-1"))

		rec := provisionRequest(t, e, "tenant-1", api.ProvisionTenantRequest{Region: "us-east-1"})
		require.Equal(t, http.StatusCreated, rec.Code)
		require.Contains(t, rec.Body.String(), `"tenantId":"tenant-1"`)

		// A tenant record exists, keyed by a did:plc, mapped to the external id.
		stored, err := deps.tenants.GetByExternalID(ctx, "tenant-1")
		require.NoError(t, err)
		require.Equal(t, "plc", stored.ID.Method())
		require.Equal(t, "tenant-1", stored.ExternalID)
		require.Equal(t, tenant.Active, stored.Status)

		// The private key was stored in the vault and the genesis op published.
		key, err := deps.secrets.Read(ctx, "/tenant/"+stored.ID.String())
		require.NoError(t, err)
		require.NotEmpty(t, key)
		require.Equal(t, 1, deps.plcPosts)

		// The tenant was registered as a customer with Sprue, keyed by its
		// did:plc, under the configured product, with the tenant details.
		require.Equal(t, 1, deps.customerAdds)
		require.NotNil(t, deps.lastAddArgs)
		require.Equal(t, stored.ID, deps.lastAddArgs.Customer)
		require.Equal(t, deps.product, deps.lastAddArgs.Product)
		require.Equal(t, map[string]string{"external_id": "tenant-1", "region": "us-east-1"}, deps.lastAddArgs.Details)

		// An active wrap key (version 1) was registered, keyed by its fingerprint
		// (the multicodec-tagged public key), not a DID URL.
		wrapRec, err := deps.wrapKeys.GetActive(ctx, stored.ID)
		require.NoError(t, err)
		require.Equal(t, 1, wrapRec.Version)
		require.Equal(t, wrapkey.Active, wrapRec.Status)
		require.NotEmpty(t, wrapRec.KID)

		// The wrap private half was sealed at its own path, decodes to X25519, and
		// its public key is exactly the kid.
		require.Equal(t, wrapkey.VaultKey(stored.ID, 1), wrapRec.VaultKey)
		sealed, err := deps.secrets.Read(ctx, wrapkey.VaultKey(stored.ID, 1))
		require.NoError(t, err)
		kp, err := x25519.Decode(sealed)
		require.NoError(t, err)
		require.Equal(t, kp.Public().String(), wrapRec.KID)

		// The kid resolves back to its record (the recovery lookup).
		byKID, err := deps.wrapKeys.GetByKID(ctx, wrapRec.KID)
		require.NoError(t, err)
		require.Equal(t, stored.ID, byKID.Tenant)

		// The published genesis operation carries the wrap public key at the fixed
		// fragment "wrap" (discovery only), alongside "hilt".
		op := parseSignedOp(t, deps.lastOp)
		require.Contains(t, op.VerificationMethods, "hilt")
		wrapVM, ok := op.VerificationMethods["wrap"]
		require.True(t, ok, "genesis op missing wrap verification method")
		require.Equal(t, "did:key:"+wrapRec.KID, wrapVM.String())
	})

	t.Run("is idempotent on the external id", func(t *testing.T) {
		e, deps := setupProvision(t, nil)
		require.NoError(t, deps.providers.Add(ctx, testutil.RandomDID(t), "us-east-1"))

		first := provisionRequest(t, e, "tenant-2", api.ProvisionTenantRequest{Region: "us-east-1"})
		require.Equal(t, http.StatusCreated, first.Code)
		stored, err := deps.tenants.GetByExternalID(ctx, "tenant-2")
		require.NoError(t, err)

		second := provisionRequest(t, e, "tenant-2", api.ProvisionTenantRequest{Region: "us-east-1"})
		require.Equal(t, http.StatusOK, second.Code)

		// No new key minted/published, and no re-registration, on the idempotent call.
		require.Equal(t, 1, deps.plcPosts)
		require.Equal(t, 1, deps.customerAdds)
		again, err := deps.tenants.GetByExternalID(ctx, "tenant-2")
		require.NoError(t, err)
		require.Equal(t, stored.ID, again.ID)
	})

	t.Run("upload service failure aborts provisioning", func(t *testing.T) {
		e, deps := setupProvision(t, nil)
		require.NoError(t, deps.providers.Add(ctx, testutil.RandomDID(t), "us-east-1"))
		deps.sprueFailure = true

		rec := provisionRequest(t, e, "tenant-6", api.ProvisionTenantRequest{Region: "us-east-1"})
		require.Equal(t, http.StatusBadGateway, rec.Code)

		// Registration was attempted but no tenant record was written, so the
		// operation is retryable.
		require.Equal(t, 1, deps.customerAdds)
		_, err := deps.tenants.GetByExternalID(ctx, "tenant-6")
		require.ErrorIs(t, err, store.ErrRecordNotFound)
	})

	t.Run("unknown region is rejected", func(t *testing.T) {
		e, _ := setupProvision(t, nil)
		rec := provisionRequest(t, e, "tenant-3", api.ProvisionTenantRequest{Region: "nowhere"})
		require.Equal(t, http.StatusBadRequest, rec.Code)
	})

	t.Run("missing region is rejected", func(t *testing.T) {
		e, _ := setupProvision(t, nil)
		rec := provisionRequest(t, e, "tenant-5", api.ProvisionTenantRequest{})
		require.Equal(t, http.StatusBadRequest, rec.Code)
	})

	t.Run("cleans up the orphaned key when PLC publication fails", func(t *testing.T) {
		e, deps := setupProvision(t, &setupConfig{plcStatus: http.StatusInternalServerError})
		require.NoError(t, deps.providers.Add(ctx, testutil.RandomDID(t), "us-east-1"))

		rec := provisionRequest(t, e, "tenant-6", api.ProvisionTenantRequest{Region: "us-east-1"})
		require.Equal(t, http.StatusBadGateway, rec.Code)

		// A key was written then cleaned up, and no tenant was recorded.
		require.Positive(t, deps.secrets.writes)
		require.Zero(t, deps.secrets.liveKeys())
		_, err := deps.tenants.GetByExternalID(ctx, "tenant-6")
		require.ErrorIs(t, err, store.ErrRecordNotFound)
	})

	t.Run("cleans up the orphaned key when storing the tenant fails", func(t *testing.T) {
		tenants := addFailTenantStore{Store: tenantmemory.New(), err: errors.New("boom")}

		e, deps := setupProvision(t, &setupConfig{tenants: tenants})
		require.NoError(t, deps.providers.Add(ctx, testutil.RandomDID(t), "us-east-1"))
		rec := provisionRequest(t, e, "tenant-7", api.ProvisionTenantRequest{Region: "us-east-1"})
		require.Equal(t, http.StatusInternalServerError, rec.Code)

		// The key written before the failed Add was cleaned up.
		require.Positive(t, deps.secrets.writes)
		require.Zero(t, deps.secrets.liveKeys())
	})
}

// serve wraps a single Route in an echo server.
func serve(route api.Route) *echo.Echo {
	e := echo.New()
	e.Add(route.Method, route.Path, route.Handler)
	return e
}

// doRequest issues an HTTP request against e. A non-empty body is sent as JSON.
func doRequest(t *testing.T, e *echo.Echo, method, target string, body []byte) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, target, bytes.NewReader(body))
	if len(body) > 0 {
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	}
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)
	return rec
}

func TestGetTenantHandler(t *testing.T) {
	ctx := t.Context()
	tenants := tenantmemory.New()
	require.NoError(t, tenants.Add(ctx, testutil.RandomDID(t), "tenant-1", testutil.RandomDID(t), tenant.Active))
	e := serve(api.NewGetTenantHandler(zap.NewNop(), tenants))

	t.Run("found", func(t *testing.T) {
		rec := doRequest(t, e, http.MethodGet, "/tenants/tenant-1", nil)
		require.Equal(t, http.StatusOK, rec.Code)
		require.Contains(t, rec.Body.String(), `"tenantId":"tenant-1"`)
		require.Contains(t, rec.Body.String(), `"status":"active"`)
	})

	t.Run("not found", func(t *testing.T) {
		rec := doRequest(t, e, http.MethodGet, "/tenants/missing", nil)
		require.Equal(t, http.StatusNotFound, rec.Code)
	})
}

func TestUpdateTenantStatusHandler(t *testing.T) {
	ctx := t.Context()
	tenants := tenantmemory.New()
	id := testutil.RandomDID(t)
	require.NoError(t, tenants.Add(ctx, id, "tenant-1", testutil.RandomDID(t), tenant.Active))
	e := serve(api.NewUpdateTenantStatusHandler(zap.NewNop(), tenants))

	statusBody := func(s api.TenantStatus) []byte {
		b, err := json.Marshal(api.UpdateTenantStatusRequest{Status: s})
		require.NoError(t, err)
		return b
	}

	t.Run("updates status", func(t *testing.T) {
		rec := doRequest(t, e, http.MethodPost, "/tenants/tenant-1/status", statusBody(api.TenantStatusWriteLocked))
		require.Equal(t, http.StatusNoContent, rec.Code)

		got, err := tenants.Get(ctx, id)
		require.NoError(t, err)
		require.Equal(t, tenant.WriteLocked, got.Status)
	})

	t.Run("unknown tenant", func(t *testing.T) {
		rec := doRequest(t, e, http.MethodPost, "/tenants/missing/status", statusBody(api.TenantStatusDisabled))
		require.Equal(t, http.StatusNotFound, rec.Code)
	})

	t.Run("invalid status value", func(t *testing.T) {
		rec := doRequest(t, e, http.MethodPost, "/tenants/tenant-1/status", []byte(`{"status":"bogus"}`))
		require.Equal(t, http.StatusUnprocessableEntity, rec.Code)
	})

	t.Run("missing status", func(t *testing.T) {
		rec := doRequest(t, e, http.MethodPost, "/tenants/tenant-1/status", []byte(`{}`))
		require.Equal(t, http.StatusUnprocessableEntity, rec.Code)
	})
}

// plcDirectory is an httptest-backed did:plc directory for the delete tests. It
// serves the tenant's last operation (a genesis op by default, or a tombstone to
// simulate an already-deactivated DID) at GET .../log/last, and accepts the
// tombstone publish at POST .../{did}. The handler talks to it through a real
// *plc.DirectoryClient, exercising the DagJSON decode path over an httptest body.
type plcDirectory struct {
	server        *httptest.Server
	logLast       []byte // DagJSON served at GET .../log/last
	logLastStatus int    // overrides the 200 status when non-zero (to simulate failures)
	deactivations int    // count of tombstone POSTs
}

func (d *plcDirectory) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet: // .../log/last
		if d.logLastStatus != 0 {
			w.WriteHeader(d.logLastStatus)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(d.logLast)
	case http.MethodPost: // tombstone publish
		d.deactivations++
		w.WriteHeader(http.StatusOK)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

type deleteDeps struct {
	tenants     *tenantmemory.Store
	buckets     *bucketmemory.Store
	accessKeys  *accesskeymemory.Store
	delegations *delegationmemory.Store
	wrapKeys    *wrapkeymemory.Store
	vault       vault.Vault
	directory   *plcDirectory
	signer      secp256k1.Signer
	genesis     *plc.SignedOperation
	tenantID    did.DID
}

// serveTombstone makes the directory report the tenant DID as already
// deactivated by serving a signed tombstone as its last operation.
func (d *deleteDeps) serveTombstone(t *testing.T) {
	t.Helper()
	tomb, err := plc.NewTombstoneFromPrevious(d.genesis)
	require.NoError(t, err)
	signed, err := plc.SignTombstone(d.signer, tomb)
	require.NoError(t, err)
	var buf bytes.Buffer
	require.NoError(t, signed.MarshalDagJSON(&buf))
	d.directory.logLast = buf.Bytes()
}

// setupDelete builds a delete handler over memory stores and an httptest did:plc
// directory. The tenant is created with a real did:plc whose genesis op the
// directory serves, so the handler can fetch it and sign a tombstone.
func setupDelete(t *testing.T, status tenant.Status) (*echo.Echo, *deleteDeps) {
	t.Helper()
	ctx := t.Context()

	signer, err := secp256k1.Generate()
	require.NoError(t, err)
	key := signer.KeyDID()
	tenantID, genesis, err := plc.New(signer,
		plc.WithRotationKeys(key),
		plc.WithVerificationMethods(map[string]did.DID{"hilt": key}),
	)
	require.NoError(t, err)

	var genesisJSON bytes.Buffer
	require.NoError(t, genesis.MarshalDagJSON(&genesisJSON))

	directory := &plcDirectory{logLast: genesisJSON.Bytes()}
	directory.server = httptest.NewServer(directory)
	t.Cleanup(directory.server.Close)

	endpoint, err := url.Parse(directory.server.URL)
	require.NoError(t, err)
	plcClient, err := plc.NewDirectoryClient(*endpoint)
	require.NoError(t, err)

	deps := &deleteDeps{
		tenants:     tenantmemory.New(),
		buckets:     bucketmemory.New(),
		accessKeys:  accesskeymemory.New(),
		delegations: delegationmemory.New(),
		wrapKeys:    wrapkeymemory.New(),
		vault:       vaultmemory.New(),
		directory:   directory,
		signer:      signer,
		genesis:     genesis,
		tenantID:    tenantID,
	}
	require.NoError(t, deps.tenants.Add(ctx, tenantID, "tenant-1", testutil.RandomDID(t), status))
	require.NoError(t, deps.vault.Write(ctx, "/tenant/"+tenantID.String(), signer.Bytes()))
	// Every provisioned tenant has an active wrap key; seed one so deletion has
	// wrap-key state to cascade.
	require.NoError(t, deps.vault.Write(ctx, wrapkey.VaultKey(tenantID, 1), []byte("wrap-key")))
	require.NoError(t, deps.wrapKeys.Add(ctx, wrapkey.Record{
		Tenant:   tenantID,
		Version:  1,
		KID:      "z6LSseedWrapKid",
		Status:   wrapkey.Active,
		VaultKey: wrapkey.VaultKey(tenantID, 1),
	}))

	route := api.NewDeleteTenantHandler(zap.NewNop(), deps.tenants, deps.buckets, deps.accessKeys, deps.delegations, deps.wrapKeys, deps.vault, plcClient)
	return serve(route), deps
}

func makeDelegation(t *testing.T, audience did.DID) ucan.Delegation {
	t.Helper()
	issuer := testutil.RandomIssuer(t)
	d, err := delegation.Delegate(issuer, audience, issuer.DID(), command.MustParse("/test/run"))
	require.NoError(t, err)
	return d
}

func TestDeleteTenantHandler(t *testing.T) {
	ctx := t.Context()

	t.Run("deletes a disabled tenant and cascades", func(t *testing.T) {
		e, deps := setupDelete(t, tenant.Disabled)

		// Seed owned resources: a bucket, an access key (+ vault key), and
		// delegations addressed to the tenant and to the access key.
		bucketID := testutil.RandomDID(t)
		require.NoError(t, deps.buckets.Add(ctx, bucketID, deps.tenantID, "b1"))
		akID := testutil.RandomDID(t)
		require.NoError(t, deps.accessKeys.Add(ctx, akID, deps.tenantID, "k1", nil, []string{"s3:GetObject"}, nil))
		akVaultKey := "/tenant/" + deps.tenantID.String() + "/access-key/" + akID.String()
		require.NoError(t, deps.vault.Write(ctx, akVaultKey, []byte("ak-key")))
		require.NoError(t, deps.delegations.PutBatch(ctx, []ucan.Delegation{makeDelegation(t, deps.tenantID)}))
		require.NoError(t, deps.delegations.PutBatch(ctx, []ucan.Delegation{makeDelegation(t, akID)}))

		rec := doRequest(t, e, http.MethodDelete, "/tenants/tenant-1", nil)
		require.Equal(t, http.StatusNoContent, rec.Code)

		// Tenant + its key gone.
		_, err := deps.tenants.GetByExternalID(ctx, "tenant-1")
		require.ErrorIs(t, err, store.ErrRecordNotFound)
		_, err = deps.vault.Read(ctx, "/tenant/"+deps.tenantID.String())
		require.ErrorIs(t, err, vault.ErrNotFound)

		// Wrap keys (registry rows + sealed private half) gone.
		_, err = deps.wrapKeys.GetActive(ctx, deps.tenantID)
		require.ErrorIs(t, err, store.ErrRecordNotFound)
		wks, err := deps.wrapKeys.List(ctx, deps.tenantID)
		require.NoError(t, err)
		require.Empty(t, wks)
		_, err = deps.vault.Read(ctx, wrapkey.VaultKey(deps.tenantID, 1))
		require.ErrorIs(t, err, vault.ErrNotFound)

		// Buckets + access keys (records and vault key) gone.
		bs, err := deps.buckets.ListByTenant(ctx, deps.tenantID)
		require.NoError(t, err)
		require.Empty(t, bs.Results)
		aks, err := deps.accessKeys.ListByTenant(ctx, deps.tenantID)
		require.NoError(t, err)
		require.Empty(t, aks)
		_, err = deps.vault.Read(ctx, akVaultKey)
		require.ErrorIs(t, err, vault.ErrNotFound)

		// Delegations to both the tenant and the access key gone.
		tenantDlgs, err := deps.delegations.ListByAudience(ctx, deps.tenantID)
		require.NoError(t, err)
		require.Empty(t, tenantDlgs.Results)
		akDlgs, err := deps.delegations.ListByAudience(ctx, akID)
		require.NoError(t, err)
		require.Empty(t, akDlgs.Results)

		// The DID was deactivated in the directory.
		require.Equal(t, 1, deps.directory.deactivations)
	})

	t.Run("already-deactivated DID still cleans up locally", func(t *testing.T) {
		e, deps := setupDelete(t, tenant.Disabled)
		deps.serveTombstone(t) // directory reports the DID as already tombstoned

		rec := doRequest(t, e, http.MethodDelete, "/tenants/tenant-1", nil)
		require.Equal(t, http.StatusNoContent, rec.Code)

		_, err := deps.tenants.GetByExternalID(ctx, "tenant-1")
		require.ErrorIs(t, err, store.ErrRecordNotFound)
		require.Equal(t, 0, deps.directory.deactivations) // no second tombstone published
	})

	t.Run("rejects a non-disabled tenant", func(t *testing.T) {
		e, deps := setupDelete(t, tenant.Active)
		rec := doRequest(t, e, http.MethodDelete, "/tenants/tenant-1", nil)
		require.Equal(t, http.StatusConflict, rec.Code)

		_, err := deps.tenants.GetByExternalID(ctx, "tenant-1")
		require.NoError(t, err)
		require.Equal(t, 0, deps.directory.deactivations)
	})

	t.Run("unknown tenant is idempotent", func(t *testing.T) {
		e, deps := setupDelete(t, tenant.Disabled)
		rec := doRequest(t, e, http.MethodDelete, "/tenants/missing", nil)
		require.Equal(t, http.StatusNoContent, rec.Code)
		require.Equal(t, 0, deps.directory.deactivations)
	})

	t.Run("aborts when the directory is unreachable", func(t *testing.T) {
		e, deps := setupDelete(t, tenant.Disabled)
		deps.directory.logLastStatus = http.StatusInternalServerError

		rec := doRequest(t, e, http.MethodDelete, "/tenants/tenant-1", nil)
		require.Equal(t, http.StatusBadGateway, rec.Code)

		// Nothing was deleted; the operation is retryable.
		_, err := deps.tenants.GetByExternalID(ctx, "tenant-1")
		require.NoError(t, err)
	})
}
