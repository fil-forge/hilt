package fx_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/fil-forge/hilt/internal/testutil"
	"github.com/fil-forge/hilt/pkg/config"
	appfx "github.com/fil-forge/hilt/pkg/fx"
	storememory "github.com/fil-forge/hilt/pkg/fx/store/memory"
	vaultmemory "github.com/fil-forge/hilt/pkg/fx/vault/memory"
	providerstore "github.com/fil-forge/hilt/pkg/store/provider"
	s3bkt "github.com/fil-forge/libforge/commands/s3/bucket"
	"github.com/fil-forge/libforge/identity"
	"github.com/fil-forge/ucantone/client"
	"github.com/fil-forge/ucantone/execution/batch"
	"github.com/fil-forge/ucantone/server"
	"github.com/fil-forge/ucantone/ucan"
	"github.com/fil-forge/ucantone/ucan/delegation"
	"github.com/fil-forge/ucantone/ucan/invocation"
	"github.com/ipfs/go-cid"
	"github.com/stretchr/testify/require"
	"go.uber.org/fx"
	"go.uber.org/zap"
)

const notPermitted = "DID resolution is permitted for registered providers only"

// listCommand is a command served to providers; any one of them would do.
var listCommand = s3bkt.List.Command

// hilt is the app's HTTP server as deployed: the UCAN RPC server mounted at
// the unauthenticated POST /, over in-memory backends, resolving did:web over
// plain HTTP so a test listener can stand in for a caller's host.
type hilt struct {
	url       *url.URL
	id        identity.Identity
	providers providerstore.Store
}

func newHilt(t *testing.T) hilt {
	t.Helper()
	cfg := &config.Config{
		Server:     config.ServerConfig{InsecureDIDResolution: true},
		Storage:    config.StorageConfig{Type: config.StorageTypeMemory},
		Vault:      config.VaultConfig{Type: config.VaultTypeMemory},
		Upload:     config.UploadConfig{ServiceID: testutil.RandomDID(t).String(), ServiceURL: "http://sprue.test", ProductID: testutil.RandomDID(t).String()},
		Revocation: config.RevocationConfig{ServiceID: testutil.RandomDID(t).String(), ServiceURL: "http://swarf.test"},
	}
	var h hilt
	var srv *server.HTTPServer
	app := fx.New(
		fx.Supply(cfg),
		appfx.ConfigModule,
		appfx.LoggerModule,
		appfx.IdentityModule,
		appfx.RevocationModule,
		appfx.APIModule,
		appfx.RPCModule,
		storememory.Module,
		vaultmemory.Module,
		fx.NopLogger,
		fx.Decorate(func(*zap.Logger) *zap.Logger { return zap.NewNop() }),
		fx.Invoke(func(s *server.HTTPServer, i identity.Identity, p providerstore.Store) {
			srv, h.id, h.providers = s, i, p
		}),
	)
	require.NoError(t, app.Err())

	e := appfx.NewEchoServer(appfx.ServerParams{Logger: zap.NewNop(), Identity: h.id, UCANServer: srv})
	ts := httptest.NewServer(e)
	t.Cleanup(ts.Close)
	u, err := url.Parse(ts.URL)
	require.NoError(t, err)
	h.url = u
	return h
}

// post sends one invocation of the list command to the server's POST / as a
// caller holding no credential would, and returns the failure its receipt
// carries.
func (h hilt) post(t *testing.T, issuer ucan.Issuer, proofs ...ucan.Delegation) error {
	t.Helper()
	links := make([]cid.Cid, 0, len(proofs))
	for _, p := range proofs {
		links = append(links, p.Link())
	}
	inv, err := invocation.Invoke(issuer, h.id.DID(), listCommand, nil,
		invocation.WithAudience(h.id.DID()), invocation.WithProofs(links...))
	require.NoError(t, err)

	c, err := client.NewHTTP(h.url)
	require.NoError(t, err)
	resp, err := c.ExecuteBatch(batch.NewRequest(t.Context(), []ucan.Invocation{inv}, batch.WithDelegations(proofs...)))
	require.NoError(t, err)
	rcpt, ok := resp.Receipt(inv.Task().Link())
	require.True(t, ok, "the server issued no receipt for the invocation")
	return testutil.ReceiptFailure(t, rcpt)
}

// webHost is a host a did:web names: a listener that counts the requests it
// receives and serves the DID document of the identity it hosts.
type webHost struct {
	id   identity.Identity
	hits *atomic.Int32
}

func newWebHost(t *testing.T) webHost {
	t.Helper()
	h := webHost{hits: new(atomic.Int32)}
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h.hits.Add(1)
		doc, err := h.id.DIDDocument()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(doc)
	}))
	t.Cleanup(ts.Close)

	id, err := identity.New("", "did:web:"+url.QueryEscape(strings.TrimPrefix(ts.URL, "http://")))
	require.NoError(t, err)
	h.id = id
	return h
}

// unreachableWebIdentity is a did:web identity whose host refuses connections.
func unreachableWebIdentity(t *testing.T) identity.Identity {
	t.Helper()
	ts := httptest.NewServer(http.NotFoundHandler())
	host := strings.TrimPrefix(ts.URL, "http://")
	ts.Close()
	id, err := identity.New("", "did:web:"+url.QueryEscape(host))
	require.NoError(t, err)
	return id
}

// TestDIDWebResolutionIsForProvidersOnly posts invocations naming a did:web
// issuer to the unauthenticated POST /. The issuer is resolved before any
// signature is checked, so the server must fetch a document only for a
// registered provider.
func TestDIDWebResolutionIsForProvidersOnly(t *testing.T) {
	t.Run("an unregistered issuer's host receives no request", func(t *testing.T) {
		h := newHilt(t)
		// The host serves a document that verifies the caller's signature: the
		// invocation would pass the signature check if the document were fetched.
		host := newWebHost(t)

		err := h.post(t, host.id)
		require.ErrorContains(t, err, notPermitted)
		require.Zero(t, host.hits.Load())
	})

	t.Run("the refusal reads the same for a reachable and an unreachable host", func(t *testing.T) {
		h := newHilt(t)
		reachable := newWebHost(t)
		unreachable := unreachableWebIdentity(t)

		errReachable := h.post(t, reachable.id)
		errUnreachable := h.post(t, unreachable)
		require.ErrorContains(t, errReachable, notPermitted)

		// The receipts differ only in the DID each caller wrote.
		require.Equal(t,
			strings.ReplaceAll(errReachable.Error(), reachable.id.DID().String(), "<issuer>"),
			strings.ReplaceAll(errUnreachable.Error(), unreachable.DID().String(), "<issuer>"),
		)
		require.Zero(t, reachable.hits.Load())
	})

	t.Run("an unregistered proof issuer's host receives no request", func(t *testing.T) {
		h := newHilt(t)
		host := newWebHost(t)
		caller := testutil.RandomIssuer(t)
		prf, err := delegation.Delegate(host.id, caller.DID(), h.id.DID(), listCommand)
		require.NoError(t, err)

		err = h.post(t, caller, prf)
		require.ErrorContains(t, err, notPermitted)
		require.Zero(t, host.hits.Load())
	})

	t.Run("a registered provider is resolved and its signature verified", func(t *testing.T) {
		h := newHilt(t)
		host := newWebHost(t)
		require.NoError(t, h.providers.Add(t.Context(), host.id.DID(), "us-east-1", nil))
		prf, err := delegation.Delegate(h.id, host.id.DID(), h.id.DID(), listCommand)
		require.NoError(t, err)

		// The invocation carries no arguments, so the command rejects it on its
		// own terms: reaching the command is what shows the issuer verified.
		err = h.post(t, host.id, prf)
		require.Error(t, err)
		require.NotContains(t, err.Error(), notPermitted)
		require.NotContains(t, err.Error(), "InvalidSignature")
		require.EqualValues(t, 1, host.hits.Load())
	})

	t.Run("a registered provider signing with another key is rejected", func(t *testing.T) {
		h := newHilt(t)
		host := newWebHost(t)
		require.NoError(t, h.providers.Add(t.Context(), host.id.DID(), "us-east-1", nil))
		impostor, err := identity.New("", host.id.DID().String())
		require.NoError(t, err)

		err = h.post(t, impostor)
		require.ErrorContains(t, err, "signature")
		require.EqualValues(t, 1, host.hits.Load())
	})

	t.Run("a did:key issuer needs no registration", func(t *testing.T) {
		h := newHilt(t)
		caller := testutil.RandomIssuer(t)
		prf, err := delegation.Delegate(h.id, caller.DID(), h.id.DID(), listCommand)
		require.NoError(t, err)

		err = h.post(t, caller, prf)
		require.Error(t, err)
		require.NotContains(t, err.Error(), notPermitted)
	})
}
