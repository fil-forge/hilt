package fx_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/fil-forge/hilt/internal/testutil"
	"github.com/fil-forge/hilt/pkg/config"
	appfx "github.com/fil-forge/hilt/pkg/fx"
	"github.com/fil-forge/libforge/identity"
	"github.com/fil-forge/ucantone/execution"
	"github.com/fil-forge/ucantone/ipld/codec/dagcbor"
	"github.com/fil-forge/ucantone/ipld/datamodel"
	"github.com/fil-forge/ucantone/server"
	ucantest "github.com/fil-forge/ucantone/testutil"
	"github.com/fil-forge/ucantone/ucan"
	"github.com/fil-forge/ucantone/ucan/container"
	"github.com/fil-forge/ucantone/ucan/delegation"
	"github.com/fil-forge/ucantone/ucan/invocation"
	"github.com/ipfs/go-cid"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

// These requests carry no partner key, cookie or bearer token. They run through
// the actual unauthenticated POST / mount and UCAN signature validator, while a
// real listener observes any outbound DID-document request.
func TestUCANServerExternalWebResolutionDeniedByDefault(t *testing.T) {
	var hits atomic.Int32
	canary := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusTeapot)
	}))
	t.Cleanup(canary.Close)
	closed := httptest.NewServer(http.NotFoundHandler())
	closedURL := closed.URL
	closed.Close()
	id, err := identity.New("", "did:web:hilt.test")
	require.NoError(t, err)
	srv := resolutionTestServer(t, id, config.ServerConfig{InsecureDIDResolution: true})
	var failures []error
	for _, target := range []string{canary.URL, closedURL} {
		issuer, err := identity.New("", webDID(target))
		require.NoError(t, err)
		failure := postInvocation(t, srv, id, issuer)
		require.Error(t, failure)
		require.EqualError(t, failure, "did:web resolution not permitted")
		failures = append(failures, failure)
		require.NotContains(t, failure.Error(), "unexpected status")
		require.NotContains(t, failure.Error(), "connection refused")
	}
	require.Equal(t, failures[0], failures[1], "reachable and unreachable targets must return the same receipt error class and detail")
	require.Zero(t, hits.Load(), "a rejected issuer must not reach a listener")
}

func TestUCANServerConfiguredWebIdentityResolvesBeforeInvalidSignature(t *testing.T) {
	var hits atomic.Int32
	var doc []byte
	canary := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		require.Equal(t, "/.well-known/did.json", r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(doc)
	}))
	t.Cleanup(canary.Close)
	legitimate, err := identity.New("", webDID(canary.URL))
	require.NoError(t, err)
	document, err := legitimate.DIDDocument()
	require.NoError(t, err)
	doc, err = json.Marshal(document)
	require.NoError(t, err)
	// A different key claims that same issuer: the DID may resolve, but its
	// document must still be used to reject the mismatching signature.
	forged, err := identity.New("", legitimate.DID().String())
	require.NoError(t, err)
	id, err := identity.New("", "did:web:hilt.test")
	require.NoError(t, err)
	srv := resolutionTestServer(t, id, config.ServerConfig{
		InsecureDIDResolution: true, AllowedWebDIDs: []string{legitimate.DID().String()},
	})
	failure := postInvocation(t, srv, id, forged)
	require.Error(t, failure)
	require.Contains(t, failure.Error(), "signature mismatch")
	require.EqualValues(t, 1, hits.Load(), "positive control must actually fetch the allowed document")

	for _, suffix := range []string{":other", ".attacker.invalid"} {
		other, err := identity.New("", legitimate.DID().String()+suffix)
		require.NoError(t, err)
		require.Contains(t, postInvocation(t, srv, id, other).Error(), "did:web resolution not permitted")
	}
	require.EqualValues(t, 1, hits.Load(), "allowlisting one DID must not authorize another path or suffix")
}

func TestUCANServerWebResolutionCannotFollowRedirectOutsideAllowlist(t *testing.T) {
	var destinationHits atomic.Int32
	destination := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		destinationHits.Add(1)
		w.WriteHeader(http.StatusTeapot)
	}))
	t.Cleanup(destination.Close)
	var sourceHits atomic.Int32
	source := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sourceHits.Add(1)
		http.Redirect(w, r, destination.URL+"/internal", http.StatusFound)
	}))
	t.Cleanup(source.Close)
	id, err := identity.New("", "did:web:hilt.test")
	require.NoError(t, err)
	issuer, err := identity.New("", webDID(source.URL))
	require.NoError(t, err)
	srv := resolutionTestServer(t, id, config.ServerConfig{
		InsecureDIDResolution: true, AllowedWebDIDs: []string{issuer.DID().String()},
	})
	failure := postInvocation(t, srv, id, issuer)
	require.Error(t, failure)
	require.Contains(t, failure.Error(), "did:web resolution not permitted")
	require.EqualValues(t, 1, sourceHits.Load())
	require.Zero(t, destinationHits.Load(), "redirect target must not receive a request")
}

func TestUCANServerSelfWebIdentityStaysLocal(t *testing.T) {
	id, err := identity.New("", "did:web:hilt.invalid")
	require.NoError(t, err)
	srv := resolutionTestServer(t, id, config.ServerConfig{})
	require.NoError(t, postInvocation(t, srv, id, id))
}

func resolutionTestServer(t *testing.T, id identity.Identity, cfg config.ServerConfig) http.Handler {
	t.Helper()
	rpc, err := appfx.NewUCANServer(appfx.UCANServerParams{
		Identity: id, Server: cfg, Logger: zap.NewNop(),
		AdminRoutes: []server.Route{{Command: ucantest.TestEchoCommand, Handler: func(requests []execution.Batch) error {
			for _, req := range requests {
				if err := req.Response.SetSuccess(datamodel.Map{}); err != nil {
					return err
				}
			}
			return nil
		}}},
	})
	require.NoError(t, err)
	return appfx.NewEchoServer(appfx.ServerParams{Identity: id, Logger: zap.NewNop(), Auth: config.AuthConfig{PartnerKey: "unused-test-key"}, UCANServer: rpc})
}

func postInvocation(t *testing.T, srv http.Handler, service identity.Identity, issuer ucan.Issuer, proofs ...ucan.Delegation) error {
	t.Helper()
	links := make([]cid.Cid, len(proofs))
	for i, proof := range proofs {
		links[i] = proof.Link()
	}
	inv, err := invocation.Invoke(issuer, service.DID(), ucantest.TestEchoCommand, nil, invocation.WithAudience(service.DID()), invocation.WithProofs(links...))
	require.NoError(t, err)
	ct := container.New(container.WithInvocations(inv), container.WithDelegations(proofs...))
	var body bytes.Buffer
	require.NoError(t, ct.MarshalCBOR(&body))
	req := httptest.NewRequest(http.MethodPost, "/", &body)
	req.Header.Set("Content-Type", dagcbor.ContentType)
	resp := httptest.NewRecorder()
	srv.ServeHTTP(resp, req)
	require.Equal(t, http.StatusOK, resp.Code)
	var result container.Container
	require.NoError(t, result.UnmarshalCBOR(resp.Body))
	require.Len(t, result.Receipts(), 1)
	return testutil.ReceiptFailure(t, result.Receipts()[0])
}

func webDID(endpoint string) string {
	return "did:web:" + strings.ReplaceAll(strings.TrimPrefix(strings.TrimPrefix(endpoint, "http://"), "https://"), ":", "%3A")
}

func TestUCANServerRejectsAmbiguousWebAllowlistConfiguration(t *testing.T) {
	id, err := identity.New("", "did:web:hilt.test")
	require.NoError(t, err)
	for _, value := range []string{"", "example.com", "did:key:z6Mkbad", "did:web:*", "did:web:allowed.test.attacker/*", "did:web:allowed.test:..:internal", "did:web:user@allowed.test", "did:web:allowed.test%2Fother", "did:web:allowed.test%3Ainvalid", "did:web:allowed.test:tenant%2Fother", "did:web:allowed.test:%2E%2E:internal"} {
		t.Run(value, func(t *testing.T) {
			_, err := appfx.NewUCANServer(appfx.UCANServerParams{
				Identity: id, Logger: zap.NewNop(), Server: config.ServerConfig{AllowedWebDIDs: []string{value}},
			})
			require.ErrorContains(t, err, "server.allowed_web_dids")
		})
	}
}

func TestUCANServerAllowsConfiguredHTTPSIdentityWithoutInsecureMode(t *testing.T) {
	var hits atomic.Int32
	var doc []byte
	canary := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		require.NotNil(t, r.TLS)
		_, _ = w.Write(doc)
	}))
	t.Cleanup(canary.Close)
	// Trust this fixture's certificate only in this serial test. Production
	// still uses the normal traced system-trust transport and HTTPS default.
	old := http.DefaultTransport
	http.DefaultTransport = canary.Client().Transport
	t.Cleanup(func() { http.DefaultTransport = old })
	legitimate, err := identity.New("", webDID(canary.URL))
	require.NoError(t, err)
	document, err := legitimate.DIDDocument()
	require.NoError(t, err)
	doc, err = json.Marshal(document)
	require.NoError(t, err)
	forged, err := identity.New("", legitimate.DID().String())
	require.NoError(t, err)
	id, err := identity.New("", "did:web:hilt.test")
	require.NoError(t, err)
	failure := postInvocation(t, resolutionTestServer(t, id, config.ServerConfig{AllowedWebDIDs: []string{legitimate.DID().String()}}), id, forged)
	require.ErrorContains(t, failure, "signature mismatch")
	require.EqualValues(t, 1, hits.Load())
}

func TestUCANServerConfiguredWebPathIdentityResolvesExactDocument(t *testing.T) {
	var hits atomic.Int32
	var doc []byte
	canary := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		require.Equal(t, "/tenant/gateway/did.json", r.URL.Path)
		_, _ = w.Write(doc)
	}))
	t.Cleanup(canary.Close)
	legitimate, err := identity.New("", webDID(canary.URL)+":tenant:gateway")
	require.NoError(t, err)
	document, err := legitimate.DIDDocument()
	require.NoError(t, err)
	doc, err = json.Marshal(document)
	require.NoError(t, err)
	forged, err := identity.New("", legitimate.DID().String())
	require.NoError(t, err)
	id, err := identity.New("", "did:web:hilt.test")
	require.NoError(t, err)
	failure := postInvocation(t, resolutionTestServer(t, id, config.ServerConfig{
		InsecureDIDResolution: true, AllowedWebDIDs: []string{legitimate.DID().String()},
	}), id, forged)
	require.ErrorContains(t, failure, "signature mismatch")
	require.EqualValues(t, 1, hits.Load())
}

func TestUCANServerDisallowedWebProofIssuerNeverReachesListener(t *testing.T) {
	var hits atomic.Int32
	canary := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusTeapot)
	}))
	t.Cleanup(canary.Close)
	id, err := identity.New("", "did:web:hilt.test")
	require.NoError(t, err)
	issuer := testutil.RandomIssuer(t)
	proofIssuer, err := identity.New("", webDID(canary.URL))
	require.NoError(t, err)
	proof, err := delegation.Delegate(proofIssuer, issuer.DID(), id.DID(), ucantest.TestEchoCommand)
	require.NoError(t, err)
	cfg := config.ServerConfig{InsecureDIDResolution: true}
	failure := postInvocation(t, resolutionTestServer(t, id, cfg), id, issuer, proof)
	require.EqualError(t, failure, "did:web resolution not permitted")
	require.Zero(t, hits.Load())
	// This control establishes that the linked proof is actually examined,
	// rather than rejected on an unrelated command or subject check first.
	cfg.AllowedWebDIDs = []string{proofIssuer.DID().String()}
	failure = postInvocation(t, resolutionTestServer(t, id, cfg), id, issuer, proof)
	require.ErrorContains(t, failure, "unexpected status: 418")
	require.EqualValues(t, 1, hits.Load())
}
