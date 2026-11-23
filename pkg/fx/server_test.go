package fx_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/fil-forge/hilt/pkg/build"
	"github.com/fil-forge/hilt/pkg/config"
	appfx "github.com/fil-forge/hilt/pkg/fx"
	providermemory "github.com/fil-forge/hilt/pkg/store/provider/memory"
	s3bkt "github.com/fil-forge/libforge/commands/s3/bucket"
	"github.com/fil-forge/ucantone/execution"
	"github.com/fil-forge/ucantone/ipld/codec/dagcbor"
	"github.com/fil-forge/ucantone/server"
	"github.com/fil-forge/ucantone/ucan/container"
	"github.com/fil-forge/ucantone/ucan/invocation"
	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"
)

func TestServerInfoRoute(t *testing.T) {
	id, err := appfx.NewIdentity(config.IdentityConfig{}, zap.NewNop())
	require.NoError(t, err)

	srv, err := appfx.NewUCANServer(appfx.UCANServerParams{Identity: id, Providers: providermemory.New(), Logger: zap.NewNop()})
	require.NoError(t, err)

	e := appfx.NewEchoServer(appfx.ServerParams{
		Logger:     zap.NewNop(),
		Identity:   id,
		UCANServer: srv,
	})

	t.Run("returns JSON when requested via Accept, case-insensitively", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set("Accept", "Application/JSON")
		rec := httptest.NewRecorder()
		e.ServeHTTP(rec, req)

		require.Equal(t, http.StatusOK, rec.Code)
		require.Contains(t, rec.Header().Get("Content-Type"), "application/json")
		var info struct {
			ID    string `json:"id"`
			Build struct {
				Version string `json:"version"`
				Repo    string `json:"repo"`
			} `json:"build"`
		}
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &info))
		require.Equal(t, id.DID().String(), info.ID)
		require.Equal(t, build.Version, info.Build.Version)
		require.Equal(t, "https://github.com/fil-forge/hilt", info.Build.Repo)
	})

	t.Run("returns a plain-text banner by default", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		rec := httptest.NewRecorder()
		e.ServeHTTP(rec, req)

		require.Equal(t, http.StatusOK, rec.Code)
		require.Contains(t, rec.Header().Get("Content-Type"), "text/plain")
		body := rec.Body.String()
		require.Contains(t, body, "hilt "+build.Version)
		require.Contains(t, body, "https://github.com/fil-forge/hilt")
		require.Contains(t, body, id.DID().String())
	})
}

func TestHealthRoute(t *testing.T) {
	id, err := appfx.NewIdentity(config.IdentityConfig{}, zap.NewNop())
	require.NoError(t, err)

	ucanSrv, err := appfx.NewUCANServer(appfx.UCANServerParams{Identity: id, Providers: providermemory.New(), Logger: zap.NewNop()})
	require.NoError(t, err)

	e := appfx.NewEchoServer(appfx.ServerParams{
		Logger:     zap.NewNop(),
		Identity:   id,
		UCANServer: ucanSrv,
		Auth:       config.AuthConfig{PartnerKey: "a-partner-key"},
	})

	// Public route: reachable without a partner-key bearer token, so deployments
	// can probe it.
	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	require.Equal(t, "OK", rec.Body.String())
}

func TestDIDDocumentRoute(t *testing.T) {
	id, err := appfx.NewIdentity(config.IdentityConfig{}, zap.NewNop())
	require.NoError(t, err)

	ucanSrv, err := appfx.NewUCANServer(appfx.UCANServerParams{Identity: id, Providers: providermemory.New(), Logger: zap.NewNop()})
	require.NoError(t, err)

	e := appfx.NewEchoServer(appfx.ServerParams{
		Logger:     zap.NewNop(),
		Identity:   id,
		UCANServer: ucanSrv,
	})

	// Public route: reachable without a partner-key bearer token.
	req := httptest.NewRequest(http.MethodGet, "/.well-known/did.json", nil)
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	require.Contains(t, rec.Header().Get("Content-Type"), "application/json")
	require.Contains(t, rec.Body.String(), id.DID().String())
	require.Equal(t, "max-age=300", rec.Header().Get("Cache-Control"))
	require.NotEmpty(t, rec.Header().Get("Last-Modified"))
	etag := rec.Header().Get("ETag")
	require.NotEmpty(t, etag)

	// A client that already holds the document gets a 304.
	req = httptest.NewRequest(http.MethodGet, "/.well-known/did.json", nil)
	req.Header.Set("If-None-Match", etag)
	rec = httptest.NewRecorder()
	e.ServeHTTP(rec, req)
	require.Equal(t, http.StatusNotModified, rec.Code)
	require.Empty(t, rec.Body.Bytes())
}

func TestUCANRequestLogsShareRequestID(t *testing.T) {
	id, err := appfx.NewIdentity(config.IdentityConfig{}, zap.NewNop())
	require.NoError(t, err)
	core, logs := observer.New(zapcore.InfoLevel)
	logger := zap.New(core)

	// An admin command: Hilt invokes it on itself, so it validates with no
	// proofs.
	ucanSrv, err := appfx.NewUCANServer(appfx.UCANServerParams{
		Identity:  id,
		Providers: providermemory.New(),
		Logger:    logger,
		AdminRoutes: []server.Route{server.NewRoute(s3bkt.List.Command,
			func(req execution.Request, res execution.Response) error {
				return res.SetSuccess(&s3bkt.ListOK{})
			},
		)},
	})
	require.NoError(t, err)
	e := appfx.NewEchoServer(appfx.ServerParams{Logger: logger, Identity: id, UCANServer: ucanSrv})

	inv, err := invocation.Invoke(id, id.DID(), s3bkt.List.Command, nil, invocation.WithAudience(id.DID()))
	require.NoError(t, err)
	var body bytes.Buffer
	require.NoError(t, container.New(container.WithInvocations(inv)).MarshalCBOR(&body))
	req := httptest.NewRequest(http.MethodPost, "/", &body)
	req.Header.Set("Content-Type", dagcbor.ContentType)
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)

	requestID := rec.Header().Get(echo.HeaderXRequestID)
	var got []any
	for _, msg := range []string{"request completed", "invocation handled"} {
		for _, entry := range logs.FilterMessage(msg).All() {
			got = append(got, entry.ContextMap()["request_id"])
		}
	}
	require.Equal(t, []any{requestID, requestID}, got)
}
