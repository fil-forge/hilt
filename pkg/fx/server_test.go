package fx_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/fil-forge/hilt/pkg/build"
	"github.com/fil-forge/hilt/pkg/config"
	appfx "github.com/fil-forge/hilt/pkg/fx"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

func TestServerInfoRoute(t *testing.T) {
	id, err := appfx.NewIdentity(config.IdentityConfig{}, zap.NewNop())
	require.NoError(t, err)

	e := appfx.NewEchoServer(appfx.ServerParams{
		Logger:     zap.NewNop(),
		Identity:   id,
		UCANServer: appfx.NewUCANServer(appfx.UCANServerParams{Identity: id}),
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

func TestDIDDocumentRoute(t *testing.T) {
	id, err := appfx.NewIdentity(config.IdentityConfig{}, zap.NewNop())
	require.NoError(t, err)

	e := appfx.NewEchoServer(appfx.ServerParams{
		Logger:     zap.NewNop(),
		Identity:   id,
		UCANServer: appfx.NewUCANServer(appfx.UCANServerParams{Identity: id}),
	})

	// Public route: reachable without a partner-key bearer token.
	req := httptest.NewRequest(http.MethodGet, "/.well-known/did.json", nil)
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	require.Contains(t, rec.Header().Get("Content-Type"), "application/json")
	require.Contains(t, rec.Body.String(), id.DID().String())
}
