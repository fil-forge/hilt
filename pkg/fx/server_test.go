package fx_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/fil-forge/hilt/pkg/config"
	appfx "github.com/fil-forge/hilt/pkg/fx"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

func TestDIDDocumentRoute(t *testing.T) {
	id, err := appfx.NewIdentity(config.IdentityConfig{}, zap.NewNop())
	require.NoError(t, err)

	ucanSrv, err := appfx.NewUCANServer(appfx.UCANServerParams{Identity: id, Logger: zap.NewNop()})
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
}
