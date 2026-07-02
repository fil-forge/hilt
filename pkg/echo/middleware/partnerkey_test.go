package middleware_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/fil-forge/hilt/pkg/echo/middleware"
	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

// newServer builds an echo server whose /guarded route is protected by the
// partner-key middleware (returning 200 when auth passes).
func newServer(partnerKey []string) *echo.Echo {
	e := echo.New()
	g := e.Group("", middleware.PartnerKeyAuth(partnerKey, zap.NewNop()))
	g.GET("/guarded", func(c echo.Context) error {
		return c.String(http.StatusOK, "ok")
	})
	return e
}

func do(t *testing.T, e *echo.Echo, authHeader string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/guarded", nil)
	if authHeader != "" {
		req.Header.Set(echo.HeaderAuthorization, authHeader)
	}
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)
	return rec
}

func TestPartnerKeyAuth(t *testing.T) {
	const key = "s3cr3t-partner-key"

	t.Run("correct bearer passes", func(t *testing.T) {
		rec := do(t, newServer([]string{key}), "Bearer "+key)
		require.Equal(t, http.StatusOK, rec.Code)
		require.Equal(t, "ok", rec.Body.String())
	})

	t.Run("wrong bearer is rejected", func(t *testing.T) {
		rec := do(t, newServer([]string{key}), "Bearer wrong")
		require.Equal(t, http.StatusUnauthorized, rec.Code)
		require.Equal(t, "Bearer", rec.Header().Get(echo.HeaderWWWAuthenticate))
	})

	t.Run("missing header is rejected", func(t *testing.T) {
		rec := do(t, newServer([]string{key}), "")
		require.Equal(t, http.StatusUnauthorized, rec.Code)
	})

	t.Run("non-bearer scheme is rejected", func(t *testing.T) {
		rec := do(t, newServer([]string{key}), "Basic "+key)
		require.Equal(t, http.StatusUnauthorized, rec.Code)
	})

	t.Run("unconfigured key rejects all", func(t *testing.T) {
		rec := do(t, newServer([]string{}), "Bearer ")
		require.Equal(t, http.StatusUnauthorized, rec.Code)
	})

	t.Run("empty/whitespace key rejects all", func(t *testing.T) {
		rec := do(t, newServer([]string{"", "  ", "\t"}), "Bearer ")
		require.Equal(t, http.StatusUnauthorized, rec.Code)
	})
}
