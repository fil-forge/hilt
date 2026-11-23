package middleware_test

import (
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"

	"github.com/fil-forge/hilt/pkg/echo/middleware"
	"github.com/fil-forge/hilt/pkg/reqlog"
	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/require"
)

// serveRequestID serves one request carrying sent as its X-Request-Id
// (none when empty) and returns the response's X-Request-Id and the id the
// handler's context carried.
func serveRequestID(t *testing.T, sent string) (returned, seen string) {
	t.Helper()
	e := echo.New()
	e.Use(middleware.RequestID())
	e.GET("/", func(c echo.Context) error {
		seen, _ = reqlog.RequestID(c.Request().Context())
		return c.NoContent(http.StatusOK)
	})
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	if sent != "" {
		req.Header.Set(echo.HeaderXRequestID, sent)
	}
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)
	return rec.Header().Get(echo.HeaderXRequestID), seen
}

// generatedID is the shape of the id echo generates.
var generatedID = regexp.MustCompile(`^[A-Za-z0-9]{32}$`)

func TestRequestID(t *testing.T) {
	t.Run("keeps a short, plain id the caller sent", func(t *testing.T) {
		returned, seen := serveRequestID(t, "ingot-req_1.2")
		require.Equal(t, []string{"ingot-req_1.2", "ingot-req_1.2"}, []string{returned, seen})
	})

	generated := map[string]string{
		"no id":                "",
		"an id over 64 chars":  strings.Repeat("a", 65),
		"an id with a space":   "a b",
		"an id with a newline": "a\nb",
		"an id with a quote":   `a"b`,
	}
	for desc, sent := range generated {
		t.Run("generates an id for "+desc, func(t *testing.T) {
			returned, seen := serveRequestID(t, sent)
			require.True(t, generatedID.MatchString(returned) && seen == returned,
				"want one generated id returned and seen, got %q returned and %q seen", returned, seen)
		})
	}
}
