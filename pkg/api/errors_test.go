package api

import (
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	ucanerrors "github.com/fil-forge/ucantone/errors"
	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/require"
)

// Echo's default error handler rewrites a string or error Message into its own
// map and passes any other value to c.JSON untouched. These tests pin that
// second path: the [Error] body reaches the client as written, so an echo
// upgrade that starts rewriting struct messages fails here rather than in a
// handler test.
func TestHTTPErrorBody(t *testing.T) {
	named := ucanerrors.New("UnknownBucket", "unknown bucket")

	cases := map[string]struct {
		err      error
		expected string
	}{
		"a named error carries its name as the code": {
			err:      named,
			expected: `{"code":"UnknownBucket","message":"unknown bucket"}`,
		},
		"a wrapped named error keeps the sentinel's code and the wrapped message": {
			err:      fmt.Errorf("%w: ghost", named),
			expected: `{"code":"UnknownBucket","message":"unknown bucket: ghost"}`,
		},
		"an unnamed error is returned without a code": {
			err:      errors.New("boom"),
			expected: `{"message":"boom"}`,
		},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			e := echo.New()
			e.GET("/", func(c echo.Context) error {
				return httpError(http.StatusConflict, tc.err)
			})
			rec := httptest.NewRecorder()
			e.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))

			require.JSONEq(t, tc.expected, rec.Body.String())
		})
	}
}
