package middleware

import (
	"regexp"

	"github.com/fil-forge/hilt/pkg/reqlog"
	"github.com/labstack/echo/v4"
	echomiddleware "github.com/labstack/echo/v4/middleware"
)

// callerRequestID is the shape of a caller's X-Request-Id that Hilt keeps.
// POST / takes no credential, so anyone can send the header, and its value
// lands on every log line of the request: anything longer or with other
// characters is replaced with a generated id.
var callerRequestID = regexp.MustCompile(`^[A-Za-z0-9._-]{1,64}$`)

// RequestID gives each request an id, the caller's X-Request-Id when it sent
// a short, plain one, and returns it in the response's X-Request-Id. The id
// goes in the request's context ([reqlog.WithRequestID]), so the UCAN
// invocation lines a request produces carry the same request_id as its
// request line.
func RequestID() echo.MiddlewareFunc {
	assign := echomiddleware.RequestIDWithConfig(echomiddleware.RequestIDConfig{
		RequestIDHandler: func(c echo.Context, id string) {
			req := c.Request()
			c.SetRequest(req.WithContext(reqlog.WithRequestID(req.Context(), id)))
		},
	})
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		handler := assign(next)
		return func(c echo.Context) error {
			header := c.Request().Header
			if id := header.Get(echo.HeaderXRequestID); id != "" && !callerRequestID.MatchString(id) {
				header.Del(echo.HeaderXRequestID)
			}
			return handler(c)
		}
	}
}
