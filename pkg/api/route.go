// Package api defines the HTTP handlers for the Hilt tenant management API
// (the fil-one service orchestrator "Tenant API"). Handlers are exposed as
// [Route] values, collected via fx and registered on the echo server.
package api

import (
	"net/http"

	"github.com/labstack/echo/v4"
	"go.uber.org/zap"
)

// Route maps an HTTP method and path to the echo handler that serves it. A
// Route can be carried as a value — e.g. collected via dependency injection —
// and registered on an echo server later.
type Route struct {
	Method  string
	Path    string
	Handler echo.HandlerFunc
}

// NewRoute builds a [Route] from a method, path, and handler.
func NewRoute(method, path string, handler echo.HandlerFunc) Route {
	return Route{Method: method, Path: path, Handler: handler}
}

// notImplemented returns a handler that logs and responds 501. Used by the
// current stub handlers until the endpoints are implemented.
func notImplemented(logger *zap.Logger, name string) echo.HandlerFunc {
	return func(c echo.Context) error {
		logger.Debug("handler not implemented", zap.String("handler", name))
		return echo.NewHTTPError(http.StatusNotImplemented, "not implemented")
	}
}
