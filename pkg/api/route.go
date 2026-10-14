// Package api defines the HTTP handlers for the Hilt tenant management API
// (the fil-one service orchestrator "Tenant API"). Handlers are exposed as
// [Route] values, collected via fx and registered on the echo server.
package api

import (
	"net/http"

	principalsvc "github.com/fil-forge/hilt/pkg/api/service/principal"
	tenantsvc "github.com/fil-forge/hilt/pkg/api/service/tenant"
	"github.com/labstack/echo/v4"
)

// Route maps an HTTP method and path to the echo handler that serves it. A
// Route can be carried as a value — e.g. collected via dependency injection —
// and registered on an echo server later.
type Route struct {
	Method  string
	Path    string
	Handler echo.HandlerFunc
}

// NewRoute builds a [Route] from a method, path, and handler. The route refuses
// a tenantId or principalId parameter its service would refuse to create, before
// the handler runs: Echo matches on the raw path and hands such an id over
// still escaped, so it would otherwise be looked up in a form it was never
// stored under.
func NewRoute(method, path string, handler echo.HandlerFunc) Route {
	return Route{Method: method, Path: path, Handler: func(c echo.Context) error {
		if id := c.Param("tenantId"); id != "" && !tenantsvc.ValidID(id) {
			return httpError(http.StatusBadRequest, tenantsvc.ErrInvalidTenantID)
		}
		if id := c.Param("principalId"); id != "" && !principalsvc.ValidID(id) {
			return httpError(http.StatusUnprocessableEntity, principalsvc.ErrInvalidPrincipalID)
		}
		return handler(c)
	}}
}
