package fx

import (
	"github.com/fil-forge/hilt/pkg/api"
	accesskeysvc "github.com/fil-forge/hilt/pkg/api/service/accesskey"
	tenantsvc "github.com/fil-forge/hilt/pkg/api/service/tenant"
	"go.uber.org/fx"
)

// APIModule provides the tenant management API services + handlers as routes,
// collected into the "routes" group and registered on the echo server.
var APIModule = fx.Module("api",
	fx.Provide(
		// Services
		tenantsvc.New,
		accesskeysvc.New,
		// Tenants
		asRoute(api.NewProvisionTenantHandler),
		asRoute(api.NewGetTenantHandler),
		asRoute(api.NewDeleteTenantHandler),
		asRoute(api.NewUpdateTenantStatusHandler),
		// Access Keys
		asRoute(api.NewCreateAccessKeyHandler),
		asRoute(api.NewListAccessKeysHandler),
		asRoute(api.NewGetAccessKeyHandler),
		asRoute(api.NewDeleteAccessKeyHandler),
	),
)

// asRoute annotates a handler constructor so its result joins the "routes"
// group consumed by the echo server.
func asRoute(constructor any) any {
	return fx.Annotate(constructor, fx.ResultTags(`group:"routes"`))
}
