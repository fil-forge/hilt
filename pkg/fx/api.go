package fx

import (
	"github.com/fil-forge/hilt/pkg/api"
	accesskeysvc "github.com/fil-forge/hilt/pkg/api/service/accesskey"
	bucketpolicysvc "github.com/fil-forge/hilt/pkg/api/service/bucketpolicy"
	principalsvc "github.com/fil-forge/hilt/pkg/api/service/principal"
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
		principalsvc.New,
		bucketpolicysvc.New,
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
		// Principals
		asRoute(api.NewCreatePrincipalHandler),
		asRoute(api.NewListPrincipalsHandler),
		asRoute(api.NewGetPrincipalHandler),
		asRoute(api.NewDeletePrincipalHandler),
		asRoute(api.NewListPrincipalAccessKeysHandler),
		// Bucket policies
		asRoute(api.NewGetBucketPolicyHandler),
		asRoute(api.NewPutBucketPolicyHandler),
		asRoute(api.NewDeleteBucketPolicyHandler),
		asRoute(api.NewListPrincipalPoliciesHandler),
		asRoute(api.NewGetPrincipalAccessHandler),
	),
)

// asRoute annotates a handler constructor so its result joins the "routes"
// group consumed by the echo server.
func asRoute(constructor any) any {
	return fx.Annotate(constructor, fx.ResultTags(`group:"routes"`))
}
