package fx

import (
	"github.com/fil-forge/hilt/pkg/rpc"
	"github.com/fil-forge/hilt/pkg/rpc/service/auth"
	"github.com/fil-forge/libforge/identity"
	"github.com/fil-forge/ucantone/server"
	"go.uber.org/fx"
)

// RPCModule provides the Hilt UCAN RPC server and the command handlers it
// serves, collected into the "ucanRoutes" group.
var RPCModule = fx.Module("rpc",
	fx.Provide(
		auth.NewAuthorizer,
		NewUploadClient,
		NewUCANServer,
		asUCANRoute(rpc.NewAuthorizeRequestHandler),
		asUCANRoute(rpc.NewCreateBucketHandler),
		asUCANRoute(rpc.NewDeleteBucketHandler),
		asUCANRoute(rpc.NewBucketInfoHandler),
		asUCANRoute(rpc.NewListBucketsHandler),
	),
)

// asUCANRoute annotates a handler constructor so its result joins the
// "ucanRoutes" group consumed by the UCAN server.
func asUCANRoute(constructor any) any {
	return fx.Annotate(constructor, fx.ResultTags(`group:"ucanRoutes"`))
}

// UCANServerParams are the dependencies for the UCAN RPC server. Handlers are
// collected from the "ucanRoutes" fx group (see RPCModule).
type UCANServerParams struct {
	fx.In
	Identity identity.Identity // embeds multikey.Issuer, satisfying ucan.Issuer
	Routes   []server.Route    `group:"ucanRoutes"`
}

// NewUCANServer builds the ucantone UCAN RPC server with the service identity
// and registers each command handler. The returned *server.HTTPServer is an
// http.Handler mounted on the echo server (see NewEchoServer).
func NewUCANServer(p UCANServerParams) *server.HTTPServer {
	srv := server.NewHTTP(p.Identity)
	for _, r := range p.Routes {
		srv.Handle(r.Command, r.Handler)
	}
	return srv
}
