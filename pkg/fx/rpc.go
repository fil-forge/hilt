package fx

import (
	"fmt"
	"time"

	"github.com/fil-forge/hilt/pkg/config"
	"github.com/fil-forge/hilt/pkg/rpc"
	"github.com/fil-forge/hilt/pkg/rpc/service/auth"
	bucketsvc "github.com/fil-forge/hilt/pkg/rpc/service/bucket"
	"github.com/fil-forge/libforge/identity"
	"github.com/fil-forge/ucantone/did/key"
	"github.com/fil-forge/ucantone/did/resolver"
	"github.com/fil-forge/ucantone/did/web"
	"github.com/fil-forge/ucantone/server"
	"github.com/fil-forge/ucantone/validator"
	"go.uber.org/fx"
	"go.uber.org/zap"
)

// RPCModule provides the Hilt UCAN RPC server and the command handlers it
// serves, collected into the "ucanRoutes" group.
var RPCModule = fx.Module("rpc",
	fx.Provide(
		auth.NewAuthorizer,
		fx.Annotate(
			NewUploadClient,
			fx.As(fx.Self()),
			fx.As(new(bucketsvc.UploadClient)),
		),
		bucketsvc.New,
		NewUCANServer,
		asUCANRoute(rpc.NewAuthorizeRequestHandler),
		asUCANRoute(rpc.NewCreateBucketHandler),
		asUCANRoute(rpc.NewDeleteBucketHandler),
		asUCANRoute(rpc.NewBucketInfoHandler),
		asUCANRoute(rpc.NewListBucketsHandler),
		asUCANRoute(rpc.NewAddProviderHandler),
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
	Identity identity.Identity   // embeds multikey.Issuer, satisfying ucan.Issuer
	Server   config.ServerConfig // supplies InsecureDIDResolution
	Logger   *zap.Logger
	Routes   []server.Route `group:"ucanRoutes"`
}

// NewUCANServer builds the ucantone UCAN RPC server with the service identity
// and registers each command handler. The returned *server.HTTPServer is an
// http.Handler mounted on the echo server (see NewEchoServer).
//
// The server is configured with a DID resolver that supports did:key and
// did:web. did:web is required so the validator can verify UCANs issued by, or
// addressed to, did:web identities — including Hilt's own service identity when
// identity.service_id is a did:web. The service's own DID document is resolved
// locally (no network round-trip) via a well-known tier ahead of the cached
// HTTP resolver.
func NewUCANServer(p UCANServerParams) (*server.HTTPServer, error) {
	didResolver, err := newDIDResolver(p.Identity, p.Server.InsecureDIDResolution, p.Logger)
	if err != nil {
		return nil, err
	}

	srv := server.NewHTTP(p.Identity,
		server.WithValidationOptions(
			validator.WithDIDResolver(didResolver),
		),
	)
	for _, r := range p.Routes {
		srv.Handle(r.Command, r.Handler)
	}
	return srv, nil
}

// newDIDResolver builds the DID resolver used to validate UCANs on the RPC
// server. did:web documents are fetched over HTTPS unless insecure is set, in
// which case they are fetched over HTTP (development only). Resolved documents
// are cached for three hours.
func newDIDResolver(id identity.Identity, insecure bool, logger *zap.Logger) (resolver.ByMethod, error) {
	webResolverOpts := []web.Option{}
	if insecure {
		logger.Warn("insecure DID resolution enabled: did:web will be resolved over HTTP instead of HTTPS; this should only be used for development purposes")
		webResolverOpts = append(webResolverOpts, web.WithInsecure(true))
	}
	webResolver, err := web.NewResolver(webResolverOpts...)
	if err != nil {
		return nil, fmt.Errorf("creating did:web resolver: %w", err)
	}

	selfDoc, err := id.DIDDocument()
	if err != nil {
		return nil, fmt.Errorf("creating DID document for service identity: %w", err)
	}

	return resolver.ByMethod{
		"key": key.Resolver,
		"web": resolver.Tiered{
			resolver.WellKnown{id.DID(): selfDoc},
			resolver.NewCached(webResolver, 3*time.Hour),
		},
	}, nil
}
