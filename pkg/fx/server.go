package fx

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"strings"

	"github.com/fil-forge/hilt/pkg/api"
	"github.com/fil-forge/hilt/pkg/build"
	"github.com/fil-forge/hilt/pkg/config"
	"github.com/fil-forge/hilt/pkg/echo/middleware"
	"github.com/fil-forge/libforge/identity"
	"github.com/fil-forge/ucantone/server"
	"github.com/labstack/echo/v4"
	echomiddleware "github.com/labstack/echo/v4/middleware"
	"go.uber.org/fx"
	"go.uber.org/zap"
)

// ServerModule provides the HTTP server with lifecycle management.
var ServerModule = fx.Module("server",
	fx.Provide(NewEchoServer),
	fx.Invoke(RegisterServerLifecycle),
)

// ServerParams are the dependencies for constructing the echo server. Routes
// are collected from the "routes" fx group (see APIModule).
type ServerParams struct {
	fx.In
	Logger     *zap.Logger
	Auth       config.AuthConfig
	Identity   identity.Identity
	Routes     []api.Route `group:"routes"`
	UCANServer *server.HTTPServer
}

// NewEchoServer creates and configures the Echo HTTP server.
func NewEchoServer(p ServerParams) *echo.Echo {
	e := echo.New()
	e.HideBanner = true
	e.HidePort = true

	e.Use(echomiddleware.Recover())
	e.Use(middleware.RequestLogger(p.Logger))

	e.GET("/", serverInfoHandler(p.Identity))
	e.GET("/health", func(c echo.Context) error {
		return c.String(http.StatusOK, "OK")
	})
	// Public DID document for did:web resolution of the service identity.
	e.GET("/.well-known/did.json", didDocumentHandler(p.Logger, p.Identity))

	// UCAN RPC API (for Ingot): invocations self-authenticate via the dispatcher,
	// so this stays outside the partner-key group.
	e.POST("/", echo.WrapHandler(p.UCANServer))

	// Tenant API routes require partner-key bearer auth; / and /health stay open.
	api := e.Group("", middleware.PartnerKeyAuth(strings.Split(p.Auth.PartnerKey, ","), p.Logger))
	for _, r := range p.Routes {
		api.Add(r.Method, r.Path, r.Handler)
	}

	return e
}

// RegisterServerLifecycle hooks server start/stop to the fx lifecycle.
func RegisterServerLifecycle(
	lc fx.Lifecycle,
	e *echo.Echo,
	cfg config.ServerConfig,
	logger *zap.Logger,
) {
	lc.Append(fx.Hook{
		OnStart: func(ctx context.Context) error {
			addr := fmt.Sprintf("%s:%d", cfg.Host, cfg.Port)

			// Bind synchronously so a failure (e.g. port already in use) is
			// returned from OnStart and aborts fx startup.
			ln, err := net.Listen("tcp", addr)
			if err != nil {
				return fmt.Errorf("binding %s: %w", addr, err)
			}
			e.Listener = ln
			logger.Info("starting Hilt service", zap.String("address", addr))
			go func() {
				// e.Start reuses the listener bound above and blocks serving
				// until Shutdown, which returns http.ErrServerClosed.
				if err := e.Start(addr); err != nil && err != http.ErrServerClosed {
					logger.Error("server stopped unexpectedly", zap.Error(err))
				}
			}()

			return nil
		},
		OnStop: func(ctx context.Context) error {
			logger.Info("shutting down server")
			return e.Shutdown(ctx)
		},
	})
}

// serverInfo identifies the service and its build, served on GET /.
type serverInfo struct {
	ID    string    `json:"id"`
	Build buildInfo `json:"build"`
}

// buildInfo is the version and source repository of the running build.
type buildInfo struct {
	Version string `json:"version"`
	Repo    string `json:"repo"`
}

// serverInfoHandler serves the service DID and build info: JSON when requested
// via the Accept header, otherwise a plain-text banner.
func serverInfoHandler(id identity.Identity) echo.HandlerFunc {
	info := serverInfo{
		ID: id.DID().String(),
		Build: buildInfo{
			Version: build.Version,
			Repo:    "https://github.com/fil-forge/hilt",
		},
	}
	return func(c echo.Context) error {
		// Media type tokens are case-insensitive.
		if strings.Contains(strings.ToLower(c.Request().Header.Get("Accept")), "application/json") {
			return c.JSON(http.StatusOK, info)
		}
		banner := fmt.Sprintf("🗡️ hilt %s\n- %s\n- %s", info.Build.Version, info.Build.Repo, info.ID)
		return c.String(http.StatusOK, banner)
	}
}

// didDocumentHandler serves the service identity's DID document for did:web
// resolution, so other services can verify Hilt's UCAN signatures.
func didDocumentHandler(logger *zap.Logger, id identity.Identity) echo.HandlerFunc {
	return func(c echo.Context) error {
		doc, err := id.DIDDocument()
		if err != nil {
			logger.Error("building DID document", zap.Error(err))
			return echo.NewHTTPError(http.StatusInternalServerError, "internal error")
		}
		return c.JSON(http.StatusOK, doc)
	}
}
