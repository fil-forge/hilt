package fx

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/fil-forge/hilt/pkg/config"
	"github.com/fil-forge/hilt/pkg/echo/middleware"
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

// NewEchoServer creates and configures the Echo HTTP server.
func NewEchoServer(logger *zap.Logger) *echo.Echo {
	e := echo.New()
	e.HideBanner = true
	e.HidePort = true

	e.Use(echomiddleware.Recover())
	e.Use(middleware.RequestLogger(logger))

	e.GET("/", func(c echo.Context) error {
		return c.String(http.StatusOK, "hello world")
	})
	e.GET("/health", func(c echo.Context) error {
		return c.String(http.StatusOK, "OK")
	})

	return e
}

// RegisterServerLifecycle hooks server start/stop to the fx lifecycle.
func RegisterServerLifecycle(
	lc fx.Lifecycle,
	e *echo.Echo,
	srv config.ServerConfig,
	logger *zap.Logger,
) {
	lc.Append(fx.Hook{
		OnStart: func(ctx context.Context) error {
			addr := fmt.Sprintf("%s:%d", srv.Host, srv.Port)
			logger.Info("starting hilt service", zap.String("address", addr))

			go func() {
				if err := e.Start(addr); err != nil && err != http.ErrServerClosed {
					logger.Fatal("server error", zap.Error(err))
				}
			}()

			return nil
		},
		OnStop: func(ctx context.Context) error {
			logger.Info("shutting down server")
			shutdownCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
			defer cancel()
			return e.Shutdown(shutdownCtx)
		},
	})
}
