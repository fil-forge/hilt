package fx

import (
	"github.com/fil-forge/hilt/pkg/config"
	"go.uber.org/fx"
)

// AppModule aggregates all application modules into a single fx option.
func AppModule(cfg *config.Config) fx.Option {
	return fx.Options(
		fx.Supply(cfg),
		ConfigModule,
		LoggerModule,
		ServerModule,
	)
}
