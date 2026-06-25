package fx

import (
	"github.com/fil-forge/hilt/pkg/config"
	"go.uber.org/fx"
)

// ConfigModule surfaces the individual config sections so consumers can depend
// on just the part they need.
var ConfigModule = fx.Module("config",
	fx.Provide(ProvideConfigs),
)

// Configs exposes the individual fields of the config to the fx graph.
type Configs struct {
	fx.Out
	Server   config.ServerConfig
	Log      config.LogConfig
	Storage  config.StorageConfig
	Postgres config.PostgresConfig
}

// ProvideConfigs provides the individual fields of the config.
func ProvideConfigs(cfg *config.Config) Configs {
	return Configs{
		Server:   cfg.Server,
		Log:      cfg.Log,
		Storage:  cfg.Storage,
		Postgres: cfg.Storage.Postgres,
	}
}
