package fx

import (
	"fmt"

	"github.com/fil-forge/hilt/pkg/config"
	storememory "github.com/fil-forge/hilt/pkg/fx/store/memory"
	storepostgres "github.com/fil-forge/hilt/pkg/fx/store/postgres"
	"go.uber.org/fx"
)

// AppModule aggregates all application modules into a single fx option,
// selecting the storage backend from the configured storage type.
func AppModule(cfg *config.Config) fx.Option {
	opts := []fx.Option{
		fx.Supply(cfg),
		ConfigModule,
		LoggerModule,
		APIModule,
		ServerModule,
	}

	switch cfg.Storage.Type {
	case config.StorageTypeMemory:
		opts = append(opts, storememory.Module)
	case config.StorageTypePostgres, "":
		// Empty type is treated as the default backend (postgres).
		opts = append(opts, storepostgres.Module)
	default:
		return fx.Error(fmt.Errorf("unknown storage.type %q (valid: memory, postgres)", cfg.Storage.Type))
	}

	return fx.Options(opts...)
}
