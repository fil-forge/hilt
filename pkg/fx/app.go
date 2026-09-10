package fx

import (
	"fmt"

	"github.com/fil-forge/hilt/pkg/config"
	storememory "github.com/fil-forge/hilt/pkg/fx/store/memory"
	storepostgres "github.com/fil-forge/hilt/pkg/fx/store/postgres"
	vaultmemory "github.com/fil-forge/hilt/pkg/fx/vault/memory"
	vaultopenbao "github.com/fil-forge/hilt/pkg/fx/vault/openbao"
	"go.uber.org/fx"
)

// AppModule aggregates all application modules into a single fx option,
// selecting the storage backend from the configured storage type.
func AppModule(cfg *config.Config) fx.Option {
	opts := []fx.Option{
		fx.Supply(cfg),
		ConfigModule,
		LoggerModule,
		IdentityModule,
		PLCModule,
		RevocationModule,
		APIModule,
		RPCModule,
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

	vault, err := vaultModule(cfg)
	if err != nil {
		return fx.Error(err)
	}
	opts = append(opts, vault)

	return fx.Options(opts...)
}

// vaultModule selects the vault backend module from the configured vault type.
func vaultModule(cfg *config.Config) (fx.Option, error) {
	switch cfg.Vault.Type {
	case config.VaultTypeMemory:
		return vaultmemory.Module, nil
	case config.VaultTypeOpenBao, "":
		// Empty type is treated as the default backend (openbao).
		return vaultopenbao.Module, nil
	default:
		return nil, fmt.Errorf("unknown vault.type %q (valid: memory, openbao)", cfg.Vault.Type)
	}
}
