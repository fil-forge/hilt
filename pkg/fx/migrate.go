package fx

import (
	"fmt"

	"github.com/fil-forge/hilt/pkg/config"
	storepostgres "github.com/fil-forge/hilt/pkg/fx/store/postgres"
	"github.com/fil-forge/hilt/pkg/iammigrate"
	"github.com/fil-forge/hilt/pkg/store/delegation"
	pgdelegation "github.com/fil-forge/hilt/pkg/store/delegation/postgres"
	"github.com/jackc/pgx/v5/pgxpool"
	"go.uber.org/fx"
)

// IAMMigrateModule wires the reduced graph `hilt migrate iam` runs on: config,
// logger, a Postgres pool that runs no schema migrations, the vault, the
// revocation client, and the [iammigrate.Migrator]. The pool skips migrations
// because the IAM schema migration refuses to run while the keys this command
// removes still exist. The memory storage backend is refused: it holds no keys
// that could outlive the process.
func IAMMigrateModule(cfg *config.Config) fx.Option {
	switch cfg.Storage.Type {
	case config.StorageTypePostgres, "":
	case config.StorageTypeMemory:
		return fx.Error(fmt.Errorf("storage.type %q holds no access keys to migrate; point the command at the postgres database", cfg.Storage.Type))
	default:
		return fx.Error(fmt.Errorf("unknown storage.type %q (valid: postgres)", cfg.Storage.Type))
	}
	vault, err := vaultModule(cfg)
	if err != nil {
		return fx.Error(err)
	}
	return fx.Options(
		fx.Supply(cfg),
		ConfigModule,
		LoggerModule,
		RevocationModule,
		vault,
		fx.Provide(
			storepostgres.NewPostgresPool,
			newUnmigratedDelegationStore,
			iammigrate.New,
		),
	)
}

// newUnmigratedDelegationStore builds the delegation store over the bare pool
// rather than the migrated one the serving app uses.
func newUnmigratedDelegationStore(pool *pgxpool.Pool) delegation.Store {
	return pgdelegation.New(pool)
}
