// Package postgres wires the Postgres-backed store implementations into the
// application via uber-go/fx.
package postgres

import (
	"context"
	"errors"
	"fmt"

	"github.com/fil-forge/hilt/pkg/config"
	"github.com/fil-forge/hilt/pkg/migrations"
	"github.com/fil-forge/hilt/pkg/store/accesskey"
	pgaccesskey "github.com/fil-forge/hilt/pkg/store/accesskey/postgres"
	"github.com/fil-forge/hilt/pkg/store/bucket"
	pgbucket "github.com/fil-forge/hilt/pkg/store/bucket/postgres"
	"github.com/fil-forge/hilt/pkg/store/delegation"
	pgdelegation "github.com/fil-forge/hilt/pkg/store/delegation/postgres"
	"github.com/fil-forge/hilt/pkg/store/provider"
	pgprovider "github.com/fil-forge/hilt/pkg/store/provider/postgres"
	"github.com/fil-forge/hilt/pkg/store/tenant"
	pgtenant "github.com/fil-forge/hilt/pkg/store/tenant/postgres"
	"github.com/jackc/pgx/v5/pgxpool"
	"go.uber.org/fx"
	"go.uber.org/zap"
)

// Module provides the Postgres-backed store implementations.
var Module = fx.Module("postgres-store",
	fx.Provide(
		NewPostgresPool,
		NewMigratedPool,
		NewAccessKeyStore,
		NewBucketStore,
		NewDelegationStore,
		NewProviderStore,
		NewTenantStore,
	),
)

// MigratedPool is a *pgxpool.Pool whose schema is guaranteed to be at the head
// migration revision by the time any store that depends on it is used. Store
// constructors depend on *MigratedPool rather than *pgxpool.Pool so the fx
// dependency graph orders NewMigratedPool's migration hook before the stores.
type MigratedPool struct {
	*pgxpool.Pool
}

// NewPostgresPool creates a pgx connection pool and registers a lifecycle hook
// to ping on start and close it at shutdown.
func NewPostgresPool(cfg config.PostgresConfig, lc fx.Lifecycle, logger *zap.Logger) (*pgxpool.Pool, error) {
	if cfg.DSN == "" {
		return nil, errors.New("storage.postgres.dsn is required when storage.type is \"postgres\"")
	}

	poolCfg, err := pgxpool.ParseConfig(cfg.DSN)
	if err != nil {
		return nil, fmt.Errorf("parsing postgres DSN: %w", err)
	}
	if cfg.MaxConns > 0 {
		poolCfg.MaxConns = cfg.MaxConns
	}
	if cfg.MinConns > 0 {
		poolCfg.MinConns = cfg.MinConns
	}

	pool, err := pgxpool.NewWithConfig(context.Background(), poolCfg)
	if err != nil {
		return nil, fmt.Errorf("creating pgx pool: %w", err)
	}

	lc.Append(fx.Hook{
		OnStart: func(ctx context.Context) error {
			if err := pool.Ping(ctx); err != nil {
				return fmt.Errorf("pinging postgres: %w", err)
			}
			logger.Info("connected to postgres", zap.Int32("max_conns", poolCfg.MaxConns))
			return nil
		},
		OnStop: func(ctx context.Context) error {
			pool.Close()
			return nil
		},
	})

	return pool, nil
}

// NewMigratedPool registers an OnStart hook that runs goose migrations against
// the pool (unless storage.postgres.skip_migrations is true) and returns a
// *MigratedPool wrapper that store constructors depend on.
func NewMigratedPool(lc fx.Lifecycle, cfg config.PostgresConfig, pool *pgxpool.Pool, logger *zap.Logger) *MigratedPool {
	lc.Append(fx.Hook{
		OnStart: func(ctx context.Context) error {
			if cfg.SkipMigrations {
				logger.Warn("skipping postgres migrations (storage.postgres.skip_migrations=true)")
				return nil
			}
			logger.Info("running postgres migrations")
			return migrations.Up(ctx, pool, logger)
		},
	})
	return &MigratedPool{Pool: pool}
}

func NewAccessKeyStore(mdb *MigratedPool) accesskey.Store {
	return pgaccesskey.New(mdb.Pool)
}

func NewBucketStore(mdb *MigratedPool) bucket.Store {
	return pgbucket.New(mdb.Pool)
}

func NewDelegationStore(mdb *MigratedPool) delegation.Store {
	return pgdelegation.New(mdb.Pool)
}

func NewProviderStore(mdb *MigratedPool) provider.Store {
	return pgprovider.New(mdb.Pool)
}

func NewTenantStore(mdb *MigratedPool) tenant.Store {
	return pgtenant.New(mdb.Pool)
}
