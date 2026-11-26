// Package postgres wires the Postgres-backed store implementations into the
// application via uber-go/fx.
package postgres

import (
	"context"
	"errors"
	"fmt"

	"github.com/exaring/otelpgx"
	"github.com/fil-forge/hilt/pkg/config"
	"github.com/fil-forge/hilt/pkg/migrations"
	"github.com/fil-forge/hilt/pkg/store/accesskey"
	pgaccesskey "github.com/fil-forge/hilt/pkg/store/accesskey/postgres"
	"github.com/fil-forge/hilt/pkg/store/bucket"
	pgbucket "github.com/fil-forge/hilt/pkg/store/bucket/postgres"
	"github.com/fil-forge/hilt/pkg/store/bucketpolicy"
	pgbucketpolicy "github.com/fil-forge/hilt/pkg/store/bucketpolicy/postgres"
	"github.com/fil-forge/hilt/pkg/store/delegation"
	pgdelegation "github.com/fil-forge/hilt/pkg/store/delegation/postgres"
	"github.com/fil-forge/hilt/pkg/store/principal"
	pgprincipal "github.com/fil-forge/hilt/pkg/store/principal/postgres"
	"github.com/fil-forge/hilt/pkg/store/provider"
	pgprovider "github.com/fil-forge/hilt/pkg/store/provider/postgres"
	"github.com/fil-forge/hilt/pkg/store/revocation"
	pgrevocation "github.com/fil-forge/hilt/pkg/store/revocation/postgres"
	"github.com/fil-forge/hilt/pkg/store/tenant"
	pgtenant "github.com/fil-forge/hilt/pkg/store/tenant/postgres"
	"github.com/fil-forge/hilt/pkg/store/usage"
	pgusage "github.com/fil-forge/hilt/pkg/store/usage/postgres"
	"github.com/fil-forge/hilt/pkg/store/wrapkey"
	pgwrapkey "github.com/fil-forge/hilt/pkg/store/wrapkey/postgres"
	"github.com/fil-forge/hilt/pkg/tasks"
	"github.com/fil-forge/libforge/taskrunner"
	"github.com/jackc/pgx/v5/pgxpool"
	"go.uber.org/fx"
	"go.uber.org/zap"
)

// Module provides the Postgres-backed store implementations and the task
// runner, whose queues are tables in the same database.
var Module = fx.Module("postgres-store",
	fx.Provide(
		NewPostgresPool,
		NewTaskRunner,
		NewMigratedPool,
		NewAccessKeyStore,
		NewBucketStore,
		NewDelegationStore,
		NewPolicyStore,
		NewPrincipalStore,
		NewProviderStore,
		NewRevocationStore,
		NewTenantStore,
		NewUsageStore,
		NewWrapKeyStore,
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
	// Every query is a span on the caller's trace.
	poolCfg.ConnConfig.Tracer = otelpgx.NewTracer()

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

// NewTaskRunner builds the runner of the durable task queues over the pool.
// It runs nothing until it is started: handlers are registered with it first,
// and [NewMigratedPool] creates its tables.
func NewTaskRunner(cfg config.TasksConfig, pool *pgxpool.Pool, logger *zap.Logger) (*taskrunner.Runner, error) {
	if cfg.TenantWorkers < 0 {
		return nil, fmt.Errorf("tasks.tenant_workers must not be negative, got %d", cfg.TenantWorkers)
	}
	if cfg.RevocationWorkers < 0 {
		return nil, fmt.Errorf("tasks.revocation_workers must not be negative, got %d", cfg.RevocationWorkers)
	}
	return taskrunner.New(pool, taskrunner.Options{
		Schema: tasks.Schema,
		Queues: tasks.Queues(cfg.TenantWorkers, cfg.RevocationWorkers),
		Logger: logger.Named("tasks"),
	})
}

// NewMigratedPool registers an OnStart hook that runs the goose migrations
// against the pool and then creates the task queues' tables, which the runner
// owns and versions itself (unless storage.postgres.skip_migrations is true,
// which skips both), and returns a *MigratedPool wrapper that store
// constructors depend on.
func NewMigratedPool(lc fx.Lifecycle, cfg config.PostgresConfig, pool *pgxpool.Pool, runner *taskrunner.Runner, logger *zap.Logger) *MigratedPool {
	lc.Append(fx.Hook{
		OnStart: func(ctx context.Context) error {
			if cfg.SkipMigrations {
				logger.Warn("skipping postgres migrations (storage.postgres.skip_migrations=true)")
				return nil
			}
			logger.Info("running postgres migrations")
			if err := migrations.Up(ctx, pool, logger); err != nil {
				return err
			}
			if err := runner.Migrate(ctx); err != nil {
				return fmt.Errorf("creating the task queues' tables: %w", err)
			}
			return nil
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

func NewPolicyStore(mdb *MigratedPool) bucketpolicy.Store {
	return pgbucketpolicy.New(mdb.Pool)
}

func NewPrincipalStore(mdb *MigratedPool) principal.Store {
	return pgprincipal.New(mdb.Pool)
}

func NewProviderStore(mdb *MigratedPool) provider.Store {
	return pgprovider.New(mdb.Pool)
}

func NewRevocationStore(mdb *MigratedPool) revocation.Store {
	return pgrevocation.New(mdb.Pool)
}

func NewTenantStore(mdb *MigratedPool) tenant.Store {
	return pgtenant.New(mdb.Pool)
}

func NewUsageStore(mdb *MigratedPool) usage.Store {
	return pgusage.New(mdb.Pool)
}

func NewWrapKeyStore(mdb *MigratedPool) wrapkey.Store {
	return pgwrapkey.New(mdb.Pool)
}
