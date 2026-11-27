package fx

import (
	"context"
	"fmt"

	storepostgres "github.com/fil-forge/hilt/pkg/fx/store/postgres"
	"github.com/fil-forge/hilt/pkg/grant"
	"github.com/fil-forge/hilt/pkg/store/accesskey"
	"github.com/fil-forge/hilt/pkg/store/bucket"
	"github.com/fil-forge/hilt/pkg/store/bucketpolicy"
	"github.com/fil-forge/hilt/pkg/store/delegation"
	"github.com/fil-forge/hilt/pkg/store/principal"
	"github.com/fil-forge/hilt/pkg/store/revocation"
	"github.com/fil-forge/hilt/pkg/store/tenant"
	"github.com/fil-forge/hilt/pkg/store/wrapkey"
	"github.com/fil-forge/hilt/pkg/tasks/revocationqueue"
	"github.com/fil-forge/hilt/pkg/tasks/tenantqueue"
	"github.com/fil-forge/hilt/pkg/vault"
	"github.com/fil-forge/libforge/taskrunner"
	"github.com/fil-forge/ucantone/did/plc"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/metric"
	"go.uber.org/fx"
	"go.uber.org/zap"
)

// TasksModule registers the task queues' handlers with the runner the store
// module provides, and starts and stops the runner with the service.
var TasksModule = fx.Module("tasks",
	fx.Provide(NewRevocationQueue, NewTenantQueue),
	fx.Invoke(RegisterTaskRunnerLifecycle),
)

// NewRevocationQueue registers the handler that publishes the revocations
// owed with the runner.
func NewRevocationQueue(
	runner *taskrunner.Runner,
	owed revocation.Store,
	secrets vault.Vault,
	publisher grant.RevocationPublisher,
	logger *zap.Logger,
) (*revocationqueue.Queue, error) {
	return revocationqueue.New(runner, revocationqueue.Deps{
		Owed:      owed,
		Secrets:   secrets,
		Publisher: publisher,
		Logger:    logger.Named("revocations"),
	})
}

// NewTenantQueue registers the handlers of the changes to a tenant's
// authority with the runner.
func NewTenantQueue(
	runner *taskrunner.Runner,
	tenants tenant.Store,
	accessKeys accesskey.Store,
	principals principal.Store,
	buckets bucket.Store,
	policies bucketpolicy.Store,
	delegations delegation.Store,
	wrapKeys wrapkey.Store,
	secrets vault.Vault,
	directory *plc.DirectoryClient,
	publisher grant.RevocationPublisher,
	logger *zap.Logger,
) (*tenantqueue.Queue, error) {
	return tenantqueue.New(runner, tenantqueue.Deps{
		Tenants:     tenants,
		AccessKeys:  accessKeys,
		Principals:  principals,
		Buckets:     buckets,
		Policies:    policies,
		Delegations: delegations,
		WrapKeys:    wrapKeys,
		Secrets:     secrets,
		Directory:   directory,
		Publisher:   publisher,
		Logger:      logger.Named("tenant-changes"),
	})
}

// RegisterTaskRunnerLifecycle starts the runner when the service starts and
// stops it on shutdown. Taking the queues is what makes fx register their
// handlers before the runner starts, and taking the migrated pool orders this
// hook after the one that creates the runner's tables.
//
// The gauges of the revocations owed report to the global OpenTelemetry meter
// provider, as the runner's own do. Nothing installs one, so they are
// recorded nowhere until the service exports metrics.
func RegisterTaskRunnerLifecycle(
	lc fx.Lifecycle,
	runner *taskrunner.Runner,
	revocations *revocationqueue.Queue,
	_ *tenantqueue.Queue,
	_ *storepostgres.MigratedPool,
	logger *zap.Logger,
) {
	var gauges metric.Registration
	lc.Append(fx.Hook{
		OnStart: func(ctx context.Context) error {
			if err := runner.Start(ctx); err != nil {
				return fmt.Errorf("starting the task runner: %w", err)
			}
			// A failure to register leaves the gauges unreported and the
			// queues running.
			var err error
			if gauges, err = revocations.RegisterMetrics(otel.GetMeterProvider()); err != nil {
				logger.Warn("revocation gauges not registered", zap.Error(err))
			}
			return nil
		},
		OnStop: func(ctx context.Context) error {
			if gauges != nil {
				if err := gauges.Unregister(); err != nil {
					logger.Warn("unregistering revocation gauges", zap.Error(err))
				}
			}
			logger.Info("stopping the task runner")
			return runner.Stop(ctx)
		},
	})
}
