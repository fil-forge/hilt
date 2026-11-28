package fx

import (
	"context"
	"fmt"
	"time"

	"github.com/fil-forge/hilt/pkg/config"
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
	fx.Invoke(RegisterTaskRunnerLifecycle, RegisterGrantRenewal),
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
	grants config.GrantsConfig,
	logger *zap.Logger,
) (*tenantqueue.Queue, error) {
	timing, interval := grantTiming(grants)
	if interval <= 0 || interval >= timing.RenewBefore {
		return nil, fmt.Errorf("grants.renewal_interval %s must be positive and shorter than grants.renew_before %s", interval, timing.RenewBefore)
	}
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
		Grants:      timing,
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

// RegisterGrantRenewal keeps the access keys' grants from expiring: when the
// service starts and every grants.renewal_interval after, it queues a
// renewal for each tenant with grants due and deletes the delegations that
// have expired ([tenantqueue.Queue.RenewDue]). It is registered after the
// runner's lifecycle, so the runner has started when the first pass runs.
func RegisterGrantRenewal(
	lc fx.Lifecycle,
	runner *taskrunner.Runner,
	tenants *tenantqueue.Queue,
	grants config.GrantsConfig,
	logger *zap.Logger,
) {
	_, interval := grantTiming(grants)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	lc.Append(fx.StartStopHook(
		func() {
			go func() {
				defer close(done)
				renewGrants(ctx, runner, tenants, logger.Named("grant-renewal"), interval)
			}()
		},
		// The stop waits for the loop, so no pass is still running when the
		// pool closes. Canceling ctx ends one in progress.
		func() {
			cancel()
			<-done
		},
	))
}

// renewGrants runs [tenantqueue.Queue.RenewDue] once, then every interval,
// until ctx is canceled. A failed pass is logged and the next one tries
// again: a grant is due its renewal window ahead of its expiry, so keys keep
// working through that many failed passes.
func renewGrants(ctx context.Context, runner *taskrunner.Runner, tenants *tenantqueue.Queue, logger *zap.Logger, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		queued, deleted, err := tenants.RenewDue(ctx, runner)
		switch {
		case ctx.Err() != nil:
			return
		case err != nil:
			logger.Error("renewing grants failed", zap.Error(err))
		case queued > 0 || deleted > 0:
			logger.Info("queued grant renewals", zap.Int("tenants", queued), zap.Int64("expired_delegations_deleted", deleted))
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

// defaultRenewalInterval is how often the renewal pass runs when the config
// does not say.
const defaultRenewalInterval = time.Hour

// grantTiming returns the grant timing and the renewal pass's interval the
// config sets, each unset one at its default, as when the config is built by
// hand rather than loaded.
func grantTiming(cfg config.GrantsConfig) (grant.Timing, time.Duration) {
	timing := grant.Timing{Lifetime: cfg.Lifetime, RenewBefore: cfg.RenewBefore}
	if timing.Lifetime == 0 {
		timing.Lifetime = grant.DefaultLifetime
	}
	if timing.RenewBefore == 0 {
		timing.RenewBefore = grant.DefaultRenewBefore
	}
	interval := cfg.RenewalInterval
	if interval == 0 {
		interval = defaultRenewalInterval
	}
	return timing, interval
}
