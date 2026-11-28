package fx_test

import (
	"context"
	"testing"
	"time"

	htestutil "github.com/fil-forge/hilt/internal/testutil"
	"github.com/fil-forge/hilt/pkg/config"
	appfx "github.com/fil-forge/hilt/pkg/fx"
	storepostgres "github.com/fil-forge/hilt/pkg/fx/store/postgres"
	"github.com/fil-forge/hilt/pkg/tasks"
	"github.com/fil-forge/hilt/pkg/tasks/revocationqueue"
	"github.com/fil-forge/libforge/taskrunner"
	"github.com/fil-forge/libforge/testutil"
	"github.com/stretchr/testify/require"
	"go.uber.org/fx"
	"go.uber.org/zap"
)

// TestAppStartsTaskRunner starts the whole app and checks the task runner
// came up with it: its tables exist, and a queued task runs.
func TestAppStartsTaskRunner(t *testing.T) {
	pool := htestutil.PostgresOrSkip(t)
	cfg := &config.Config{
		// Port 0 binds any free port.
		Server: config.ServerConfig{Host: "127.0.0.1"},
		Storage: config.StorageConfig{
			Type:     config.StorageTypePostgres,
			Postgres: config.PostgresConfig{DSN: pool.Config().ConnString()},
		},
		Vault:      config.VaultConfig{Type: config.VaultTypeMemory},
		PLC:        config.PLCConfig{Directory: "http://plc.test"},
		Upload:     config.UploadConfig{ServiceID: testutil.RandomDID(t).String(), ServiceURL: "http://sprue.test", ProductID: testutil.RandomDID(t).String()},
		Revocation: config.RevocationConfig{ServiceID: testutil.RandomDID(t).String(), ServiceURL: "http://swarf.test"},
		Tasks:      config.TasksConfig{TenantWorkers: 1, RevocationWorkers: 1},
	}

	tables := []string{"queue_tenant_tasks", "queue_tenant_leases", "queue_revocation_tasks", "queue_revocation_leases"}
	exists := func(table string) bool {
		t.Helper()
		var found bool
		require.NoError(t, pool.QueryRow(t.Context(), `SELECT to_regclass($1) IS NOT NULL`, tasks.Schema+"."+table).Scan(&found))
		return found
	}
	for _, table := range tables {
		require.False(t, exists(table), "%s exists before the app starts", table)
	}

	var runner *taskrunner.Runner
	app := fx.New(
		appfx.AppModule(cfg),
		fx.NopLogger,
		fx.Decorate(func(*zap.Logger) *zap.Logger { return zap.NewNop() }),
		fx.Populate(&runner),
	)
	require.NoError(t, app.Err())

	startCtx, cancel := context.WithTimeout(t.Context(), htestutil.WaitTimeout)
	defer cancel()
	require.NoError(t, app.Start(startCtx))
	stopped := false
	stop := func() {
		if stopped {
			return
		}
		stopped = true
		ctx, cancel := context.WithTimeout(context.Background(), htestutil.WaitTimeout)
		defer cancel()
		require.NoError(t, app.Stop(ctx))
	}
	t.Cleanup(stop)

	for _, table := range tables {
		require.True(t, exists(table), "%s was not created", table)
	}

	// A publish for a tenant that owes nothing ends at once and without
	// error, which takes a started runner with the handler registered.
	tenant := testutil.RandomDID(t)
	id, err := runner.Submit(t.Context(), revocationqueue.PublishSpec(tenant))
	require.NoError(t, err)
	ids := []taskrunner.TaskID{id}
	waitCtx, cancelWait := context.WithTimeout(t.Context(), htestutil.WaitTimeout)
	defer cancelWait()
	ended, err := runner.WaitAll(waitCtx, tasks.QueueRevocation, ids...)
	require.NoError(t, err)
	require.NoError(t, ended[ids[0]].Err)

	// Stopping the app stops the runner: it runs nothing further.
	stop()
	_, err = runner.Run(t.Context(), taskrunner.Spec{Queue: tasks.QueueRevocation, Subject: tenant.String(), Action: tasks.ActionPublish})
	require.ErrorIs(t, err, taskrunner.ErrNotStarted)
}

func TestNewTaskRunnerRefusesNegativeWorkers(t *testing.T) {
	_, err := storepostgres.NewTaskRunner(config.TasksConfig{TenantWorkers: -1}, nil, zap.NewNop())
	require.ErrorContains(t, err, "tasks.tenant_workers must not be negative")
	_, err = storepostgres.NewTaskRunner(config.TasksConfig{RevocationWorkers: -1}, nil, zap.NewNop())
	require.ErrorContains(t, err, "tasks.revocation_workers must not be negative")
}

// The service refuses to start on grant timing that would never renew a
// grant in time. The checks run before the queue touches the runner.
func TestNewTenantQueueRefusesBadGrantTiming(t *testing.T) {
	for _, grants := range []config.GrantsConfig{
		{Lifetime: time.Hour, RenewBefore: time.Minute, RenewalInterval: time.Hour},
		{Lifetime: time.Hour, RenewBefore: time.Minute, RenewalInterval: -time.Second},
		{Lifetime: time.Hour, RenewBefore: 2 * time.Hour, RenewalInterval: time.Minute},
	} {
		_, err := appfx.NewTenantQueue(nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, grants, zap.NewNop())
		require.Error(t, err, "%+v", grants)
	}
}
