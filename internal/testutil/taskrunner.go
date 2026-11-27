package testutil

import (
	"context"
	"testing"
	"time"

	"github.com/fil-forge/hilt/pkg/grant"
	accesskeypostgres "github.com/fil-forge/hilt/pkg/store/accesskey/postgres"
	bucketpolicypostgres "github.com/fil-forge/hilt/pkg/store/bucketpolicy/postgres"
	delegationpostgres "github.com/fil-forge/hilt/pkg/store/delegation/postgres"
	revocationpostgres "github.com/fil-forge/hilt/pkg/store/revocation/postgres"
	tenantpostgres "github.com/fil-forge/hilt/pkg/store/tenant/postgres"
	"github.com/fil-forge/hilt/pkg/tasks"
	"github.com/fil-forge/hilt/pkg/tasks/revocationqueue"
	"github.com/fil-forge/hilt/pkg/tasks/tenantqueue"
	"github.com/fil-forge/hilt/pkg/vault"
	"github.com/fil-forge/libforge/taskrunner"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"
)

// StartTaskRunner returns a running task runner of the service's queues over
// pool, one worker per queue, with its tables created. register adds the
// handlers before it starts. The runner polls every 20ms, so a test does not
// wait on the production interval, and is stopped when the test finishes.
func StartTaskRunner(t *testing.T, pool *pgxpool.Pool, register func(r *taskrunner.Runner)) *taskrunner.Runner {
	t.Helper()
	r, err := taskrunner.New(pool, taskrunner.Options{
		Schema:       tasks.Schema,
		Queues:       tasks.Queues(1, 1),
		PollInterval: 20 * time.Millisecond,
	})
	require.NoError(t, err)
	if register != nil {
		register(r)
	}
	require.NoError(t, r.Migrate(t.Context()))
	require.NoError(t, r.Start(context.Background()))
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), WaitTimeout)
		defer cancel()
		if err := r.Stop(ctx); err != nil {
			t.Logf("stopping the task runner: %v", err)
		}
	})
	return r
}

// StartServiceTasks returns a running task runner over pool with the
// service's own handlers registered: queue-tenant's, which change a tenant's
// status and its keys' grants, and queue-revocation's, which publishes the
// revocations owed to publisher and retries a failed publish within a test's
// patience. The handlers read the tenants' signing keys from secrets.
func StartServiceTasks(t *testing.T, pool *pgxpool.Pool, secrets vault.Vault, publisher grant.RevocationPublisher) *taskrunner.Runner {
	t.Helper()
	return StartTaskRunner(t, pool, func(r *taskrunner.Runner) {
		_, err := tenantqueue.New(r, tenantqueue.Deps{
			Tenants:     tenantpostgres.New(pool),
			AccessKeys:  accesskeypostgres.New(pool),
			Policies:    bucketpolicypostgres.New(pool),
			Delegations: delegationpostgres.New(pool),
			Secrets:     secrets,
		})
		require.NoError(t, err)
		_, err = revocationqueue.New(r, revocationqueue.Deps{
			Owed:         revocationpostgres.New(pool),
			Secrets:      secrets,
			Publisher:    publisher,
			PublishRetry: taskrunner.RetryPolicy{First: 20 * time.Millisecond, Max: 50 * time.Millisecond, Multiplier: 2},
		})
		require.NoError(t, err)
	})
}
