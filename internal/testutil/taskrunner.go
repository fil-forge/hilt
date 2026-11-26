package testutil

import (
	"context"
	"testing"
	"time"

	"github.com/fil-forge/hilt/pkg/grant"
	accesskeypostgres "github.com/fil-forge/hilt/pkg/store/accesskey/postgres"
	bucketpostgres "github.com/fil-forge/hilt/pkg/store/bucket/postgres"
	bucketpolicypostgres "github.com/fil-forge/hilt/pkg/store/bucketpolicy/postgres"
	delegationpostgres "github.com/fil-forge/hilt/pkg/store/delegation/postgres"
	principalpostgres "github.com/fil-forge/hilt/pkg/store/principal/postgres"
	revocationpostgres "github.com/fil-forge/hilt/pkg/store/revocation/postgres"
	tenantpostgres "github.com/fil-forge/hilt/pkg/store/tenant/postgres"
	"github.com/fil-forge/hilt/pkg/tasks"
	"github.com/fil-forge/hilt/pkg/tasks/revocationqueue"
	"github.com/fil-forge/hilt/pkg/tasks/tenantqueue"
	"github.com/fil-forge/hilt/pkg/vault"
	"github.com/fil-forge/libforge/taskrunner"
	"github.com/fil-forge/ucantone/did"
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
// status, create and delete its access keys and change their grants, and
// queue-revocation's, which publishes the revocations owed to publisher and
// retries a failed publish within a test's patience. The handlers read the
// tenants' signing keys from secrets. Each wrap may replace what
// queue-tenant's handlers work through, for a test that acts at a point in a
// handler's run.
func StartServiceTasks(t *testing.T, pool *pgxpool.Pool, secrets vault.Vault, publisher grant.RevocationPublisher, wrap ...func(*tenantqueue.Deps)) *taskrunner.Runner {
	t.Helper()
	return StartTaskRunner(t, pool, func(r *taskrunner.Runner) {
		deps := tenantqueue.Deps{
			Tenants:     tenantpostgres.New(pool),
			AccessKeys:  accesskeypostgres.New(pool),
			Principals:  principalpostgres.New(pool),
			Buckets:     bucketpostgres.New(pool),
			Policies:    bucketpolicypostgres.New(pool),
			Delegations: delegationpostgres.New(pool),
			Secrets:     secrets,
		}
		for _, w := range wrap {
			w(&deps)
		}
		_, err := tenantqueue.New(r, deps)
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

// AwaitPublished waits for the tenant's queue-revocation tasks that are
// queued or running to finish, so that what a change recorded as owed has
// been published, or its publishing has failed for good.
func AwaitPublished(t *testing.T, r *taskrunner.Runner, tenant did.DID) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), WaitTimeout)
	defer cancel()
	pending, err := r.PendingOn(ctx, tasks.QueueRevocation, tenant.String())
	require.NoError(t, err)
	_, err = r.WaitAll(ctx, tasks.QueueRevocation, pending...)
	require.NoError(t, err, "the tenant's revocations were not published")
}
