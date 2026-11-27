package testutil

import (
	"context"
	"testing"
	"time"

	"github.com/fil-forge/hilt/pkg/grant"
	"github.com/fil-forge/hilt/pkg/store"
	accesskeypostgres "github.com/fil-forge/hilt/pkg/store/accesskey/postgres"
	bucketpostgres "github.com/fil-forge/hilt/pkg/store/bucket/postgres"
	"github.com/fil-forge/hilt/pkg/store/bucketpolicy"
	bucketpolicypostgres "github.com/fil-forge/hilt/pkg/store/bucketpolicy/postgres"
	delegationpostgres "github.com/fil-forge/hilt/pkg/store/delegation/postgres"
	principalpostgres "github.com/fil-forge/hilt/pkg/store/principal/postgres"
	revocationpostgres "github.com/fil-forge/hilt/pkg/store/revocation/postgres"
	tenantpostgres "github.com/fil-forge/hilt/pkg/store/tenant/postgres"
	wrapkeypostgres "github.com/fil-forge/hilt/pkg/store/wrapkey/postgres"
	"github.com/fil-forge/hilt/pkg/tasks"
	"github.com/fil-forge/hilt/pkg/tasks/revocationqueue"
	"github.com/fil-forge/hilt/pkg/tasks/tenantqueue"
	"github.com/fil-forge/hilt/pkg/vault"
	s3bkt "github.com/fil-forge/libforge/commands/s3/bucket"
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
// status, create and delete its access keys, write and remove its buckets'
// policies, change the keys' grants and delete the tenant, and
// queue-revocation's, which publishes the revocations owed to publisher and
// retries a failed publish within a test's patience. The handlers read the
// tenants' signing keys from secrets, and tenant deletion publishes to
// publisher too. Tenant deletion needs a DID directory, which a wrap sets
// ([WithDirectory]). Each wrap may replace what queue-tenant's handlers work
// through, for a test that acts at a point in a handler's run.
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
			WrapKeys:    wrapkeypostgres.New(pool),
			Secrets:     secrets,
			Publisher:   publisher,
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

// WithDirectory returns a wrap for [StartServiceTasks] that gives tenant
// deletion the DID directory it deactivates the tenant's DID in.
func WithDirectory(directory tenantqueue.Directory) func(*tenantqueue.Deps) {
	return func(deps *tenantqueue.Deps) { deps.Directory = directory }
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

// BeforePolicyCommit returns a wrap for [StartServiceTasks] that calls before
// on every pass of a queue-tenant handler that writes or removes a policy
// (put-policy, delete-policy, and remove-principal for each policy it
// rewrites), once the handler has read everything it reads for that policy
// and before it records any write. What before does therefore lands between
// the handler's reads and the task's commit.
func BeforePolicyCommit(before func()) func(*tenantqueue.Deps) {
	return func(deps *tenantqueue.Deps) {
		deps.Policies = hookedPolicies{Store: deps.Policies, before: before}
	}
}

// hookedPolicies runs before when a handler asks for the statements that
// write or remove a policy, which it builds before recording any write.
type hookedPolicies struct {
	bucketpolicy.Store
	before func()
}

func (h hookedPolicies) PutStatements(tenant, bucket did.DID, doc s3bkt.PolicyDocument) (store.Statement, []store.Statement) {
	h.before()
	return h.Store.PutStatements(tenant, bucket, doc)
}

func (h hookedPolicies) DeleteStatements(bucket did.DID) (store.Statement, store.Statement) {
	h.before()
	return h.Store.DeleteStatements(bucket)
}

// PutPolicy stores doc as the policy of the tenant's bucket, with the
// statements a policy task's commit runs, and returns its ETag. It grants and
// revokes nothing: it is for a test that seeds a policy beside grants it
// stores itself.
func PutPolicy(t *testing.T, pool *pgxpool.Pool, tenant, bucket did.DID, doc s3bkt.PolicyDocument) string {
	t.Helper()
	ctx := t.Context()
	put, index := bucketpolicypostgres.New(pool).PutStatements(tenant, bucket, doc)
	tx, err := pool.Begin(ctx)
	require.NoError(t, err)
	defer tx.Rollback(ctx)
	tag, err := tx.Exec(ctx, put.SQL, put.Args...)
	require.NoError(t, err)
	require.EqualValues(t, 1, tag.RowsAffected(), "the bucket is not the tenant's")
	for _, st := range index {
		_, err := tx.Exec(ctx, st.SQL, st.Args...)
		require.NoError(t, err)
	}
	require.NoError(t, tx.Commit(ctx))
	return s3bkt.ETag(doc)
}
