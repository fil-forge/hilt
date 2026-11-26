package testutil

import (
	"context"
	"testing"
	"time"

	"github.com/fil-forge/hilt/pkg/tasks"
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
