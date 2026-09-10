package testutil

import (
	"runtime"
	"testing"
	"time"

	"github.com/fil-forge/hilt/pkg/migrations"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	tcpostgres "github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"
	"go.uber.org/zap"
)

const (
	testPostgresDB   = "hilt"
	testPostgresUser = "hilt"
	testPostgresPass = "hilt"
)

// CreatePostgres starts a throwaway Postgres container, runs the hilt
// migrations against it, and returns a connection pool. The container is
// cleaned up when the test finishes.
func CreatePostgres(t *testing.T) *pgxpool.Pool {
	t.Helper()

	ctx := t.Context()
	container, err := tcpostgres.Run(ctx,
		"postgres:16-alpine",
		tcpostgres.WithDatabase(testPostgresDB),
		tcpostgres.WithUsername(testPostgresUser),
		tcpostgres.WithPassword(testPostgresPass),
		testcontainers.WithWaitStrategy(
			wait.ForLog("database system is ready to accept connections").
				WithOccurrence(2).
				WithStartupTimeout(30*time.Second),
		),
	)
	require.NoError(t, err)
	testcontainers.CleanupContainer(t, container)

	dsn, err := container.ConnectionString(ctx, "sslmode=disable")
	require.NoError(t, err)

	t.Logf("Postgres DSN: %s", dsn)

	pool, err := pgxpool.New(ctx, dsn)
	require.NoError(t, err)
	t.Cleanup(pool.Close)

	require.NoError(t, migrations.Up(ctx, pool, zap.NewNop()))
	return pool
}

// PostgresOrSkip is [CreatePostgres] for a test that runs only where Docker
// is: without it the test skips, except on a Linux CI runner, where Docker is
// expected and its absence fails the test.
func PostgresOrSkip(t *testing.T) *pgxpool.Pool {
	t.Helper()
	if IsRunningInCI(t) && runtime.GOOS == "linux" && !IsDockerAvailable(t) {
		t.Fatalf("docker is expected in CI linux testing environments, but wasn't found")
	}
	if !IsDockerAvailable(t) {
		t.SkipNow()
	}
	return CreatePostgres(t)
}
