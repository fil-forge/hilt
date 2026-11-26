package testutil

import (
	"context"
	"fmt"
	"net/url"
	"runtime"
	"sync"
	"sync/atomic"
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

	// testPostgresTemplateDB holds the migrated schema every test database is
	// copied from.
	testPostgresTemplateDB = "hilt_template"
)

// postgresServer is the Postgres container a test binary shares. It is started
// by the first test that asks for a database and removed by the testcontainers
// reaper once the process exits.
type postgresServer struct {
	// dsn connects to the container's default database.
	dsn string
	// admin creates and drops the per-test databases.
	admin *pgxpool.Pool
	// databases numbers the databases handed out.
	databases atomic.Int64

	templateOnce sync.Once
	templateErr  error
}

var (
	sharedPostgresOnce sync.Once
	sharedPostgres     *postgresServer
	sharedPostgresErr  error
)

// startPostgres returns the process's Postgres container, starting it on the
// first call.
func startPostgres(t *testing.T) *postgresServer {
	t.Helper()
	sharedPostgresOnce.Do(func() {
		sharedPostgres, sharedPostgresErr = newPostgresServer()
	})
	require.NoError(t, sharedPostgresErr, "starting the shared postgres container")
	return sharedPostgres
}

func newPostgresServer() (*postgresServer, error) {
	// The container outlives the test that starts it, so nothing here may hang
	// off a test's context.
	ctx := context.Background()
	container, err := tcpostgres.Run(ctx,
		"postgres:16-alpine",
		tcpostgres.WithDatabase(testPostgresDB),
		tcpostgres.WithUsername(testPostgresUser),
		tcpostgres.WithPassword(testPostgresPass),
		// The data is thrown away with the container, so durability is traded
		// for speed. Every test holds its own pool, hence the connection limit.
		testcontainers.WithCmdArgs(
			"-c", "fsync=off",
			"-c", "synchronous_commit=off",
			"-c", "full_page_writes=off",
			"-c", "max_connections=500",
		),
		testcontainers.WithWaitStrategy(
			wait.ForLog("database system is ready to accept connections").
				WithOccurrence(2).
				WithStartupTimeout(60*time.Second),
		),
	)
	if err != nil {
		return nil, fmt.Errorf("starting postgres container: %w", err)
	}
	dsn, err := container.ConnectionString(ctx, "sslmode=disable")
	if err != nil {
		return nil, fmt.Errorf("reading postgres connection string: %w", err)
	}
	admin, err := pgxpool.New(ctx, dsn)
	if err != nil {
		return nil, fmt.Errorf("connecting to postgres: %w", err)
	}
	return &postgresServer{dsn: dsn, admin: admin}, nil
}

// databaseDSN is the server's DSN pointed at the named database.
func (s *postgresServer) databaseDSN(name string) (string, error) {
	u, err := url.Parse(s.dsn)
	if err != nil {
		return "", fmt.Errorf("parsing postgres DSN: %w", err)
	}
	u.Path = "/" + name
	return u.String(), nil
}

// template migrates the template database on the first call. No connection to
// it stays open: Postgres refuses to copy a database that has sessions.
func (s *postgresServer) template() error {
	s.templateOnce.Do(func() {
		ctx := context.Background()
		s.templateErr = func() error {
			if _, err := s.admin.Exec(ctx, "CREATE DATABASE "+testPostgresTemplateDB); err != nil {
				return fmt.Errorf("creating template database: %w", err)
			}
			dsn, err := s.databaseDSN(testPostgresTemplateDB)
			if err != nil {
				return err
			}
			pool, err := pgxpool.New(ctx, dsn)
			if err != nil {
				return fmt.Errorf("connecting to template database: %w", err)
			}
			defer pool.Close()
			if err := migrations.Up(ctx, pool, zap.NewNop()); err != nil {
				return fmt.Errorf("migrating template database: %w", err)
			}
			return nil
		}()
	})
	return s.templateErr
}

// newDatabase creates a database for one test, copied from template when one
// is named, and returns a pool on it. The database is dropped when the test
// finishes.
func (s *postgresServer) newDatabase(t *testing.T, template string) *pgxpool.Pool {
	t.Helper()
	ctx := context.Background()
	name := fmt.Sprintf("hilt_test_%d", s.databases.Add(1))
	create := "CREATE DATABASE " + name
	if template != "" {
		create += " TEMPLATE " + template
	}
	_, err := s.admin.Exec(ctx, create)
	require.NoError(t, err)

	dsn, err := s.databaseDSN(name)
	require.NoError(t, err)
	pool, err := pgxpool.New(ctx, dsn)
	require.NoError(t, err)
	t.Cleanup(func() {
		pool.Close()
		// FORCE ends any session a test left behind, such as a transaction it
		// holds a lock with.
		if _, err := s.admin.Exec(ctx, "DROP DATABASE IF EXISTS "+name+" WITH (FORCE)"); err != nil {
			t.Logf("dropping test database %s: %v", name, err)
		}
	})
	return pool
}

// CreatePostgres returns a connection pool on a fresh database carrying the
// hilt schema. Every test of a test binary shares one Postgres container; each
// call gets its own database, copied from a template migrated once per
// process, and the database is dropped when the test finishes.
func CreatePostgres(t *testing.T) *pgxpool.Pool {
	t.Helper()
	server := startPostgres(t)
	require.NoError(t, server.template())
	return server.newDatabase(t, testPostgresTemplateDB)
}

// CreateUnmigratedPostgres is CreatePostgres with an empty database, for tests
// that drive the migrations themselves.
func CreateUnmigratedPostgres(t *testing.T) *pgxpool.Pool {
	t.Helper()
	return startPostgres(t).newDatabase(t, "")
}

// PostgresOrSkip is [CreatePostgres] for a test that runs only where Docker
// is: without it the test skips, except on a Linux CI runner, where Docker is
// expected and its absence fails the test.
func PostgresOrSkip(t *testing.T) *pgxpool.Pool {
	t.Helper()
	requireDockerOrSkip(t)
	return CreatePostgres(t)
}

var (
	dockerOnce      sync.Once
	dockerAvailable bool
)

// requireDockerOrSkip skips the test when Docker is unavailable, and fails it
// instead on a Linux CI runner. The daemon is probed once per process.
func requireDockerOrSkip(t *testing.T) {
	t.Helper()
	dockerOnce.Do(func() { dockerAvailable = IsDockerAvailable(t) })
	if dockerAvailable {
		return
	}
	if IsRunningInCI(t) && runtime.GOOS == "linux" {
		t.Fatalf("docker is expected in CI linux testing environments, but wasn't found")
	}
	t.Skip("docker is not available")
}
