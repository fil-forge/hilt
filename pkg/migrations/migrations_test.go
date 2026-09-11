package migrations_test

import (
	"context"
	"database/sql"
	"runtime"
	"testing"

	"github.com/fil-forge/hilt/internal/testutil"
	"github.com/fil-forge/hilt/pkg/migrations"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

// accessKeyIAMVersion is the migration that splits the access-key name
// uniqueness by principal (00008_access_key_iam.sql).
const accessKeyIAMVersion = 8

// upToAccessKeyIAM starts a Postgres container, migrates it to
// accessKeyIAMVersion, and seeds a provider, a tenant and two principals.
func upToAccessKeyIAM(t *testing.T) *sql.DB {
	t.Helper()
	if testutil.IsRunningInCI(t) && runtime.GOOS == "linux" {
		if !testutil.IsDockerAvailable(t) {
			t.Fatalf("docker is expected in CI linux testing environments, but wasn't found")
		}
	}
	if !testutil.IsDockerAvailable(t) {
		t.SkipNow()
	}

	ctx := t.Context()
	pool := testutil.CreateUnmigratedPostgres(t)
	db := stdlib.OpenDBFromPool(pool)
	t.Cleanup(func() { _ = db.Close() })
	require.NoError(t, migrations.UpTo(ctx, db, accessKeyIAMVersion, zap.NewNop()))

	exec(t, ctx, db, `INSERT INTO provider (id, region) VALUES ('did:key:provider', 'us-east-1')`)
	exec(t, ctx, db, `INSERT INTO tenant (id, external_id, provider_id, status)
		VALUES ('did:plc:tenant', 'tenant-1', 'did:key:provider', 'active')`)
	exec(t, ctx, db, `INSERT INTO principal (tenant_id, external_id) VALUES ('did:plc:tenant', 'alice'), ('did:plc:tenant', 'bob')`)
	return db
}

func exec(t *testing.T, ctx context.Context, db *sql.DB, query string, args ...any) {
	t.Helper()
	_, err := db.ExecContext(ctx, query, args...)
	require.NoError(t, err)
}

func TestAccessKeyIAMDown(t *testing.T) {
	t.Run("refuses a tenant holding two keys of one name", func(t *testing.T) {
		ctx := t.Context()
		db := upToAccessKeyIAM(t)
		// Two principals of the same tenant each hold a key named "laptop" —
		// legal under this migration, unrepresentable before it.
		exec(t, ctx, db, `INSERT INTO access_key (id, tenant_id, name, permissions, principal)
			VALUES ('did:key:ak1', 'did:plc:tenant', 'laptop', '{}', 'alice'),
			       ('did:key:ak2', 'did:plc:tenant', 'laptop', '{}', 'bob')`)

		err := migrations.Down(ctx, db, zap.NewNop())
		require.Error(t, err)
		require.Contains(t, err.Error(), "access_key has duplicate (tenant_id, name): (did:plc:tenant, laptop)")
		require.Contains(t, err.Error(), "the pre-IAM schema cannot hold two keys of one tenant with the same name")

		// The rollback left the schema as it was: both keys are still there.
		var count int
		require.NoError(t, db.QueryRowContext(ctx, `SELECT COUNT(*) FROM access_key`).Scan(&count))
		require.Equal(t, 2, count)
	})

	t.Run("rolls back when no tenant holds two keys of one name", func(t *testing.T) {
		ctx := t.Context()
		db := upToAccessKeyIAM(t)
		exec(t, ctx, db, `INSERT INTO access_key (id, tenant_id, name, permissions, principal)
			VALUES ('did:key:ak1', 'did:plc:tenant', 'laptop', '{}', 'alice'),
			       ('did:key:ak2', 'did:plc:tenant', 'desktop', '{}', 'bob')`)

		require.NoError(t, migrations.Down(ctx, db, zap.NewNop()))

		// The pre-IAM schema is back: no principal column, and the tenant-wide
		// unique constraint again refuses a second key of the same name.
		var exists bool
		require.NoError(t, db.QueryRowContext(ctx, `SELECT EXISTS (
			SELECT 1 FROM information_schema.columns
			WHERE table_name = 'access_key' AND column_name = 'principal')`).Scan(&exists))
		require.False(t, exists)
		_, err := db.ExecContext(ctx, `INSERT INTO access_key (id, tenant_id, name, permissions)
			VALUES ('did:key:ak3', 'did:plc:tenant', 'laptop', '{}')`)
		require.ErrorContains(t, err, "access_key_tenant_id_name_key")
	})
}
