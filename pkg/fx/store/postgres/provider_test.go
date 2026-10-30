package postgres_test

import (
	"testing"

	"github.com/stretchr/testify/require"
	"go.uber.org/fx/fxtest"
	"go.uber.org/zap"

	"github.com/fil-forge/hilt/internal/testutil"
	"github.com/fil-forge/hilt/pkg/config"
	storepostgres "github.com/fil-forge/hilt/pkg/fx/store/postgres"
)

func TestNewPostgresPool(t *testing.T) {
	t.Run("bounds every connection's lock wait and idle transaction", func(t *testing.T) {
		dsn := testutil.PostgresOrSkip(t).Config().ConnString()
		lc := fxtest.NewLifecycle(t)
		pool, err := storepostgres.NewPostgresPool(config.PostgresConfig{DSN: dsn}, lc, zap.NewNop())
		require.NoError(t, err)
		lc.RequireStart()
		defer lc.RequireStop()

		var lockTimeout, idleTimeout string
		require.NoError(t, pool.QueryRow(t.Context(), `SELECT current_setting('lock_timeout'), current_setting('idle_in_transaction_session_timeout')`).Scan(&lockTimeout, &idleTimeout))
		require.Equal(t, [2]string{"10s", "30s"}, [2]string{lockTimeout, idleTimeout})
	})
}
