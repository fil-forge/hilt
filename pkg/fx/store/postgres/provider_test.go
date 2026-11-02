package postgres_test

import (
	"strconv"
	"testing"

	"github.com/fil-forge/hilt/pkg/config"
	pgfx "github.com/fil-forge/hilt/pkg/fx/store/postgres"
	"github.com/fil-forge/hilt/pkg/store"
	"github.com/stretchr/testify/require"
	"go.uber.org/fx/fxtest"
	"go.uber.org/zap"
)

func TestNewPostgresPool(t *testing.T) {
	t.Run("sets idle_in_transaction_session_timeout on every connection to the idle transaction timeout", func(t *testing.T) {
		// pgx opens connections lazily, so building the pool needs no server.
		pool, err := pgfx.NewPostgresPool(
			config.PostgresConfig{DSN: "postgres://any-user:any-password@localhost:5432/any-db?sslmode=disable"},
			fxtest.NewLifecycle(t),
			zap.NewNop(),
		)
		require.NoError(t, err)
		t.Cleanup(pool.Close)

		require.Equal(t,
			strconv.FormatInt(store.IdleTransactionTimeout.Milliseconds(), 10),
			pool.Config().ConnConfig.RuntimeParams["idle_in_transaction_session_timeout"],
		)
	})
}
