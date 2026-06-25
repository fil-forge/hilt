package fx_test

import (
	"testing"

	"github.com/fil-forge/hilt/pkg/config"
	appfx "github.com/fil-forge/hilt/pkg/fx"
	"github.com/stretchr/testify/require"
	"go.uber.org/fx"
)

func validate(cfg *config.Config) error {
	return fx.ValidateApp(appfx.AppModule(cfg), fx.NopLogger)
}

func TestAppModuleStorageSelection(t *testing.T) {
	t.Run("memory", func(t *testing.T) {
		cfg := &config.Config{Storage: config.StorageConfig{Type: config.StorageTypeMemory}}
		require.NoError(t, validate(cfg))
	})

	t.Run("postgres", func(t *testing.T) {
		cfg := &config.Config{Storage: config.StorageConfig{
			Type:     config.StorageTypePostgres,
			Postgres: config.PostgresConfig{DSN: "postgres://hilt:hilt@localhost:5432/hilt?sslmode=disable"},
		}}
		require.NoError(t, validate(cfg))
	})

	t.Run("empty defaults to postgres", func(t *testing.T) {
		cfg := &config.Config{Storage: config.StorageConfig{
			Type:     "",
			Postgres: config.PostgresConfig{DSN: "postgres://hilt:hilt@localhost:5432/hilt?sslmode=disable"},
		}}
		require.NoError(t, validate(cfg))
	})

	t.Run("unknown type errors", func(t *testing.T) {
		cfg := &config.Config{Storage: config.StorageConfig{Type: "bogus"}}
		require.Error(t, validate(cfg))
	})
}
