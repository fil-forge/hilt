package fx_test

import (
	"testing"

	"github.com/fil-forge/hilt/pkg/config"
	appfx "github.com/fil-forge/hilt/pkg/fx"
	"github.com/stretchr/testify/require"
	"go.uber.org/fx"
)

func validateMigrate(cfg *config.Config) error {
	return fx.ValidateApp(appfx.IAMMigrateModule(cfg), fx.NopLogger)
}

func TestIAMMigrateModule(t *testing.T) {
	postgres := config.StorageConfig{
		Type:     config.StorageTypePostgres,
		Postgres: config.PostgresConfig{DSN: "postgres://hilt:hilt@localhost:5432/hilt?sslmode=disable"},
	}

	t.Run("postgres with the memory vault", func(t *testing.T) {
		cfg := &config.Config{Storage: postgres, Vault: config.VaultConfig{Type: config.VaultTypeMemory}}
		require.NoError(t, validateMigrate(cfg))
	})

	t.Run("postgres with openbao", func(t *testing.T) {
		cfg := &config.Config{Storage: postgres, Vault: config.VaultConfig{Type: config.VaultTypeOpenBao}}
		require.NoError(t, validateMigrate(cfg))
	})

	t.Run("empty storage type defaults to postgres", func(t *testing.T) {
		cfg := &config.Config{Storage: config.StorageConfig{Type: "", Postgres: postgres.Postgres}}
		require.NoError(t, validateMigrate(cfg))
	})

	t.Run("memory storage is refused", func(t *testing.T) {
		cfg := &config.Config{Storage: config.StorageConfig{Type: config.StorageTypeMemory}}
		require.ErrorContains(t, validateMigrate(cfg), "no access keys to migrate")
	})

	t.Run("unknown storage type errors", func(t *testing.T) {
		cfg := &config.Config{Storage: config.StorageConfig{Type: "bogus"}}
		require.Error(t, validateMigrate(cfg))
	})

	t.Run("unknown vault type errors", func(t *testing.T) {
		cfg := &config.Config{Storage: postgres, Vault: config.VaultConfig{Type: "bogus"}}
		require.Error(t, validateMigrate(cfg))
	})
}
