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

	for _, storageType := range []string{"bogus", "memory"} {
		t.Run(storageType+" is refused, naming the valid type", func(t *testing.T) {
			cfg := &config.Config{Storage: config.StorageConfig{Type: storageType}}
			err := validate(cfg)
			require.ErrorContains(t, err, `unknown storage.type "`+storageType+`" (valid: postgres)`)
		})
	}
}

func TestAppModuleVaultSelection(t *testing.T) {
	cfg := func(vaultType string) *config.Config {
		return &config.Config{
			Storage: config.StorageConfig{Type: config.StorageTypePostgres},
			Vault:   config.VaultConfig{Type: vaultType},
		}
	}

	t.Run("memory", func(t *testing.T) {
		require.NoError(t, validate(cfg(config.VaultTypeMemory)))
	})

	t.Run("empty defaults to openbao", func(t *testing.T) {
		require.NoError(t, validate(cfg("")))
	})

	t.Run("openbao", func(t *testing.T) {
		require.NoError(t, validate(cfg(config.VaultTypeOpenBao)))
	})

	t.Run("unknown type errors", func(t *testing.T) {
		require.Error(t, validate(cfg("bogus")))
	})
}
