// Package config loads hilt service configuration from a config file,
// environment variables (HILT_ prefix), and built-in defaults.
package config

import (
	"fmt"
	"strings"

	"github.com/spf13/pflag"
	"github.com/spf13/viper"
)

// Valid values for StorageConfig.Type.
const (
	StorageTypeMemory   = "memory"
	StorageTypePostgres = "postgres"
)

// Config holds the hilt service configuration.
type Config struct {
	Server  ServerConfig  `mapstructure:"server"`
	Log     LogConfig     `mapstructure:"log"`
	Storage StorageConfig `mapstructure:"storage"`
}

// ServerConfig holds HTTP server settings.
type ServerConfig struct {
	Host string `mapstructure:"host"`
	Port int    `mapstructure:"port"`
}

// LogConfig holds logging settings.
type LogConfig struct {
	Level string `mapstructure:"level"`
}

// StorageConfig selects and configures the store backend.
type StorageConfig struct {
	// Type selects the backend: "memory" or "postgres". Defaults to "postgres".
	Type     string         `mapstructure:"type"`
	Postgres PostgresConfig `mapstructure:"postgres"`
}

// PostgresConfig holds PostgreSQL settings.
type PostgresConfig struct {
	// DSN is a libpq-style connection string, e.g.
	// "postgres://user:pass@host:5432/db?sslmode=disable".
	DSN string `mapstructure:"dsn"`
	// MaxConns is the maximum number of connections the pool will hold.
	MaxConns int32 `mapstructure:"max_conns"`
	// MinConns is the minimum number of idle connections the pool maintains.
	MinConns int32 `mapstructure:"min_conns"`
	// SkipMigrations disables automatic goose migrations on startup.
	SkipMigrations bool `mapstructure:"skip_migrations"`
}

// SetDefaults configures default values for viper.
func SetDefaults(v *viper.Viper) {
	v.SetDefault("server.host", "127.0.0.1")
	v.SetDefault("server.port", 8080)
	v.SetDefault("log.level", "info")

	v.SetDefault("storage.type", StorageTypePostgres)
	v.SetDefault("storage.postgres.dsn", "postgres://hilt:hilt@localhost:5432/hilt?sslmode=disable")
	v.SetDefault("storage.postgres.max_conns", 10)
	v.SetDefault("storage.postgres.min_conns", 0)
}

// BindEnvVars sets up environment variable binding with the HILT_ prefix.
func BindEnvVars(v *viper.Viper) {
	v.SetEnvPrefix("HILT")
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	v.AutomaticEnv()
}

// BindFlags binds known server flags from the flag set to their config keys, so
// a flag set on the command line overrides env vars, the config file, and
// defaults. Flags that are absent from the set are skipped.
func BindFlags(v *viper.Viper, flags *pflag.FlagSet) error {
	bindings := map[string]string{
		"server.host":                      "host",
		"server.port":                      "port",
		"storage.type":                     "storage",
		"storage.postgres.dsn":             "postgres-dsn",
		"storage.postgres.skip_migrations": "skip-migrations",
	}
	for key, name := range bindings {
		if f := flags.Lookup(name); f != nil {
			if err := v.BindPFlag(key, f); err != nil {
				return fmt.Errorf("binding flag %q: %w", name, err)
			}
		}
	}
	return nil
}

// LoadOption customizes how configuration is loaded.
type LoadOption func(*viper.Viper) error

// WithFlagSet binds command-line flags (see [BindFlags]) to the config so they
// take precedence over env vars, the config file, and defaults.
func WithFlagSet(flags *pflag.FlagSet) LoadOption {
	return func(v *viper.Viper) error {
		return BindFlags(v, flags)
	}
}

// Load creates a viper instance and loads configuration from the given config
// file (if provided), environment variables, and defaults.
func Load(configFile string, opts ...LoadOption) (*Config, error) {
	cfg, _, err := LoadWithViper(configFile, opts...)
	return cfg, err
}

// LoadWithViper creates a viper instance and loads configuration, returning both
// the Config struct and the viper instance for flag binding.
func LoadWithViper(configFile string, opts ...LoadOption) (*Config, *viper.Viper, error) {
	v := viper.New()

	SetDefaults(v)
	BindEnvVars(v)
	for _, opt := range opts {
		if err := opt(v); err != nil {
			return nil, nil, err
		}
	}

	if configFile != "" {
		v.SetConfigFile(configFile)
		if err := v.ReadInConfig(); err != nil {
			return nil, nil, fmt.Errorf("reading config file: %w", err)
		}
	} else {
		v.SetConfigName("config")
		v.SetConfigType("yaml")
		v.AddConfigPath(".")
		v.AddConfigPath("/etc/hilt/")
		// Ignore error if no config file found - use defaults and env vars.
		if err := v.ReadInConfig(); err != nil {
			if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
				return nil, nil, fmt.Errorf("reading config file: %w", err)
			}
		}
	}

	var cfg Config
	if err := v.Unmarshal(&cfg); err != nil {
		return nil, nil, fmt.Errorf("unmarshaling config: %w", err)
	}

	return &cfg, v, nil
}
