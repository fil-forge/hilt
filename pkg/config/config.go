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

// Valid values for VaultConfig.Type.
const (
	VaultTypeMemory    = "memory"
	VaultTypeHashicorp = "hashicorp"
)

// Valid values for HashicorpConfig.AuthMethod.
const (
	VaultAuthToken   = "token"
	VaultAuthAppRole = "approle"
)

// Config holds the hilt service configuration.
type Config struct {
	Identity IdentityConfig `mapstructure:"identity"`
	Server   ServerConfig   `mapstructure:"server"`
	Log      LogConfig      `mapstructure:"log"`
	Storage  StorageConfig  `mapstructure:"storage"`
	Vault    VaultConfig    `mapstructure:"vault"`
	PLC      PLCConfig      `mapstructure:"plc"`
	Auth     AuthConfig     `mapstructure:"auth"`
	Upload   UploadConfig   `mapstructure:"upload"`
}

// UploadConfig holds settings for the Sprue upload service, which Hilt calls to
// provision a bucket's storage space.
type UploadConfig struct {
	// ServiceID is the Sprue service's DID (e.g. "did:web:sprue.example.com").
	ServiceID string `mapstructure:"service_id"`
	// ServiceURL is the Sprue service's HTTP endpoint.
	ServiceURL string `mapstructure:"service_url"`
	// ProductID is the Sprue product/plan DID that tenants are registered under
	// when Hilt provisions them (the /customer/add product argument).
	ProductID string `mapstructure:"product_id"`
	// Proofs is the UCAN delegation container the upload client presents to Sprue
	// — either an inline (codec-prefixed) encoded container or a path to a file
	// containing one. Empty means no proofs (only self-issued calls will work).
	Proofs string `mapstructure:"proofs"`
}

// IdentityConfig holds the Hilt service identity used to sign and receive UCAN
// invocations on the UCAN RPC API.
type IdentityConfig struct {
	// KeyFile is the path to a PEM-encoded Ed25519 private key. When empty, an
	// ephemeral key is generated at startup (its DID changes each restart).
	KeyFile string `mapstructure:"key_file"`
	// ServiceID is an optional did:web identity to wrap the key with, allowing
	// the service to accept UCANs addressed to the did:web (e.g.
	// "did:web:hilt.example.com"). When empty, the key's did:key is used.
	ServiceID string `mapstructure:"service_id"`
}

// ServerConfig holds HTTP server settings.
type ServerConfig struct {
	Host string `mapstructure:"host"`
	Port int    `mapstructure:"port"`
}

// AuthConfig holds authentication settings for the Tenant API.
type AuthConfig struct {
	// PartnerKey is the pre-shared bearer token required on Tenant API requests.
	// CSV of keys is supported, e.g. "key1,key2".
	PartnerKey string `mapstructure:"partner_key"`
}

// LogConfig holds logging settings.
type LogConfig struct {
	Level string `mapstructure:"level"`
}

// PLCConfig holds settings for the did:plc directory.
type PLCConfig struct {
	// Directory is the did:plc directory endpoint used to resolve and publish
	// PLC operations, e.g. "https://plc.directory".
	Directory string `mapstructure:"directory"`
}

// StorageConfig selects and configures the store backend.
type StorageConfig struct {
	// Type selects the backend: "memory" or "postgres". Defaults to "postgres".
	Type     string         `mapstructure:"type"`
	Postgres PostgresConfig `mapstructure:"postgres"`
}

// VaultConfig selects and configures the vault backend for private key material.
type VaultConfig struct {
	// Type selects the backend: "hashicorp" or "memory". Defaults to "hashicorp".
	Type      string          `mapstructure:"type"`
	Hashicorp HashicorpConfig `mapstructure:"hashicorp"`
}

// HashicorpConfig holds settings for the HashiCorp Vault backend.
type HashicorpConfig struct {
	// Address is the Vault server address, e.g. "http://127.0.0.1:8200".
	Address string `mapstructure:"address"`
	// Mount is the KV v2 secrets engine mount path. Defaults to "secret".
	Mount string `mapstructure:"mount"`
	// AuthMethod selects how to authenticate: "token" or "approle". Defaults to
	// "approle".
	AuthMethod string `mapstructure:"auth_method"`
	// Token is the Vault auth token (used when AuthMethod is "token").
	Token string `mapstructure:"token"`
	// AppRole holds the AppRole credentials (used when AuthMethod is "approle").
	AppRole AppRoleConfig `mapstructure:"approle"`
}

// AppRoleConfig holds HashiCorp Vault AppRole authentication credentials.
type AppRoleConfig struct {
	// RoleID is the AppRole role ID.
	RoleID string `mapstructure:"role_id"`
	// SecretID is the AppRole secret ID.
	SecretID string `mapstructure:"secret_id"`
	// Mount is the AppRole auth method mount path. Defaults to "approle".
	Mount string `mapstructure:"mount"`
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

	v.SetDefault("vault.type", VaultTypeHashicorp)
	v.SetDefault("vault.hashicorp.address", "http://127.0.0.1:8200")
	v.SetDefault("vault.hashicorp.mount", "secret")
	v.SetDefault("vault.hashicorp.auth_method", VaultAuthAppRole)
	v.SetDefault("vault.hashicorp.approle.mount", "approle")

	v.SetDefault("plc.directory", "https://plc.directory")

	v.SetDefault("upload.service_id", "did:web:upload.forgery.network")
	v.SetDefault("upload.service_url", "https://upload.forgery.network")
	v.SetDefault("upload.product_id", "did:web:hilt.forgery.network")
}

// flagBindings maps each config key to its serve-command flag name.
var flagBindings = map[string]string{
	"identity.key_file":                 "identity-key-file",
	"identity.service_id":               "identity-service-id",
	"server.host":                       "host",
	"server.port":                       "port",
	"storage.type":                      "storage",
	"storage.postgres.dsn":              "postgres-dsn",
	"storage.postgres.skip_migrations":  "skip-migrations",
	"vault.type":                        "vault",
	"vault.hashicorp.address":           "hashicorp-address",
	"vault.hashicorp.mount":             "hashicorp-mount",
	"vault.hashicorp.auth_method":       "hashicorp-auth-method",
	"vault.hashicorp.token":             "hashicorp-token",
	"vault.hashicorp.approle.role_id":   "hashicorp-approle-role-id",
	"vault.hashicorp.approle.secret_id": "hashicorp-approle-secret-id",
	"vault.hashicorp.approle.mount":     "hashicorp-approle-mount",
	"plc.directory":                     "plc-directory",
	"auth.partner_key":                  "partner-key",
	"upload.service_id":                 "upload-service-id",
	"upload.service_url":                "upload-service-url",
	"upload.product_id":                 "upload-product-id",
	"upload.proofs":                     "upload-proofs",
}

// BindEnvVars sets up environment variable binding with the HILT_ prefix. Each
// known config key is bound explicitly so env vars resolve on Unmarshal even when
// no flag or config file provides the key (viper's AutomaticEnv alone does not
// populate nested keys during Unmarshal) — this is what lets the `hilt client`
// commands pick up e.g. HILT_IDENTITY_KEY_FILE.
func BindEnvVars(v *viper.Viper) {
	v.SetEnvPrefix("HILT")
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	v.AutomaticEnv()
	for key := range flagBindings {
		// BindEnv derives the env name from the prefix + replacer (e.g.
		// identity.key_file → HILT_IDENTITY_KEY_FILE); it only errors on an empty key.
		_ = v.BindEnv(key)
	}
}

// BindFlags binds known server flags from the flag set to their config keys, so
// a flag set on the command line overrides env vars, the config file, and
// defaults. Flags that are absent from the set are skipped.
func BindFlags(v *viper.Viper, flags *pflag.FlagSet) error {
	for key, name := range flagBindings {
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
