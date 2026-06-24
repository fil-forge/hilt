// Package config loads hilt service configuration from a config file,
// environment variables (HILT_ prefix), and built-in defaults.
package config

import (
	"fmt"
	"strings"

	"github.com/spf13/pflag"
	"github.com/spf13/viper"
)

// Config holds the hilt service configuration.
type Config struct {
	Server ServerConfig `mapstructure:"server"`
	Log    LogConfig    `mapstructure:"log"`
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

// SetDefaults configures default values for viper.
func SetDefaults(v *viper.Viper) {
	v.SetDefault("server.host", "0.0.0.0")
	v.SetDefault("server.port", 8080)
	v.SetDefault("log.level", "info")
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
		"server.host": "host",
		"server.port": "port",
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
		// Ignore error if no config file found - use defaults and env vars
		_ = v.ReadInConfig()
	}

	var cfg Config
	if err := v.Unmarshal(&cfg); err != nil {
		return nil, nil, fmt.Errorf("unmarshaling config: %w", err)
	}

	return &cfg, v, nil
}
