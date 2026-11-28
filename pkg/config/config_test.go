package config_test

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/fil-forge/hilt/pkg/config"
	"github.com/stretchr/testify/require"
)

// TestLoadEnvOnly verifies environment variables populate nested config keys
// through Load with no flags and no config file — the `hilt client` commands rely
// on this (e.g. HILT_IDENTITY_KEY_FILE supplies the signing key). viper's
// AutomaticEnv alone does not bind nested keys on Unmarshal; BindEnvVars binds each
// known key explicitly.
func TestLoadEnvOnly(t *testing.T) {
	t.Setenv("HILT_IDENTITY_KEY_FILE", "/etc/hilt/svc.pem")
	t.Setenv("HILT_IDENTITY_SERVICE_ID", "did:web:hilt.example.com")
	t.Setenv("HILT_UPLOAD_SERVICE_URL", "https://upload.example.com")
	t.Setenv("HILT_REVOCATION_SERVICE_URL", "https://revocation.example.com")

	cfg, err := config.Load("")
	require.NoError(t, err)
	require.Equal(t, "/etc/hilt/svc.pem", cfg.Identity.KeyFile)
	require.Equal(t, "did:web:hilt.example.com", cfg.Identity.ServiceID)
	require.Equal(t, "https://upload.example.com", cfg.Upload.ServiceURL)
	require.Equal(t, "https://revocation.example.com", cfg.Revocation.ServiceURL)
}

// TestLoadUploadHasNoDefault verifies the upload service settings stay empty
// when nothing configures them, so `hilt serve` refuses to start instead of
// provisioning tenants and buckets on another stage's Sprue.
func TestLoadUploadHasNoDefault(t *testing.T) {
	t.Setenv("HILT_UPLOAD_SERVICE_ID", "")
	t.Setenv("HILT_UPLOAD_SERVICE_URL", "")
	t.Setenv("HILT_UPLOAD_PRODUCT_ID", "")
	t.Setenv("HILT_UPLOAD_PROOFS", "")

	cfg, err := config.Load("")
	require.NoError(t, err)
	require.Equal(t, config.UploadConfig{}, cfg.Upload)
}

// TestLoadRevocationHasNoDefault verifies the revocation service settings stay
// empty when nothing configures them, so `hilt serve` refuses to start instead
// of publishing revocations to another stage's Swarf.
func TestLoadRevocationHasNoDefault(t *testing.T) {
	t.Setenv("HILT_REVOCATION_SERVICE_ID", "")
	t.Setenv("HILT_REVOCATION_SERVICE_URL", "")

	cfg, err := config.Load("")
	require.NoError(t, err)
	require.Equal(t, config.RevocationConfig{}, cfg.Revocation)
}

// TestLoadGrantTiming verifies the grant timing defaults, and that a config
// file, as an integration test mounts one, sets them as durations.
func TestLoadGrantTiming(t *testing.T) {
	cfg, err := config.Load("")
	require.NoError(t, err)
	require.Equal(t, config.GrantsConfig{Lifetime: 168 * time.Hour, RenewBefore: 72 * time.Hour, RenewalInterval: time.Hour}, cfg.Grants)

	path := filepath.Join(t.TempDir(), "config.yaml")
	require.NoError(t, os.WriteFile(path, []byte("grants:\n  lifetime: 90s\n  renew_before: 45s\n  renewal_interval: 5s\n"), 0o600))
	cfg, err = config.Load(path)
	require.NoError(t, err)
	require.Equal(t, config.GrantsConfig{Lifetime: 90 * time.Second, RenewBefore: 45 * time.Second, RenewalInterval: 5 * time.Second}, cfg.Grants)
}
