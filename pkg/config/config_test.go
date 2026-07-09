package config_test

import (
	"testing"

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

	cfg, err := config.Load("")
	require.NoError(t, err)
	require.Equal(t, "/etc/hilt/svc.pem", cfg.Identity.KeyFile)
	require.Equal(t, "did:web:hilt.example.com", cfg.Identity.ServiceID)
	require.Equal(t, "https://upload.example.com", cfg.Upload.ServiceURL)
}
