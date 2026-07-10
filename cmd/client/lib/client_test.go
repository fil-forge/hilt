package lib

import (
	"testing"

	"github.com/fil-forge/hilt/pkg/config"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/require"
)

// newCmdWithURL returns a command with the inherited --url persistent flag the
// `hilt client` tree provides, optionally set.
func newCmdWithURL(t *testing.T, url string) *cobra.Command {
	t.Helper()
	parent := &cobra.Command{Use: "client"}
	parent.PersistentFlags().String("url", "", "")
	child := &cobra.Command{Use: "child"}
	parent.AddCommand(child)
	if url != "" {
		require.NoError(t, parent.PersistentFlags().Set("url", url))
	}
	return child
}

func TestResolvePartnerKey(t *testing.T) {
	t.Run("config key wins over env var", func(t *testing.T) {
		t.Setenv(partnerKeyEnvVar, "env-key")
		cfg := &config.Config{Auth: config.AuthConfig{PartnerKey: "config-key"}}
		require.Equal(t, "config-key", resolvePartnerKey(cfg))
	})

	t.Run("first entry of a CSV key is used", func(t *testing.T) {
		cfg := &config.Config{Auth: config.AuthConfig{PartnerKey: " key-a , key-b"}}
		require.Equal(t, "key-a", resolvePartnerKey(cfg))
	})

	t.Run("empty config key falls back to env var", func(t *testing.T) {
		t.Setenv(partnerKeyEnvVar, "env-key")
		require.Equal(t, "env-key", resolvePartnerKey(&config.Config{}))
	})

	t.Run("nil config falls back to env var", func(t *testing.T) {
		t.Setenv(partnerKeyEnvVar, "env-key")
		require.Equal(t, "env-key", resolvePartnerKey(nil))
	})

	t.Run("empty when neither config nor env var is set", func(t *testing.T) {
		t.Setenv(partnerKeyEnvVar, "")
		require.Empty(t, resolvePartnerKey(nil))
	})
}

func TestServerURLWithoutConfig(t *testing.T) {
	t.Run("explicit --url works without config", func(t *testing.T) {
		for _, raw := range []string{"127.0.0.1:8080", "localhost:8080"} {
			u, err := serverURL(newCmdWithURL(t, raw), nil)
			require.NoError(t, err, "--url %q", raw)
			require.Equal(t, "http", u.Scheme, "--url %q", raw)
			require.Equal(t, raw, u.Host, "--url %q", raw)
		}
	})

	t.Run("explicit scheme is preserved", func(t *testing.T) {
		u, err := serverURL(newCmdWithURL(t, "https://hilt.example.com"), nil)
		require.NoError(t, err)
		require.Equal(t, "https", u.Scheme)
		require.Equal(t, "hilt.example.com", u.Host)
	})

	t.Run("missing --url without config is an error", func(t *testing.T) {
		_, err := serverURL(newCmdWithURL(t, ""), nil)
		require.ErrorContains(t, err, "--url is required")
	})
}
