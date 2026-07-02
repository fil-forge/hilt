package fx_test

import (
	"testing"

	"github.com/fil-forge/hilt/pkg/config"
	appfx "github.com/fil-forge/hilt/pkg/fx"
	"github.com/stretchr/testify/require"
)

func TestNewPLCClient(t *testing.T) {
	t.Run("valid endpoint", func(t *testing.T) {
		client, err := appfx.NewPLCClient(config.PLCConfig{Directory: "https://plc.directory"})
		require.NoError(t, err)
		require.NotNil(t, client)
	})

	t.Run("empty endpoint errors", func(t *testing.T) {
		_, err := appfx.NewPLCClient(config.PLCConfig{Directory: ""})
		require.Error(t, err)
	})

	t.Run("unparseable endpoint errors", func(t *testing.T) {
		_, err := appfx.NewPLCClient(config.PLCConfig{Directory: "://nope"})
		require.Error(t, err)
	})
}
