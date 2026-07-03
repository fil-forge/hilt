package fx_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/fil-forge/hilt/pkg/config"
	appfx "github.com/fil-forge/hilt/pkg/fx"
	"github.com/fil-forge/libforge/testutil"
	"github.com/fil-forge/ucantone/ucan/command"
	"github.com/fil-forge/ucantone/ucan/container"
	"github.com/fil-forge/ucantone/ucan/delegation"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

func TestNewUploadClient(t *testing.T) {
	id, err := appfx.NewIdentity(config.IdentityConfig{}, zap.NewNop())
	require.NoError(t, err)

	baseCfg := func(proofs string) config.UploadConfig {
		return config.UploadConfig{
			ServiceID:  testutil.RandomDID(t).String(),
			ServiceURL: "http://sprue.test",
			Proofs:     proofs,
		}
	}

	// A container holding one root delegation (subject == issuer), and its
	// codec-prefixed encoding.
	svc := testutil.RandomIssuer(t)
	alice := testutil.RandomDID(t)
	cmd := command.MustParse("/test/run")
	dlg, err := delegation.Delegate(svc, alice, svc.DID(), cmd)
	require.NoError(t, err)
	encoded, err := container.Encode(container.Base64url, container.New(container.WithDelegations(dlg)))
	require.NoError(t, err)

	t.Run("inline encoded container", func(t *testing.T) {
		c, err := appfx.NewUploadClient(id, baseCfg(string(encoded)), zap.NewNop())
		require.NoError(t, err)
		require.NotNil(t, c)

		// The proof store was built from the config value.
		proofs, links, err := c.Proofs.ProofChain(t.Context(), alice, cmd, svc.DID())
		require.NoError(t, err)
		require.Len(t, proofs, 1)
		require.Len(t, links, 1)
	})

	t.Run("path to a container file", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "proofs")
		require.NoError(t, os.WriteFile(path, encoded, 0o600))

		c, err := appfx.NewUploadClient(id, baseCfg(path), zap.NewNop())
		require.NoError(t, err)
		proofs, _, err := c.Proofs.ProofChain(t.Context(), alice, cmd, svc.DID())
		require.NoError(t, err)
		require.Len(t, proofs, 1)
	})

	t.Run("empty proofs yields an empty store", func(t *testing.T) {
		c, err := appfx.NewUploadClient(id, baseCfg(""), zap.NewNop())
		require.NoError(t, err)
		require.NotNil(t, c)
	})

	t.Run("invalid proofs (neither container nor file) errors", func(t *testing.T) {
		_, err := appfx.NewUploadClient(id, baseCfg("not-a-container-and-not-a-file"), zap.NewNop())
		require.Error(t, err)
	})
}
