package fx_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/fil-forge/hilt/pkg/client/upload"
	"github.com/fil-forge/hilt/pkg/config"
	appfx "github.com/fil-forge/hilt/pkg/fx"
	"github.com/fil-forge/libforge/testutil"
	"github.com/fil-forge/ucantone/ucan/command"
	"github.com/fil-forge/ucantone/ucan/container"
	"github.com/fil-forge/ucantone/ucan/delegation"
	"github.com/stretchr/testify/require"
	"go.uber.org/fx"
	"go.uber.org/zap"
)

func TestNewUploadClient(t *testing.T) {
	id, err := appfx.NewIdentity(config.IdentityConfig{}, zap.NewNop())
	require.NoError(t, err)

	baseCfg := func(proofs string) config.UploadConfig {
		return config.UploadConfig{
			ServiceID:  testutil.RandomDID(t).String(),
			ServiceURL: "http://sprue.test",
			ProductID:  testutil.RandomDID(t).String(),
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

	missingCases := map[string]struct {
		unset       func(*config.UploadConfig)
		wantMessage string
	}{
		"service DID is unset": {
			unset:       func(c *config.UploadConfig) { c.ServiceID = "" },
			wantMessage: "upload.service_id is required: set HILT_UPLOAD_SERVICE_ID or --upload-service-id",
		},
		"service URL is unset": {
			unset:       func(c *config.UploadConfig) { c.ServiceURL = "" },
			wantMessage: "upload.service_url is required: set HILT_UPLOAD_SERVICE_URL or --upload-service-url",
		},
		"product DID is unset": {
			unset:       func(c *config.UploadConfig) { c.ProductID = "" },
			wantMessage: "upload.product_id is required: set HILT_UPLOAD_PRODUCT_ID or --upload-product-id",
		},
	}
	for desc, tc := range missingCases {
		t.Run("errors when "+desc, func(t *testing.T) {
			cfg := baseCfg("")
			tc.unset(&cfg)
			_, err := appfx.NewUploadClient(id, cfg, zap.NewNop())
			require.EqualError(t, err, tc.wantMessage)
		})
	}

	t.Run("invalid product DID errors", func(t *testing.T) {
		cfg := baseCfg("")
		cfg.ProductID = "not-a-did"
		_, err := appfx.NewUploadClient(id, cfg, zap.NewNop())
		require.ErrorContains(t, err, "upload.product_id")
	})

	t.Run("invalid proofs (neither container nor file) errors", func(t *testing.T) {
		_, err := appfx.NewUploadClient(id, baseCfg("not-a-container-and-not-a-file"), zap.NewNop())
		require.Error(t, err)
	})
}

// TestUploadClientRequiresConfig checks that an app built without the upload
// settings fails while it is being constructed, which is when `hilt serve`
// exits, rather than when it first calls Sprue.
func TestUploadClientRequiresConfig(t *testing.T) {
	app := fx.New(
		fx.Supply(&config.Config{}),
		appfx.ConfigModule,
		appfx.LoggerModule,
		appfx.IdentityModule,
		fx.Provide(appfx.NewUploadClient),
		fx.NopLogger,
		fx.Invoke(func(*upload.Client) {}),
	)
	require.ErrorContains(t, app.Err(), "upload.service_id is required")
}
