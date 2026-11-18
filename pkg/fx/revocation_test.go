package fx_test

import (
	"testing"

	"github.com/fil-forge/hilt/pkg/config"
	appfx "github.com/fil-forge/hilt/pkg/fx"
	"github.com/fil-forge/hilt/pkg/grant"
	"github.com/fil-forge/libforge/testutil"
	"github.com/stretchr/testify/require"
	"go.uber.org/fx"
)

func TestNewRevocationClient(t *testing.T) {
	serviceID := testutil.RandomDID(t)

	t.Run("builds a client", func(t *testing.T) {
		c, err := appfx.NewRevocationClient(config.RevocationConfig{
			ServiceID:  serviceID.String(),
			ServiceURL: "http://swarf.test",
		})
		require.NoError(t, err)
		require.Equal(t, serviceID, c.ServiceID)
	})

	missingCases := map[string]struct {
		cfg         config.RevocationConfig
		wantMessage string
	}{
		"service DID is unset": {
			cfg:         config.RevocationConfig{ServiceURL: "http://swarf.test"},
			wantMessage: "revocation.service_id is required: set HILT_REVOCATION_SERVICE_ID or --revocation-service-id",
		},
		"service URL is unset": {
			cfg:         config.RevocationConfig{ServiceID: serviceID.String()},
			wantMessage: "revocation.service_url is required: set HILT_REVOCATION_SERVICE_URL or --revocation-service-url",
		},
	}
	for desc, tc := range missingCases {
		t.Run("errors when "+desc, func(t *testing.T) {
			_, err := appfx.NewRevocationClient(tc.cfg)
			require.EqualError(t, err, tc.wantMessage)
		})
	}

	t.Run("invalid service DID errors", func(t *testing.T) {
		_, err := appfx.NewRevocationClient(config.RevocationConfig{
			ServiceID:  "not-a-did",
			ServiceURL: "http://swarf.test",
		})
		require.ErrorContains(t, err, "revocation.service_id")
	})

	t.Run("invalid service URL errors", func(t *testing.T) {
		_, err := appfx.NewRevocationClient(config.RevocationConfig{
			ServiceID:  serviceID.String(),
			ServiceURL: "http://[::1",
		})
		require.ErrorContains(t, err, "revocation.service_url")
	})
}

// TestRevocationModuleRequiresConfig checks that an app built without the
// revocation settings fails while it is being constructed, which is when
// `hilt serve` exits, rather than when it first publishes a revocation.
func TestRevocationModuleRequiresConfig(t *testing.T) {
	app := fx.New(
		fx.Supply(&config.Config{}),
		appfx.ConfigModule,
		appfx.RevocationModule,
		fx.NopLogger,
		fx.Invoke(func(grant.RevocationPublisher) {}),
	)
	require.ErrorContains(t, app.Err(), "revocation.service_id is required")
}
