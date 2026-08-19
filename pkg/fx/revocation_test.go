package fx_test

import (
	"testing"

	"github.com/fil-forge/hilt/pkg/config"
	appfx "github.com/fil-forge/hilt/pkg/fx"
	"github.com/fil-forge/libforge/testutil"
	"github.com/stretchr/testify/require"
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
