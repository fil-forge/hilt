package rpc_test

import (
	"testing"

	adminprovider "github.com/fil-forge/hilt/pkg/commands/admin/provider"
	"github.com/fil-forge/hilt/pkg/rpc"
	"github.com/fil-forge/hilt/pkg/store"
	providermemory "github.com/fil-forge/hilt/pkg/store/provider/memory"
	"github.com/fil-forge/libforge/testutil"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

func TestAddProvider(t *testing.T) {
	ctx := t.Context()
	serviceID := testutil.RandomDID(t)
	providerID := testutil.RandomDID(t)

	t.Run("the service identity registers a provider", func(t *testing.T) {
		providers := providermemory.New()
		ok, err := rpc.AddProvider(ctx, zap.NewNop(), serviceID, providers, serviceID,
			&adminprovider.AddArguments{Provider: providerID, Region: "us-east-1"})
		require.NoError(t, err)
		require.NotNil(t, ok)

		rec, err := providers.GetByRegion(ctx, "us-east-1")
		require.NoError(t, err)
		require.Equal(t, providerID, rec.ID)
	})

	t.Run("rejects an issuer that is not the service", func(t *testing.T) {
		providers := providermemory.New()
		_, err := rpc.AddProvider(ctx, zap.NewNop(), serviceID, providers, testutil.RandomDID(t),
			&adminprovider.AddArguments{Provider: providerID, Region: "us-east-1"})
		require.ErrorIs(t, err, rpc.ErrUnauthorized)

		// nothing was stored
		_, err = providers.GetByRegion(ctx, "us-east-1")
		require.ErrorIs(t, err, store.ErrRecordNotFound)
	})

	t.Run("rejects a duplicate provider or region", func(t *testing.T) {
		providers := providermemory.New()
		require.NoError(t, providers.Add(ctx, providerID, "us-east-1"))
		_, err := rpc.AddProvider(ctx, zap.NewNop(), serviceID, providers, serviceID,
			&adminprovider.AddArguments{Provider: testutil.RandomDID(t), Region: "us-east-1"})
		require.ErrorIs(t, err, rpc.ErrProviderExists)
	})
}
