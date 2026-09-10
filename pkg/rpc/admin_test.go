package rpc_test

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/fil-forge/hilt/pkg/client/upload"
	adminprovider "github.com/fil-forge/hilt/pkg/commands/admin/provider"
	adminnodes "github.com/fil-forge/hilt/pkg/commands/admin/provider/nodes"
	"github.com/fil-forge/hilt/pkg/rpc"
	"github.com/fil-forge/hilt/pkg/store"
	delegationmemory "github.com/fil-forge/hilt/pkg/store/delegation/memory"
	providermemory "github.com/fil-forge/hilt/pkg/store/provider/memory"
	routingcmds "github.com/fil-forge/libforge/commands/routing"
	"github.com/fil-forge/libforge/testutil"
	"github.com/fil-forge/ucantone/did"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

// fakeRouting is a stub of the upload service's routing policy put, recording the
// policy and candidates it was asked to store.
type fakeRouting struct {
	err        error
	called     bool
	policy     did.DID
	candidates []did.DID
}

func (f *fakeRouting) PutRoutingPolicy(_ context.Context, policy did.DID, candidates []did.DID, _ ...upload.MethodOption) error {
	f.called = true
	f.policy = policy
	f.candidates = candidates
	return f.err
}

func TestAddProvider(t *testing.T) {
	ctx := t.Context()
	serviceID := testutil.RandomDID(t)
	providerID := testutil.RandomDID(t)
	nodes := []did.DID{testutil.RandomDID(t), testutil.RandomDID(t)}

	t.Run("the service identity registers a provider and its routing policy", func(t *testing.T) {
		providers, delegations, routing := providermemory.New(), delegationmemory.New(), &fakeRouting{}
		ok, err := rpc.AddProvider(ctx, zap.NewNop(), serviceID, providers, delegations, routing, serviceID,
			&adminprovider.AddArguments{Provider: providerID, Region: "us-east-1", Nodes: nodes})
		require.NoError(t, err)
		require.NotNil(t, ok)

		rec, err := providers.GetByRegion(ctx, "us-east-1")
		require.NoError(t, err)
		require.Equal(t, providerID, rec.ID)
		require.NotNil(t, rec.Policy)

		// The nodes were put as the candidates of the record's policy.
		require.True(t, routing.called)
		require.Equal(t, *rec.Policy, routing.policy)
		require.Equal(t, nodes, routing.candidates)

		// The policy root (iss == sub == policy, aud == service, no expiry) proves
		// the service's authority to put the policy.
		proofs, links, err := delegations.ProofChain(ctx, serviceID, routingcmds.Put.Command, *rec.Policy)
		require.NoError(t, err)
		require.Len(t, proofs, 1)
		require.Len(t, links, 1)
		root := proofs[0]
		require.Equal(t, *rec.Policy, root.Issuer())
		require.Equal(t, *rec.Policy, root.Subject())
		require.Equal(t, serviceID, root.Audience())
		require.Nil(t, root.Expiration())
	})

	t.Run("rejects an issuer that is not the service", func(t *testing.T) {
		providers, routing := providermemory.New(), &fakeRouting{}
		_, err := rpc.AddProvider(ctx, zap.NewNop(), serviceID, providers, delegationmemory.New(), routing, testutil.RandomDID(t),
			&adminprovider.AddArguments{Provider: providerID, Region: "us-east-1", Nodes: nodes})
		require.ErrorIs(t, err, rpc.ErrUnauthorized)
		require.False(t, routing.called)

		// nothing was stored
		_, err = providers.GetByRegion(ctx, "us-east-1")
		require.ErrorIs(t, err, store.ErrRecordNotFound)
	})

	t.Run("registers a provider without nodes and without a policy", func(t *testing.T) {
		providers, routing := providermemory.New(), &fakeRouting{}
		ok, err := rpc.AddProvider(ctx, zap.NewNop(), serviceID, providers, delegationmemory.New(), routing, serviceID,
			&adminprovider.AddArguments{Provider: providerID, Region: "us-east-1"})
		require.NoError(t, err)
		require.NotNil(t, ok)
		require.False(t, routing.called)

		rec, err := providers.GetByRegion(ctx, "us-east-1")
		require.NoError(t, err)
		require.Nil(t, rec.Policy)
	})

	t.Run("stores no provider when the upload service rejects the policy", func(t *testing.T) {
		providers := providermemory.New()
		routing := &fakeRouting{err: errors.New("sprue unavailable")}
		_, err := rpc.AddProvider(ctx, zap.NewNop(), serviceID, providers, delegationmemory.New(), routing, serviceID,
			&adminprovider.AddArguments{Provider: providerID, Region: "us-east-1", Nodes: nodes})
		require.Error(t, err)
		_, err = providers.GetByRegion(ctx, "us-east-1")
		require.ErrorIs(t, err, store.ErrRecordNotFound)
	})

	t.Run("rejects a duplicate provider or region", func(t *testing.T) {
		providers := providermemory.New()
		routing := &fakeRouting{}
		require.NoError(t, providers.Add(ctx, providerID, "us-east-1", nil))
		_, err := rpc.AddProvider(ctx, zap.NewNop(), serviceID, providers, delegationmemory.New(), routing, serviceID,
			&adminprovider.AddArguments{Provider: testutil.RandomDID(t), Region: "us-east-1", Nodes: nodes})
		require.ErrorIs(t, err, rpc.ErrProviderExists)
		require.False(t, routing.called)
	})

	t.Run("rejects invalid provider arguments before issuing policy material", func(t *testing.T) {
		for name, args := range map[string]*adminprovider.AddArguments{
			"missing provider": {Region: "us-east-1", Nodes: nodes},
			"missing region":   {Provider: providerID, Nodes: nodes},
		} {
			t.Run(name, func(t *testing.T) {
				routing := &fakeRouting{}
				_, err := rpc.AddProvider(ctx, zap.NewNop(), serviceID, providermemory.New(), delegationmemory.New(), routing, serviceID, args)
				require.ErrorIs(t, err, store.ErrInvalidArgument)
				require.False(t, routing.called)
			})
		}
	})
}

func TestSetProviderNodes(t *testing.T) {
	ctx := t.Context()
	serviceID := testutil.RandomDID(t)
	providerID := testutil.RandomDID(t)
	policy := testutil.RandomDID(t)
	nodes := []did.DID{testutil.RandomDID(t)}

	t.Run("puts the nodes as the provider's policy candidates", func(t *testing.T) {
		providers, routing := providermemory.New(), &fakeRouting{}
		require.NoError(t, providers.Add(ctx, providerID, "us-east-1", &policy))
		ok, err := rpc.SetProviderNodes(ctx, zap.NewNop(), serviceID, providers, delegationmemory.New(), routing, serviceID,
			&adminnodes.SetArguments{Provider: providerID, Nodes: nodes})
		require.NoError(t, err)
		require.NotNil(t, ok)
		require.True(t, routing.called)
		require.Equal(t, policy, routing.policy)
		require.Equal(t, nodes, routing.candidates)
	})

	t.Run("issues a policy for a provider that has none", func(t *testing.T) {
		providers, delegations, routing := providermemory.New(), delegationmemory.New(), &fakeRouting{}
		require.NoError(t, providers.Add(ctx, providerID, "us-east-1", nil))
		ok, err := rpc.SetProviderNodes(ctx, zap.NewNop(), serviceID, providers, delegations, routing, serviceID,
			&adminnodes.SetArguments{Provider: providerID, Nodes: nodes})
		require.NoError(t, err)
		require.NotNil(t, ok)

		rec, err := providers.Get(ctx, providerID)
		require.NoError(t, err)
		require.NotNil(t, rec.Policy)
		require.True(t, routing.called)
		require.Equal(t, *rec.Policy, routing.policy)
		require.Equal(t, nodes, routing.candidates)

		proofs, _, err := delegations.ProofChain(ctx, serviceID, routingcmds.Put.Command, *rec.Policy)
		require.NoError(t, err)
		require.Len(t, proofs, 1)
		require.Equal(t, *rec.Policy, proofs[0].Subject())
	})

	t.Run("records no policy when the upload service rejects the put", func(t *testing.T) {
		providers := providermemory.New()
		require.NoError(t, providers.Add(ctx, providerID, "us-east-1", nil))
		_, err := rpc.SetProviderNodes(ctx, zap.NewNop(), serviceID, providers, delegationmemory.New(), &fakeRouting{err: errors.New("sprue unavailable")}, serviceID,
			&adminnodes.SetArguments{Provider: providerID, Nodes: nodes})
		require.Error(t, err)

		rec, err := providers.Get(ctx, providerID)
		require.NoError(t, err)
		require.Nil(t, rec.Policy)
	})

	t.Run("rejects an issuer that is not the service", func(t *testing.T) {
		routing := &fakeRouting{}
		_, err := rpc.SetProviderNodes(ctx, zap.NewNop(), serviceID, providermemory.New(), delegationmemory.New(), routing, testutil.RandomDID(t),
			&adminnodes.SetArguments{Provider: providerID, Nodes: nodes})
		require.ErrorIs(t, err, rpc.ErrUnauthorized)
		require.False(t, routing.called)
	})

	t.Run("rejects an empty node set", func(t *testing.T) {
		providers, routing := providermemory.New(), &fakeRouting{}
		require.NoError(t, providers.Add(ctx, providerID, "us-east-1", &policy))
		_, err := rpc.SetProviderNodes(ctx, zap.NewNop(), serviceID, providers, delegationmemory.New(), routing, serviceID,
			&adminnodes.SetArguments{Provider: providerID})
		require.ErrorIs(t, err, rpc.ErrInvalidNodes)
		require.False(t, routing.called)
	})

	t.Run("rejects an unknown provider", func(t *testing.T) {
		routing := &fakeRouting{}
		_, err := rpc.SetProviderNodes(ctx, zap.NewNop(), serviceID, providermemory.New(), delegationmemory.New(), routing, serviceID,
			&adminnodes.SetArguments{Provider: providerID, Nodes: nodes})
		require.ErrorIs(t, err, rpc.ErrProviderNotFound)
		require.False(t, routing.called)
	})
}

func TestListProviders(t *testing.T) {
	ctx := t.Context()
	serviceID := testutil.RandomDID(t)

	t.Run("reports an empty list when no provider is registered", func(t *testing.T) {
		ok, err := rpc.ListProviders(ctx, zap.NewNop(), serviceID, providermemory.New(), serviceID, &adminprovider.ListArguments{})
		require.NoError(t, err)
		require.NotNil(t, ok.Providers)
		require.Empty(t, ok.Providers)
	})

	t.Run("reports every provider with its region and policy, ordered by DID", func(t *testing.T) {
		providers := providermemory.New()
		ids := []did.DID{testutil.RandomDID(t), testutil.RandomDID(t), testutil.RandomDID(t)}
		slices.SortFunc(ids, func(a, b did.DID) int { return strings.Compare(a.String(), b.String()) })
		policy := testutil.RandomDID(t)
		// Added in reverse so the order comes from the list, not from insertion.
		require.NoError(t, providers.Add(ctx, ids[2], "eu-west-1", nil))
		require.NoError(t, providers.Add(ctx, ids[1], "us-east-1", &policy))
		require.NoError(t, providers.Add(ctx, ids[0], "ap-south-1", nil))

		ok, err := rpc.ListProviders(ctx, zap.NewNop(), serviceID, providers, serviceID, &adminprovider.ListArguments{})
		require.NoError(t, err)
		require.Equal(t, []adminprovider.Provider{
			{Provider: ids[0], Region: "ap-south-1"},
			{Provider: ids[1], Region: "us-east-1", Policy: &policy},
			{Provider: ids[2], Region: "eu-west-1"},
		}, ok.Providers)
	})

	t.Run("rejects an issuer that is not the service", func(t *testing.T) {
		_, err := rpc.ListProviders(ctx, zap.NewNop(), serviceID, providermemory.New(), testutil.RandomDID(t), &adminprovider.ListArguments{})
		require.ErrorIs(t, err, rpc.ErrUnauthorized)
	})
}
