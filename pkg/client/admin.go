package client

import (
	"context"
	"fmt"
	"net/url"

	adminprovider "github.com/fil-forge/hilt/pkg/commands/admin/provider"
	adminnodes "github.com/fil-forge/hilt/pkg/commands/admin/provider/nodes"
	"github.com/fil-forge/hilt/pkg/lib/zapucan"
	"github.com/fil-forge/ucantone/binding"
	"github.com/fil-forge/ucantone/client"
	"github.com/fil-forge/ucantone/did"
	"github.com/fil-forge/ucantone/execution"
	"github.com/fil-forge/ucantone/ucan"
	"github.com/fil-forge/ucantone/ucan/invocation"
	"go.uber.org/zap"
)

// AdminClient invokes Hilt's /admin/* UCAN RPC commands. These are self-issued:
// the issuer must be Hilt's own service identity and the subject is the service
// itself, so no delegation proofs are attached. Construct it with [NewAdminClient],
// passing the service identity as the issuer.
type AdminClient struct {
	Issuer   ucan.Issuer
	Executor execution.Executor
	Logger   *zap.Logger
}

// NewAdminClient creates an admin client for Hilt's UCAN RPC API at serviceURL.
// issuer is the service identity: admin commands are self-issued, so its DID is
// the invocation issuer, subject and audience.
func NewAdminClient(issuer ucan.Issuer, serviceURL url.URL, logger *zap.Logger) (*AdminClient, error) {
	if issuer == nil {
		return nil, fmt.Errorf("issuer is required")
	}
	if logger == nil {
		logger = zap.NewNop()
	}
	executor, err := client.NewHTTP(&serviceURL)
	if err != nil {
		return nil, fmt.Errorf("creating HTTP executor: %w", err)
	}
	return &AdminClient{Issuer: issuer, Executor: executor, Logger: logger}, nil
}

// AddProvider invokes /admin/provider/add to register a regional provider and the
// storage nodes it operates. No proofs are attached: the subject is the service
// itself, so authority is implicit in the issuer being the service identity.
func (c *AdminClient) AddProvider(ctx context.Context, providerID did.DID, region string, nodes []did.DID) error {
	_, err := invokeAdmin(ctx, c, adminprovider.Add, &adminprovider.AddArguments{Provider: providerID, Region: region, Nodes: nodes})
	if err != nil {
		return fmt.Errorf("adding provider: %w", err)
	}
	return nil
}

// SetProviderNodes invokes /admin/provider/nodes/set to replace the storage nodes
// a registered provider operates.
func (c *AdminClient) SetProviderNodes(ctx context.Context, providerID did.DID, nodes []did.DID) error {
	_, err := invokeAdmin(ctx, c, adminnodes.Set, &adminnodes.SetArguments{Provider: providerID, Nodes: nodes})
	if err != nil {
		return fmt.Errorf("setting provider nodes: %w", err)
	}
	return nil
}

// ListProviders invokes /admin/provider/list and returns every registered
// regional provider with its region and routing policy, ordered by provider DID.
func (c *AdminClient) ListProviders(ctx context.Context) (*adminprovider.ListOK, error) {
	ok, err := invokeAdmin(ctx, c, adminprovider.List, &adminprovider.ListArguments{})
	if err != nil {
		return nil, fmt.Errorf("listing providers: %w", err)
	}
	return ok, nil
}

// invokeAdmin issues a self-issued admin invocation (issuer, subject and audience
// are all the service identity, with no proofs), executes it and unpacks the
// typed result.
func invokeAdmin[A, O binding.CBORValue](ctx context.Context, c *AdminClient, cmd binding.Binding[A, O], args A) (O, error) {
	var zero O
	serviceID := c.Issuer.DID()
	inv, err := cmd.Invoke(c.Issuer, serviceID, args, invocation.WithAudience(serviceID))
	if err != nil {
		return zero, fmt.Errorf("invoking %s: %w", cmd.Command, err)
	}
	log := zapucan.WithInvocation(c.Logger, inv)
	log.Debug("executing invocation")
	res, err := c.Executor.Execute(execution.NewRequest(ctx, inv))
	if err != nil {
		log.Error("failed to execute invocation", zap.Error(err))
		return zero, fmt.Errorf("executing %s invocation: %w", cmd.Command, err)
	}
	ok, err := cmd.Unpack(res.Receipt())
	if err != nil {
		return zero, err
	}
	return ok, nil
}
