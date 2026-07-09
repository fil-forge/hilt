package client

import (
	"context"
	"fmt"
	"net/url"

	adminprovider "github.com/fil-forge/hilt/pkg/commands/admin/provider"
	"github.com/fil-forge/hilt/pkg/lib/zapucan"
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

// AddProvider invokes /admin/provider/add to register a regional provider. No
// proofs are attached: the subject is the service itself, so authority is implicit
// in the issuer being the service identity.
func (c *AdminClient) AddProvider(ctx context.Context, providerID did.DID, region string) error {
	serviceID := c.Issuer.DID()
	inv, err := adminprovider.Add.Invoke(c.Issuer, serviceID,
		&adminprovider.AddArguments{Provider: providerID, Region: region},
		invocation.WithAudience(serviceID),
	)
	if err != nil {
		return fmt.Errorf("invoking %s: %w", adminprovider.Add.Command, err)
	}
	log := zapucan.WithInvocation(c.Logger, inv)
	log.Debug("executing invocation")
	res, err := c.Executor.Execute(execution.NewRequest(ctx, inv))
	if err != nil {
		log.Error("failed to execute invocation", zap.Error(err))
		return fmt.Errorf("executing %s invocation: %w", adminprovider.Add.Command, err)
	}
	if _, err := adminprovider.Add.Unpack(res.Receipt()); err != nil {
		return fmt.Errorf("adding provider: %w", err)
	}
	return nil
}
