package client

import (
	"context"
	"fmt"
	"net/http"
	"net/url"

	"github.com/fil-forge/hilt/pkg/lib/zapucan"
	customercmds "github.com/fil-forge/libforge/commands/customer"
	providercmds "github.com/fil-forge/libforge/commands/provider"
	ucanlib "github.com/fil-forge/libforge/ucan"
	"github.com/fil-forge/ucantone/client"
	"github.com/fil-forge/ucantone/did"
	"github.com/fil-forge/ucantone/execution"
	"github.com/fil-forge/ucantone/ucan"
	"github.com/fil-forge/ucantone/ucan/invocation"
	"go.uber.org/zap"
)

type UploadClientOption func(*UploadClientConfig)

type UploadClientConfig struct {
	httpClient *http.Client
}

func WithHTTPClient(httpClient *http.Client) UploadClientOption {
	return func(cfg *UploadClientConfig) {
		cfg.httpClient = httpClient
	}
}

type UploadClient struct {
	ServiceID did.DID
	Proofs    ucanlib.ProofStore
	Executor  execution.Executor
	Logger    *zap.Logger
}

// NewUploadClient creates a new [UploadClient] for interacting with the upload
// service. The proofs parameter is used to provide proofs for UCAN invocations
// made by the client.
func NewUploadClient(serviceID did.DID, serviceURL url.URL, proofs ucanlib.ProofStore, logger *zap.Logger, opts ...UploadClientOption) (*UploadClient, error) {
	cfg := &UploadClientConfig{}
	for _, opt := range opts {
		opt(cfg)
	}

	var httpExecutor execution.Executor
	var err error
	if cfg.httpClient != nil {
		httpExecutor, err = client.NewHTTP(&serviceURL, client.WithHTTPClient(cfg.httpClient))
	} else {
		httpExecutor, err = client.NewHTTP(&serviceURL)
	}
	if err != nil {
		return nil, fmt.Errorf("creating HTTP executor: %w", err)
	}

	return &UploadClient{
		ServiceID: serviceID,
		Proofs:    proofs,
		Executor:  httpExecutor,
		Logger:    logger,
	}, nil
}

// RegisterCustomer registers a new customer with the upload service.
func (c *UploadClient) RegisterCustomer(ctx context.Context, issuer ucan.Issuer, id did.DID, product did.DID, details map[string]string) error {
	proofs, proofLinks, err := c.Proofs.ProofChain(ctx, issuer.DID(), customercmds.Add.Command, c.ServiceID)
	if err != nil {
		return fmt.Errorf("getting proof chain: %w", err)
	}
	inv, err := customercmds.Add.Invoke(
		issuer,
		c.ServiceID,
		&customercmds.AddArguments{
			Customer: id,
			Product:  product,
			Details:  details,
		},
		invocation.WithAudience(c.ServiceID),
		invocation.WithProofs(proofLinks...),
	)
	if err != nil {
		return fmt.Errorf("invoking register customer: %w", err)
	}
	log := zapucan.WithInvocation(c.Logger, inv)
	log.Debug("executing invocation")
	_, err = c.Executor.Execute(execution.NewRequest(ctx, inv, execution.WithDelegations(proofs...)))
	if err != nil {
		log.Error("failed to execute register customer invocation", zap.Error(err))
		return fmt.Errorf("executing register customer invocation: %w", err)
	}
	return nil
}

// ProvisionSpace provisions a new space with the upload service. It returns the
// ID of the subscription that was set up.
func (c *UploadClient) ProvisionSpace(ctx context.Context, account ucan.Issuer, space did.DID) (string, error) {
	inv, err := providercmds.Add.Invoke(
		account,
		account.DID(),
		&providercmds.AddArguments{
			Provider: c.ServiceID,
			Consumer: space,
		},
		invocation.WithAudience(c.ServiceID),
	)
	if err != nil {
		return "", fmt.Errorf("invoking provision space: %w", err)
	}
	log := zapucan.WithInvocation(c.Logger, inv)
	log.Debug("executing invocation")
	res, err := c.Executor.Execute(execution.NewRequest(ctx, inv))
	if err != nil {
		log.Error("failed to execute provision invocation", zap.Error(err))
		return "", fmt.Errorf("executing provision invocation: %w", err)
	}
	addOK, err := providercmds.Add.Unpack(res.Receipt())
	if err != nil {
		log.Error("failed to unpack provision result", zap.Error(err))
		return "", fmt.Errorf("unpacking provision result: %w", err)
	}
	return addOK.ID, nil
}
