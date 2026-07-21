package upload

import (
	"context"
	"fmt"
	"net/http"
	"net/url"

	"github.com/fil-forge/hilt/pkg/lib/zapucan"
	blobcmds "github.com/fil-forge/libforge/commands/blob"
	customercmds "github.com/fil-forge/libforge/commands/customer"
	providercmds "github.com/fil-forge/libforge/commands/provider"
	ucanlib "github.com/fil-forge/libforge/ucan"
	"github.com/fil-forge/ucantone/client"
	"github.com/fil-forge/ucantone/did"
	"github.com/fil-forge/ucantone/execution"
	"github.com/fil-forge/ucantone/ucan"
	"github.com/fil-forge/ucantone/ucan/container"
	"github.com/fil-forge/ucantone/ucan/invocation"
	"go.uber.org/zap"
)

type Option func(*clientConfig)

type clientConfig struct {
	httpClient *http.Client
	logger     *zap.Logger
	product    did.DID
	proofs     ucanlib.ProofStore
}

func WithHTTPClient(httpClient *http.Client) Option {
	return func(cfg *clientConfig) {
		cfg.httpClient = httpClient
	}
}

// WithProduct sets the default product/plan DID used when registering customers
// (see [Client.RegisterCustomer]).
func WithProduct(product did.DID) Option {
	return func(cfg *clientConfig) {
		cfg.product = product
	}
}

func WithLogger(logger *zap.Logger) Option {
	return func(cfg *clientConfig) {
		if logger != nil {
			cfg.logger = logger
		}
	}
}

// WithBaseProofs sets the default proof store used when invoking methods on the
// upload service. Individual method calls may override this with [WithProofs].
func WithBaseProofs(proofs ucanlib.ProofStore) Option {
	return func(cfg *clientConfig) {
		if proofs != nil {
			cfg.proofs = proofs
		}
	}
}

type MethodOption func(*methodConfig)

type methodConfig struct {
	issuer ucan.Issuer
	proofs ucanlib.ProofStore
}

func WithIssuer(iss ucan.Issuer) MethodOption {
	return func(cfg *methodConfig) {
		if iss != nil {
			cfg.issuer = iss
		}
	}
}

func WithProofs(proofs ucanlib.ProofStore) MethodOption {
	return func(cfg *methodConfig) {
		if proofs != nil {
			cfg.proofs = proofs
		}
	}
}

type Client struct {
	ServiceID did.DID
	Issuer    ucan.Issuer
	Proofs    ucanlib.ProofStore
	Product   did.DID
	Executor  execution.Executor
	Logger    *zap.Logger
}

// NewClient creates a new [Client] for interacting with the upload
// service. The issuer and proofs parameters are used as the issuer and
// proof set if none are provided as individual method options.
func NewClient(serviceID did.DID, serviceURL url.URL, issuer ucan.Issuer, opts ...Option) (*Client, error) {
	cfg := &clientConfig{
		logger: zap.NewNop(),
	}
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

	if issuer == nil {
		return nil, fmt.Errorf("issuer is required")
	}
	proofs := cfg.proofs
	if proofs == nil {
		proofs = ucanlib.NewContainerProofStore(container.New())
	}

	return &Client{
		ServiceID: serviceID,
		Issuer:    issuer,
		Proofs:    proofs,
		Product:   cfg.product,
		Executor:  httpExecutor,
		Logger:    cfg.logger,
	}, nil
}

// RegisterCustomer registers a new customer with the upload service.
func (c *Client) RegisterCustomer(ctx context.Context, customer did.DID, product did.DID, details map[string]string, opts ...MethodOption) error {
	cfg := &methodConfig{issuer: c.Issuer, proofs: c.Proofs}
	for _, opt := range opts {
		opt(cfg)
	}
	proofs, proofLinks, err := cfg.proofs.ProofChain(ctx, cfg.issuer.DID(), customercmds.Add.Command, c.ServiceID)
	if err != nil {
		return fmt.Errorf("getting proof chain: %w", err)
	}
	inv, err := customercmds.Add.Invoke(
		cfg.issuer,
		c.ServiceID,
		&customercmds.AddArguments{
			Customer: customer,
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
	res, err := c.Executor.Execute(execution.NewRequest(ctx, inv, execution.WithDelegations(proofs...)))
	if err != nil {
		log.Error("failed to execute register customer invocation", zap.Error(err))
		return fmt.Errorf("executing register customer invocation: %w", err)
	}
	if _, err := customercmds.Add.Unpack(res.Receipt()); err != nil {
		log.Error("failed to unpack register customer result", zap.Error(err))
		return fmt.Errorf("unpacking register customer result: %w", err)
	}
	return nil
}

// ProvisionSpace provisions a new space with the upload service. It returns the
// ID of the subscription that was set up.
func (c *Client) ProvisionSpace(ctx context.Context, account ucan.Issuer, space did.DID) (string, error) {
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

// SpaceEmpty checks whether the given space is empty (contains no blobs).
func (c *Client) SpaceEmpty(ctx context.Context, space did.DID, opts ...MethodOption) (bool, error) {
	cfg := &methodConfig{issuer: c.Issuer, proofs: c.Proofs}
	for _, opt := range opts {
		opt(cfg)
	}
	proofs, proofLinks, err := cfg.proofs.ProofChain(ctx, cfg.issuer.DID(), blobcmds.List.Command, space)
	if err != nil {
		return false, fmt.Errorf("getting proof chain: %w", err)
	}
	size := uint64(1)
	inv, err := blobcmds.List.Invoke(
		cfg.issuer,
		space,
		&blobcmds.ListArguments{
			Size: &size,
		},
		invocation.WithAudience(c.ServiceID),
		invocation.WithProofs(proofLinks...),
	)
	if err != nil {
		return false, fmt.Errorf("invoking list blobs: %w", err)
	}
	log := zapucan.WithInvocation(c.Logger, inv)
	log.Debug("executing invocation")
	res, err := c.Executor.Execute(execution.NewRequest(ctx, inv, execution.WithDelegations(proofs...)))
	if err != nil {
		log.Error("failed to execute list blobs invocation", zap.Error(err))
		return false, fmt.Errorf("executing list blobs invocation: %w", err)
	}
	listOK, err := blobcmds.List.Unpack(res.Receipt())
	if err != nil {
		log.Error("failed to unpack list blobs result", zap.Error(err))
		return false, fmt.Errorf("unpacking list blobs result: %w", err)
	}
	return len(listOK.Results) == 0, nil
}
