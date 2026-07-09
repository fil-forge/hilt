package rpc

import (
	"context"
	"errors"
	"fmt"

	adminprovider "github.com/fil-forge/hilt/pkg/commands/admin/provider"
	"github.com/fil-forge/hilt/pkg/store"
	providerstore "github.com/fil-forge/hilt/pkg/store/provider"
	"github.com/fil-forge/libforge/identity"
	"github.com/fil-forge/ucantone/binding"
	"github.com/fil-forge/ucantone/did"
	ucanerrors "github.com/fil-forge/ucantone/errors"
	"github.com/fil-forge/ucantone/server"
	"go.uber.org/zap"
)

// Error names for the admin commands' known rejections, exported so callers can
// match on the stable Name() of a serialized failure.
const (
	UnauthorizedErrorName   = "Unauthorized"
	ProviderExistsErrorName = "ProviderExists"
)

// Known rejections returned by the admin handlers.
var (
	// ErrUnauthorized is returned when the invocation issuer is not the service's
	// own identity. Admin commands are self-issued only.
	ErrUnauthorized = ucanerrors.New(UnauthorizedErrorName, "only the service identity may perform this operation")
	// ErrProviderExists is returned when a provider is already registered for the
	// given DID or region.
	ErrProviderExists = ucanerrors.New(ProviderExistsErrorName, "a provider is already registered for this DID or region")
)

// NewAddProviderHandler handles /admin/provider/add — register a regional provider
// (DID + region). It is an admin command: only an invocation issued by the service's
// own identity is accepted (no delegation proofs, since the subject is the service).
func NewAddProviderHandler(logger *zap.Logger, id identity.Identity, providers providerstore.Store) server.Route {
	log := logger.With(zap.Stringer("command", adminprovider.Add.Command))
	return adminprovider.Add.Route(func(req *binding.Request[*adminprovider.AddArguments], res *binding.Response[*adminprovider.AddOK]) error {
		ok, err := AddProvider(req.Context(), log, id.DID(), providers, req.Invocation().Issuer(), req.Task().Arguments())
		if err != nil {
			log.Error("add provider failed", zap.Error(err))
			return adminFailure(res, err)
		}
		return res.SetSuccess(ok)
	})
}

// AddProvider registers a provider. Only the service identity (issuer == serviceID)
// may call it; there are no delegation proofs because the subject is the service. It
// is factored out of the handler so it can be unit tested without constructing a
// UCAN invocation.
func AddProvider(ctx context.Context, logger *zap.Logger, serviceID did.DID, providers providerstore.Store, issuer did.DID, args *adminprovider.AddArguments) (*adminprovider.AddOK, error) {
	if issuer != serviceID {
		return nil, ErrUnauthorized
	}
	if err := providers.Add(ctx, args.Provider, args.Region); err != nil {
		if errors.Is(err, store.ErrRecordExists) {
			return nil, fmt.Errorf("%w: provider %s region %q", ErrProviderExists, args.Provider, args.Region)
		}
		return nil, fmt.Errorf("adding provider: %w", err)
	}
	logger.Info("added provider", zap.Stringer("provider", args.Provider), zap.String("region", args.Region))
	return &adminprovider.AddOK{}, nil
}
