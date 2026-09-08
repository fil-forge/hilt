package rpc

import (
	"context"
	"errors"
	"fmt"

	"github.com/fil-forge/hilt/pkg/client/upload"
	adminprovider "github.com/fil-forge/hilt/pkg/commands/admin/provider"
	adminnodes "github.com/fil-forge/hilt/pkg/commands/admin/provider/nodes"
	"github.com/fil-forge/hilt/pkg/store"
	delegationstore "github.com/fil-forge/hilt/pkg/store/delegation"
	providerstore "github.com/fil-forge/hilt/pkg/store/provider"
	"github.com/fil-forge/libforge/identity"
	"github.com/fil-forge/ucantone/binding"
	"github.com/fil-forge/ucantone/did"
	ucanerrors "github.com/fil-forge/ucantone/errors"
	"github.com/fil-forge/ucantone/multikey"
	"github.com/fil-forge/ucantone/multikey/ed25519"
	"github.com/fil-forge/ucantone/server"
	"github.com/fil-forge/ucantone/ucan"
	"github.com/fil-forge/ucantone/ucan/command"
	"github.com/fil-forge/ucantone/ucan/delegation"
	"go.uber.org/zap"
)

// Error names for the admin commands' known rejections, exported so callers can
// match on the stable Name() of a serialized failure.
const (
	UnauthorizedErrorName     = "Unauthorized"
	ProviderExistsErrorName   = "ProviderExists"
	ProviderNotFoundErrorName = "ProviderNotFound"
	InvalidNodesErrorName     = "InvalidNodes"
)

// Known rejections returned by the admin handlers.
var (
	// ErrUnauthorized is returned when the invocation issuer is not the service's
	// own identity. Admin commands are self-issued only.
	ErrUnauthorized = ucanerrors.New(UnauthorizedErrorName, "only the service identity may perform this operation")
	// ErrProviderExists is returned when a provider is already registered for the
	// given DID or region.
	ErrProviderExists = ucanerrors.New(ProviderExistsErrorName, "a provider is already registered for this DID or region")
	// ErrProviderNotFound is returned when no provider is registered for the given
	// DID.
	ErrProviderNotFound = ucanerrors.New(ProviderNotFoundErrorName, "no provider is registered for this DID")
	// ErrInvalidNodes is returned when a provider's node set is empty.
	ErrInvalidNodes = ucanerrors.New(InvalidNodesErrorName, "at least one storage node is required")
)

// RoutingClient is the subset of the upload service (Sprue) the admin commands
// need: putting a routing policy's candidate set. It is satisfied by
// [*upload.Client].
type RoutingClient interface {
	PutRoutingPolicy(ctx context.Context, policy did.DID, candidates []did.DID, opts ...upload.MethodOption) error
}

// NewAddProviderHandler handles /admin/provider/add — register a regional provider
// (DID + region, optionally with the storage nodes it operates). It is an admin
// command: only an invocation issued by the service's own identity is accepted (no
// delegation proofs, since the subject is the service).
func NewAddProviderHandler(logger *zap.Logger, id identity.Identity, providers providerstore.Store, delegations delegationstore.Store, uploads RoutingClient) server.Route {
	log := logger.With(zap.Stringer("command", adminprovider.Add.Command))
	return adminprovider.Add.Route(func(req *binding.Request[*adminprovider.AddArguments], res *binding.Response[*adminprovider.AddOK]) error {
		ok, err := AddProvider(req.Context(), log, id.DID(), providers, delegations, uploads, req.Invocation().Issuer(), req.Task().Arguments())
		if err != nil {
			log.Error("add provider failed", zap.Error(err))
			return adminFailure(res, err)
		}
		return res.SetSuccess(ok)
	})
}

// AddProvider registers a provider. Only the service identity (issuer == serviceID)
// may call it; there are no delegation proofs because the subject is the service.
//
// When nodes are given, the provider's routing policy is issued and the nodes are
// put as its candidates on the upload service before the provider record is
// stored. The record goes last: the provider store has no delete, and an orphaned
// root delegation or upload-service policy that no record references is inert.
// Without nodes the provider is stored with no policy and its buckets use default
// routing until nodes are set.
//
// It is factored out of the handler so it can be unit tested without constructing
// a UCAN invocation.
func AddProvider(ctx context.Context, logger *zap.Logger, serviceID did.DID, providers providerstore.Store, delegations delegationstore.Store, uploads RoutingClient, issuer did.DID, args *adminprovider.AddArguments) (*adminprovider.AddOK, error) {
	if issuer != serviceID {
		return nil, ErrUnauthorized
	}

	// Validate the arguments and check for an existing registration before any
	// policy material is issued or sent to the upload service.
	if args.Provider == did.Undef {
		return nil, fmt.Errorf("provider ID is required: %w", store.ErrInvalidArgument)
	}
	if args.Region == "" {
		return nil, fmt.Errorf("provider region is required: %w", store.ErrInvalidArgument)
	}
	if _, err := providers.Get(ctx, args.Provider); err == nil {
		return nil, fmt.Errorf("%w: provider %s region %q", ErrProviderExists, args.Provider, args.Region)
	} else if !errors.Is(err, store.ErrRecordNotFound) {
		return nil, fmt.Errorf("checking provider: %w", err)
	}
	if _, err := providers.GetByRegion(ctx, args.Region); err == nil {
		return nil, fmt.Errorf("%w: provider %s region %q", ErrProviderExists, args.Provider, args.Region)
	} else if !errors.Is(err, store.ErrRecordNotFound) {
		return nil, fmt.Errorf("checking provider region: %w", err)
	}

	var policy *did.DID
	if len(args.Nodes) > 0 {
		policyID, err := issuePolicy(ctx, serviceID, delegations)
		if err != nil {
			return nil, err
		}
		if err := setPolicyNodes(ctx, uploads, delegations, policyID, args.Nodes); err != nil {
			return nil, err
		}
		policy = &policyID
	}

	if err := providers.Add(ctx, args.Provider, args.Region, policy); err != nil {
		if errors.Is(err, store.ErrRecordExists) {
			return nil, fmt.Errorf("%w: provider %s region %q", ErrProviderExists, args.Provider, args.Region)
		}
		return nil, fmt.Errorf("adding provider: %w", err)
	}
	log := logger.With(
		zap.Stringer("provider", args.Provider),
		zap.String("region", args.Region),
		zap.Int("nodes", len(args.Nodes)),
	)
	if policy != nil {
		log = log.With(zap.Stringer("policy", *policy))
	}
	log.Info("added provider")
	return &adminprovider.AddOK{}, nil
}

// NewSetProviderNodesHandler handles /admin/provider/nodes/set — replace the
// storage nodes a registered provider operates. It is an admin command: only an
// invocation issued by the service's own identity is accepted.
func NewSetProviderNodesHandler(logger *zap.Logger, id identity.Identity, providers providerstore.Store, delegations delegationstore.Store, uploads RoutingClient) server.Route {
	log := logger.With(zap.Stringer("command", adminnodes.Set.Command))
	return adminnodes.Set.Route(func(req *binding.Request[*adminnodes.SetArguments], res *binding.Response[*adminnodes.SetOK]) error {
		ok, err := SetProviderNodes(req.Context(), log, id.DID(), providers, delegations, uploads, req.Invocation().Issuer(), req.Task().Arguments())
		if err != nil {
			log.Error("set provider nodes failed", zap.Error(err))
			return adminFailure(res, err)
		}
		return res.SetSuccess(ok)
	})
}

// SetProviderNodes replaces the candidates of a registered provider's routing
// policy on the upload service, issuing the policy first if the provider has
// none. Only the service identity (issuer == serviceID) may call it. Hilt stores
// no node list itself: the upload service holds the policy's candidate set.
func SetProviderNodes(ctx context.Context, logger *zap.Logger, serviceID did.DID, providers providerstore.Store, delegations delegationstore.Store, uploads RoutingClient, issuer did.DID, args *adminnodes.SetArguments) (*adminnodes.SetOK, error) {
	if issuer != serviceID {
		return nil, ErrUnauthorized
	}
	if len(args.Nodes) == 0 {
		return nil, ErrInvalidNodes
	}
	rec, err := providers.Get(ctx, args.Provider)
	if errors.Is(err, store.ErrRecordNotFound) {
		return nil, fmt.Errorf("%w: %s", ErrProviderNotFound, args.Provider)
	} else if err != nil {
		return nil, fmt.Errorf("looking up provider: %w", err)
	}
	if rec.Policy == nil {
		// Issue the policy and put its candidates before recording it on the
		// provider, so a failure leaves only inert orphans (see AddProvider).
		policyID, err := issuePolicy(ctx, serviceID, delegations)
		if err != nil {
			return nil, err
		}
		if err := setPolicyNodes(ctx, uploads, delegations, policyID, args.Nodes); err != nil {
			return nil, err
		}
		if err := providers.SetPolicy(ctx, args.Provider, policyID); err != nil {
			return nil, fmt.Errorf("recording provider policy: %w", err)
		}
		rec.Policy = &policyID
	} else if err := setPolicyNodes(ctx, uploads, delegations, *rec.Policy, args.Nodes); err != nil {
		return nil, err
	}
	logger.Info("set provider nodes",
		zap.Stringer("provider", args.Provider),
		zap.Stringer("policy", *rec.Policy),
		zap.Int("nodes", len(args.Nodes)),
	)
	return &adminnodes.SetOK{}, nil
}

// issuePolicy creates a routing policy: a fresh ed25519 key whose DID is the
// policy DID delegates top authority over itself to the service (a non-expiring
// root, stored in the delegation store) and is then discarded. The delegation is
// the service's proof for every later put on the policy.
func issuePolicy(ctx context.Context, serviceID did.DID, delegations delegationstore.Store) (did.DID, error) {
	policySigner, err := ed25519.Generate()
	if err != nil {
		return did.Undef, fmt.Errorf("generating policy key: %w", err)
	}
	policyID := policySigner.KeyDID()
	root, err := delegation.Delegate(multikey.NewIssuer(policyID, policySigner), serviceID, policyID, command.Top(), delegation.WithNoExpiration())
	if err != nil {
		return did.Undef, fmt.Errorf("issuing policy root delegation: %w", err)
	}
	if err := delegations.PutBatch(ctx, []ucan.Delegation{root}); err != nil {
		return did.Undef, fmt.Errorf("storing policy root delegation: %w", err)
	}
	return policyID, nil
}

// setPolicyNodes puts nodes as the candidate set of the routing policy on the
// upload service. The invocation is issued by the service identity (the upload
// client's default issuer) and proven by the policy root delegation held in the
// delegation store.
func setPolicyNodes(ctx context.Context, uploads RoutingClient, delegations delegationstore.Store, policy did.DID, nodes []did.DID) error {
	if err := uploads.PutRoutingPolicy(ctx, policy, nodes, upload.WithProofs(delegations)); err != nil {
		return fmt.Errorf("putting routing policy %s: %w", policy, err)
	}
	return nil
}
