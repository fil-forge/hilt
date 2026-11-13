package fx

import (
	"context"
	"errors"
	"sync"
	"time"

	providerstore "github.com/fil-forge/hilt/pkg/store/provider"
	"github.com/fil-forge/ucantone/did"
	"go.uber.org/zap"
)

const (
	// providerReloadInterval is the shortest time between two reads of the
	// provider store. A newly registered provider is recognized within it.
	providerReloadInterval = 10 * time.Second
	// providerReloadTimeout bounds one read of the provider store.
	providerReloadTimeout = 5 * time.Second
)

// errDIDNotPermitted is the answer for every DID that is not a registered
// provider. It names neither the DID nor its host, so it reads the same
// whether or not the host is reachable.
var errDIDNotPermitted = errors.New("DID resolution is permitted for registered providers only")

// providerResolver resolves a DID with the next resolver only when the DID
// identifies a registered provider, and refuses every other DID without
// calling it.
//
// A token's issuer is resolved before its signature is checked, so the DID
// reaching a resolver is whatever an unauthenticated caller wrote. The
// providers are the only callers the commands served to others admit, which
// makes their DIDs the only ones worth fetching a document for.
//
// The registered DIDs are held in memory, so a refusal costs no store read:
// an unrecognized DID triggers a reload at most once per reload interval. The
// provider store has no delete, so a DID once recognized stays recognized.
type providerResolver struct {
	providers providerstore.Store
	next      did.Resolver
	logger    *zap.Logger
	now       func() time.Time

	mu sync.Mutex
	// known holds the DIDs of the providers found by the last reload.
	known map[did.DID]struct{}
	// reloaded is when the provider store was last read, zero before the first
	// read.
	reloaded time.Time
}

func newProviderResolver(providers providerstore.Store, next did.Resolver, logger *zap.Logger) *providerResolver {
	return &providerResolver{providers: providers, next: next, logger: logger, now: time.Now}
}

func (r *providerResolver) Resolve(ctx context.Context, d did.DID) (did.Document, error) {
	if !r.registered(ctx, d) {
		r.logger.Debug("refusing to resolve a DID that is not a registered provider", zap.Stringer("did", d))
		return did.Document{}, errDIDNotPermitted
	}
	return r.next.Resolve(ctx, d)
}

// registered reports whether d identifies a registered provider, reloading the
// known set first when d is not in it and the reload interval has passed.
func (r *providerResolver) registered(ctx context.Context, d did.DID) bool {
	r.mu.Lock()
	defer r.mu.Unlock()

	if _, ok := r.known[d]; ok {
		return true
	}
	now := r.now()
	if !r.reloaded.IsZero() && now.Sub(r.reloaded) < providerReloadInterval {
		return false
	}
	r.reloaded = now

	// The reload serves every later caller, so the request that triggers it
	// cannot cancel it.
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), providerReloadTimeout)
	defer cancel()
	recs, err := r.providers.List(ctx)
	if err != nil {
		r.logger.Error("listing providers for DID resolution", zap.Error(err))
		return false
	}
	known := make(map[did.DID]struct{}, len(recs))
	for _, rec := range recs {
		known[rec.ID] = struct{}{}
	}
	r.known = known
	_, ok := known[d]
	return ok
}
