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
//
// The store is read outside the lock. A known provider resolves while a reload
// is in flight; an unrecognized DID waits for the reload to end, so a provider
// it finds is recognized by the requests that arrived during it.
type providerResolver struct {
	providers providerstore.Store
	next      did.Resolver
	logger    *zap.Logger
	now       func() time.Time

	mu sync.Mutex
	// known holds the DIDs of the providers found by the last successful
	// reload. A reload replaces the map and never writes to it.
	known map[did.DID]struct{}
	// reloaded is when the last reload started, zero before the first.
	reloaded time.Time
	// reloading is closed when the reload in flight ends, nil when none is.
	reloading chan struct{}
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

// registered reports whether d identifies a registered provider. When d is
// not known it waits for the reload in flight, starting one if the reload
// interval has passed, and looks again.
func (r *providerResolver) registered(ctx context.Context, d did.DID) bool {
	r.mu.Lock()
	if _, ok := r.known[d]; ok {
		r.mu.Unlock()
		return true
	}
	reloading := r.reloading
	if reloading == nil {
		now := r.now()
		if !r.reloaded.IsZero() && now.Sub(r.reloaded) < providerReloadInterval {
			r.mu.Unlock()
			return false
		}
		r.reloaded = now
		reloading = make(chan struct{})
		r.reloading = reloading
		// The reload serves every later caller, so the request that triggers it
		// cannot cancel it.
		go r.reload(context.WithoutCancel(ctx), reloading)
	}
	r.mu.Unlock()

	select {
	case <-reloading:
	case <-ctx.Done():
		return false
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	_, ok := r.known[d]
	return ok
}

// reload reads the provider store and replaces the known set, keeping the
// current one when the read fails. It closes done when it ends.
func (r *providerResolver) reload(ctx context.Context, done chan struct{}) {
	ctx, cancel := context.WithTimeout(ctx, providerReloadTimeout)
	defer cancel()

	var known map[did.DID]struct{}
	recs, err := r.providers.List(ctx)
	if err != nil {
		r.logger.Error("listing providers for DID resolution", zap.Error(err))
	} else {
		known = make(map[did.DID]struct{}, len(recs))
		for _, rec := range recs {
			known[rec.ID] = struct{}{}
		}
	}

	r.mu.Lock()
	if known != nil {
		r.known = known
	}
	r.reloading = nil
	r.mu.Unlock()
	close(done)
}
