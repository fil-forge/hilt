package fx

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/fil-forge/hilt/pkg/config"
	"github.com/fil-forge/hilt/pkg/tracing"
	"github.com/fil-forge/libforge/identity"
	"github.com/fil-forge/ucantone/did"
	"github.com/fil-forge/ucantone/did/key"
	"github.com/fil-forge/ucantone/did/resolver"
	"github.com/fil-forge/ucantone/did/web"
	"go.uber.org/zap"
)

var errWebDIDNotAllowed = errors.New("did:web resolution not permitted")

// newDIDResolver denies external did:web resolution unless explicitly configured.
// The guard precedes the cache and HTTP resolver: untrusted invocations and their
// proofs cannot probe network reachability before their signatures are checked.
// The service's own document is always resolved locally.
func newDIDResolver(id identity.Identity, cfg config.ServerConfig, logger *zap.Logger) (resolver.ByMethod, error) {
	if logger == nil {
		logger = zap.NewNop()
	}
	allowed := make(map[did.DID]struct{}, len(cfg.AllowedWebDIDs))
	urls := make(map[string]struct{}, len(cfg.AllowedWebDIDs))
	for _, value := range cfg.AllowedWebDIDs {
		d, err := did.Parse(value)
		if err != nil || d.Method() != web.Method {
			return nil, fmt.Errorf("server.allowed_web_dids: expected an exact did:web identity")
		}
		u, err := allowedDocumentURL(d, cfg.InsecureDIDResolution)
		if err != nil {
			return nil, fmt.Errorf("server.allowed_web_dids: %w", err)
		}
		allowed[d] = struct{}{}
		urls[u] = struct{}{}
	}
	logger.Info("configured UCAN did:web resolution allowlist", zap.Int("identities", len(allowed)))
	// The library follows redirects. Guard every transport attempt, not just
	// the original DID, so an allowed document cannot redirect to another host,
	// port, path or query outside the configured document URLs.
	opts := []web.Option{web.WithTransport(tracing.Transport(allowedDIDTransport{
		base: http.DefaultTransport, urls: urls,
	}))}
	if cfg.InsecureDIDResolution {
		logger.Warn("insecure DID resolution enabled: did:web will be resolved over HTTP instead of HTTPS; this should only be used for development purposes")
		opts = append(opts, web.WithInsecure(true))
	}
	r, err := web.NewResolver(opts...)
	if err != nil {
		return nil, fmt.Errorf("creating did:web resolver: %w", err)
	}
	cached := resolver.NewCached(r, 3*time.Hour)
	selfDoc, err := id.DIDDocument()
	if err != nil {
		return nil, fmt.Errorf("creating DID document for service identity: %w", err)
	}
	guarded := did.ResolverFunc(func(ctx context.Context, d did.DID) (did.Document, error) {
		if d == id.DID() {
			return selfDoc, nil
		}
		if _, ok := allowed[d]; !ok {
			logger.Debug("did:web resolution denied by allowlist", zap.Stringer("did", d))
			return did.Document{}, errWebDIDNotAllowed
		}
		return cached.Resolve(ctx, d)
	})
	return resolver.ByMethod{"key": key.Resolver, "web": guarded}, nil
}

type allowedDIDTransport struct {
	base http.RoundTripper
	urls map[string]struct{}
}

func (t allowedDIDTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	if _, ok := t.urls[r.URL.String()]; !ok || r.Method != http.MethodGet {
		return nil, errWebDIDNotAllowed
	}
	return t.base.RoundTrip(r)
}

// allowedDocumentURL mirrors the pinned did:web resolver's URL construction,
// while rejecting ambiguous config (userinfo, wildcards, traversal or URL syntax).
// Matching complete DIDs and complete request URLs preserves explicit path/port
// scope; this is not a glob or a suffix-based host allowlist.
func allowedDocumentURL(d did.DID, insecure bool) (string, error) {
	parts := strings.Split(d.Identifier(), ":")
	host := strings.ReplaceAll(parts[0], "%3A", ":")
	if host == "" || strings.ContainsAny(host, "/*?#[\\]@%") {
		return "", errors.New("invalid did:web authority")
	}
	authority, err := url.Parse("https://" + host)
	if err != nil || authority.Hostname() == "" || authority.Port() == "0" {
		return "", errors.New("invalid did:web authority")
	}
	if !regexp.MustCompile(`^[A-Za-z0-9.-]+$`).MatchString(authority.Hostname()) {
		return "", errors.New("invalid did:web hostname")
	}
	for _, label := range strings.Split(strings.TrimSuffix(authority.Hostname(), "."), ".") {
		if label == "" || strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return "", errors.New("invalid did:web hostname")
		}
	}
	path := web.WellKnownDIDPath
	if len(parts) > 1 {
		for _, part := range parts[1:] {
			if part == "" || part == "." || part == ".." || strings.ContainsAny(part, "/\\?#*[]{}%") {
				return "", errors.New("invalid did:web path")
			}
		}
		path = "/" + strings.Join(parts[1:], "/") + "/did.json"
	}
	scheme := "https"
	if insecure {
		scheme = "http"
	}
	return (&url.URL{Scheme: scheme, Host: host, Path: path}).String(), nil
}
