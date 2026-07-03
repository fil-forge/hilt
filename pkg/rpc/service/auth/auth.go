// Package auth provides the request authorization service for the Hilt UCAN RPC
// handlers: it authenticates SigV4/SigV4a signatures, resolves the access key
// and tenant, and enforces the provider/region constraints shared by every S3
// command.
package auth

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/fil-forge/hilt/pkg/sigv4"
	"github.com/fil-forge/hilt/pkg/store"
	"github.com/fil-forge/hilt/pkg/store/accesskey"
	"github.com/fil-forge/hilt/pkg/store/provider"
	"github.com/fil-forge/hilt/pkg/store/tenant"
	"github.com/fil-forge/hilt/pkg/vault"
	s3 "github.com/fil-forge/libforge/commands/s3"
	"github.com/fil-forge/ucantone/did"
	"github.com/fil-forge/ucantone/multikey/ed25519"
	"github.com/multiformats/go-multibase"
	"go.uber.org/zap"
)

// AuthorizedRequest is the authenticated, authorized context of an S3 RPC
// request: the verified caller's access key and tenant, and the region the
// request is scoped to (served by the tenant's provider). Command-specific
// permission checks use AccessKey.Permissions.
type AuthorizedRequest struct {
	AccessKey accesskey.Record
	Tenant    tenant.Record
	Region    string
	// Signed is the parsed, verified request signature. Handlers use it to derive
	// the verification key and to inspect the requested action.
	Signed *sigv4.SignedRequest
}

// Authorizer authenticates and authorizes S3 RPC requests. It is the shared
// authorization service injected into the S3 command handlers.
type Authorizer struct {
	logger     *zap.Logger
	accessKeys accesskey.Store
	tenants    tenant.Store
	providers  provider.Store
	secrets    vault.Vault
}

// NewAuthorizer constructs the shared authorization service.
func NewAuthorizer(
	logger *zap.Logger,
	accessKeys accesskey.Store,
	tenants tenant.Store,
	providers provider.Store,
	secrets vault.Vault,
) *Authorizer {
	return &Authorizer{
		logger:     logger,
		accessKeys: accessKeys,
		tenants:    tenants,
		providers:  providers,
		secrets:    secrets,
	}
}

// Authorize authenticates and authorizes an S3 RPC request — shared by all S3
// command handlers. It verifies the SigV4/SigV4a signature and time bounds,
// resolves the access key and its tenant, confirms the invocation issuer is the
// tenant's provider, and validates the request region against that provider.
// The command-specific S3 permission check is left to the caller (see
// [accesskey.Record.Permissions]).
func (a *Authorizer) Authorize(ctx context.Context, issuer did.DID, req s3.Request) (*AuthorizedRequest, error) {
	sr, err := sigv4.Parse(sigv4.Request{
		Method:  req.Method,
		Headers: req.Headers,
		URL:     req.URL,
	})
	if err != nil {
		a.logger.Debug("rejecting unparseable request signature", zap.Error(err))
		return nil, ErrMalformedSignature
	}
	log := a.logger.With(zap.String("access_key", sr.AccessKeyID), zap.Strings("regions", sr.Regions))
	log.Debug("authorizing request")

	accessKeyID, err := did.Parse(did.KeyPrefix + sr.AccessKeyID)
	if err != nil {
		log.Debug("rejecting invalid access key id", zap.Error(err))
		return nil, ErrInvalidAccessKeyID
	}

	akRec, err := a.accessKeys.Get(ctx, accessKeyID)
	if errors.Is(err, store.ErrRecordNotFound) {
		log.Debug("rejecting unknown access key")
		return nil, ErrUnknownAccessKey
	} else if err != nil {
		log.Error("looking up access key", zap.Error(err))
		return nil, fmt.Errorf("looking up access key: %w", err)
	}
	log = log.With(zap.Stringer("tenant", akRec.Tenant))

	// Reject expired access keys before touching the vault. ValidateTimeBounds
	// (below) bounds the signature's freshness, not the credential's lifetime.
	if akRec.ExpiresAt != nil && time.Now().After(*akRec.ExpiresAt) {
		log.Debug("rejecting expired access key", zap.Timep("expires_at", akRec.ExpiresAt))
		return nil, ErrAccessKeyExpired
	}

	// Authenticate: verify the request signature using the access key's secret.
	signer, err := a.AccessKeySigner(ctx, akRec.Tenant, accessKeyID)
	if err != nil {
		log.Error("loading access key", zap.Error(err))
		return nil, err
	}
	secret, err := EncodeSecret(signer)
	if err != nil {
		return nil, err
	}
	if err := sigv4.Verify(sr, secret); err != nil {
		log.Debug("rejecting invalid request signature", zap.Error(err))
		return nil, ErrSignatureMismatch
	}
	if err := sigv4.ValidateTimeBounds(sr, time.Now()); err != nil {
		log.Debug("rejecting request outside its validity window", zap.Error(err))
		return nil, ErrSignatureExpired
	}

	tenantRec, err := a.tenants.Get(ctx, akRec.Tenant)
	if err != nil {
		log.Error("looking up tenant", zap.Error(err))
		return nil, fmt.Errorf("looking up tenant: %w", err)
	}
	log = log.With(zap.Stringer("provider", tenantRec.Provider))

	// Disabled is the hard lock-out state (lifecycle Active → Disabled → delete).
	// WriteLocked still authenticates here so reads (like ListBuckets) work; write
	// handlers gate WriteLocked themselves, since Authorize is operation-agnostic.
	if tenantRec.Status == tenant.Disabled {
		log.Debug("rejecting disabled tenant")
		return nil, ErrTenantDisabled
	}

	// Only the tenant's provider may invoke on its behalf.
	if issuer != tenantRec.Provider {
		log.Debug("rejecting invocation not from the tenant's provider", zap.Stringer("issuer", issuer))
		return nil, ErrIssuerForbidden
	}

	// The request must be scoped to a region served by the tenant's provider.
	region, err := validateRegion(ctx, a.providers, sr.Regions, tenantRec.Provider)
	if err != nil {
		log.Debug("rejecting request region", zap.Error(err))
		return nil, err
	}

	log.Debug("request authorized", zap.String("region", region))
	return &AuthorizedRequest{AccessKey: akRec, Tenant: tenantRec, Region: region, Signed: sr}, nil
}

// AccessKeySigner reads the access key's ed25519 private key from the vault.
func (a *Authorizer) AccessKeySigner(ctx context.Context, tenantID, accessKeyID did.DID) (ed25519.Signer, error) {
	keyBytes, err := a.secrets.Read(ctx, vault.AccessKeyPath(tenantID, accessKeyID))
	if err != nil {
		return nil, fmt.Errorf("reading access key secret: %w", err)
	}
	signer, err := ed25519.Decode(keyBytes)
	if err != nil {
		return nil, fmt.Errorf("decoding access key: %w", err)
	}
	return signer, nil
}

// EncodeSecret returns the multibase base64url secretAccessKey string the
// client signs with, for the given access key private key.
func EncodeSecret(signer ed25519.Signer) (string, error) {
	secret, err := multibase.Encode(multibase.Base64url, signer.Bytes())
	if err != nil {
		return "", fmt.Errorf("encoding access key secret: %w", err)
	}
	return secret, nil
}

// validateRegion confirms the tenant's provider serves one of the regions the
// request is scoped to, returning the matched region.
func validateRegion(ctx context.Context, providers provider.Store, regions []string, tenantProvider did.DID) (string, error) {
	for _, r := range regions {
		prov, err := providers.GetByRegion(ctx, r)
		if errors.Is(err, store.ErrRecordNotFound) {
			continue // no provider serves this region
		}
		if err != nil {
			return "", fmt.Errorf("looking up provider for region %q: %w", r, err)
		}
		if prov.ID == tenantProvider {
			return r, nil
		}
	}
	return "", ErrRegionNotServed
}
