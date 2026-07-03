// Package auth provides the request authorization service for the Hilt UCAN RPC
// handlers: it authenticates SigV4/SigV4a signatures, resolves the access key
// and tenant, and enforces the provider/region constraints shared by every S3
// command.
package auth

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/fil-forge/hilt/pkg/sigv4"
	"github.com/fil-forge/hilt/pkg/store"
	"github.com/fil-forge/hilt/pkg/store/accesskey"
	"github.com/fil-forge/hilt/pkg/store/bucket"
	"github.com/fil-forge/hilt/pkg/store/provider"
	"github.com/fil-forge/hilt/pkg/store/tenant"
	"github.com/fil-forge/hilt/pkg/vault"
	s3 "github.com/fil-forge/libforge/commands/s3"
	"github.com/fil-forge/ucantone/did"
	"github.com/fil-forge/ucantone/multikey"
	"github.com/fil-forge/ucantone/multikey/ed25519"
	"github.com/fil-forge/ucantone/multikey/secp256k1"
	"github.com/fil-forge/ucantone/ucan"
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
	// Operation is the S3 operation the (signature-verified) request performs. The
	// access key is confirmed to hold its permission; handlers check it matches the
	// operation they serve.
	Operation Operation
	// BucketName is the bucket name from the request.
	BucketName string
	// Bucket is the resolved bucket the request addresses, when the operation acts
	// on an existing bucket. It is confirmed to belong to the tenant and to be
	// within the access key's bucket scope. Nil for ListBuckets and CreateBucket.
	Bucket *bucket.Record
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
	buckets    bucket.Store
	secrets    vault.Vault
}

// NewAuthorizer constructs the shared authorization service.
func NewAuthorizer(
	logger *zap.Logger,
	accessKeys accesskey.Store,
	tenants tenant.Store,
	providers provider.Store,
	buckets bucket.Store,
	secrets vault.Vault,
) *Authorizer {
	return &Authorizer{
		logger:     logger,
		accessKeys: accessKeys,
		tenants:    tenants,
		providers:  providers,
		buckets:    buckets,
		secrets:    secrets,
	}
}

// Authorize authenticates and authorizes an S3 RPC request. It verifies the
// SigV4/SigV4a signature and time bounds, resolves the access key and its
// tenant, confirms the invocation issuer is the tenant's provider, and
// validates the request region against that provider.
//
// Finally, the requested S3 operation is checked against the access key's
// permissions. Note that the caller must still check the operation matches the
// handler's operation, since Authorize is operation-agnostic.
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
	log = log.With(zap.String("region", region))

	// Determine the S3 operation the (verified) request performs and confirm the
	// access key is permitted to perform it. The operation is returned so the
	// handler can check it matches the operation it serves.
	op, bucketName, _, err := classifyRequest(req)
	if err != nil {
		log.Debug("rejecting unsupported operation", zap.Error(err))
		return nil, ErrUnsupportedOperation
	}
	if !slices.Contains(akRec.Permissions, op.Permission()) {
		log.Debug("rejecting operation the access key lacks permission for", zap.Stringer("operation", op))
		return nil, ErrOperationNotPermitted
	}

	// For operations on an existing bucket, resolve it (within the tenant) and
	// confirm it is within the access key's bucket scope (empty scope = all buckets).
	var resolved *bucket.Record
	if op.addressesExistingBucket() {
		b, err := a.buckets.GetByName(ctx, bucketName)
		if errors.Is(err, store.ErrRecordNotFound) || (err == nil && b.Tenant != tenantRec.ID) {
			log.Debug("rejecting unknown bucket", zap.String("bucket", bucketName))
			return nil, ErrUnknownBucket
		} else if err != nil {
			log.Error("looking up bucket", zap.Error(err))
			return nil, fmt.Errorf("looking up bucket: %w", err)
		}
		if len(akRec.Buckets) > 0 && !slices.Contains(akRec.Buckets, b.ID) {
			log.Debug("rejecting bucket the access key is not scoped to", zap.String("bucket", bucketName))
			return nil, ErrBucketNotPermitted
		}
		resolved = &b
	}

	log.Debug("request authorized", zap.Stringer("operation", op))
	return &AuthorizedRequest{
		AccessKey:  akRec,
		Tenant:     tenantRec,
		Region:     region,
		Operation:  op,
		BucketName: bucketName,
		Bucket:     resolved,
		Signed:     sr,
	}, nil
}

// TenantIssuer loads the tenant's secp256k1 signing key from the vault and
// returns an issuer that signs as the tenant — used to act on the tenant's
// behalf (e.g. provisioning a bucket's space with Sprue).
func (a *Authorizer) TenantIssuer(ctx context.Context, tenantID did.DID) (ucan.Issuer, error) {
	keyBytes, err := a.secrets.Read(ctx, vault.TenantKeyPath(tenantID))
	if err != nil {
		return nil, fmt.Errorf("reading tenant key: %w", err)
	}
	signer, err := secp256k1.Decode(keyBytes)
	if err != nil {
		return nil, fmt.Errorf("decoding tenant key: %w", err)
	}
	return multikey.NewIssuer(tenantID, signer), nil
}

// AccessKeySigner reads the access key's ed25519 private key from the vault.
func (a *Authorizer) AccessKeySigner(ctx context.Context, tenantID, accessKeyID did.DID) (multikey.Signer, error) {
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
func EncodeSecret(signer multikey.Signer) (string, error) {
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
