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

	"github.com/fil-forge/hilt/pkg/bucketpolicy"
	"github.com/fil-forge/hilt/pkg/sigv4"
	"github.com/fil-forge/hilt/pkg/store"
	"github.com/fil-forge/hilt/pkg/store/accesskey"
	"github.com/fil-forge/hilt/pkg/store/bucket"
	bucketpolicystore "github.com/fil-forge/hilt/pkg/store/bucketpolicy"
	principalstore "github.com/fil-forge/hilt/pkg/store/principal"
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
// request: the verified caller's access key and tenant, the region the request
// is scoped to (served by the tenant's provider), and the S3 permissions the
// key holds. Command-specific permission checks use Permissions.
type AuthorizedRequest struct {
	AccessKey accesskey.Record
	Tenant    tenant.Record
	// Provider is the tenant's regional provider, confirmed to serve Region.
	Provider provider.Record
	Region   string
	// Permissions is the set of S3 actions the credential holds, which the
	// operation's action is confirmed to be in. A service key holds its own
	// permission set; a principal-bound key holds its principal's effective set
	// on Bucket, or s3:ListAllMyBuckets alone for ListBuckets.
	Permissions []string
	// Principal is the userId the credential is bound to. Nil for a service
	// credential, which is not a principal and is evaluated against no policy.
	Principal *string
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
	// SourceBucketName and SourceBucket are the copy source's bucket, for the copy
	// operations (Operation.CopiesSource()): resolved, tenant-checked and
	// scope-checked like Bucket, with the access key confirmed to hold
	// SourcePermission. Empty and nil for every other operation. SourceBucket is
	// Bucket itself when the copy stays within one bucket.
	SourceBucketName string
	SourceBucket     *bucket.Record
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
	principals principalstore.Store
	policies   bucketpolicystore.Store
	secrets    vault.Vault
}

// NewAuthorizer constructs the shared authorization service.
func NewAuthorizer(
	logger *zap.Logger,
	accessKeys accesskey.Store,
	tenants tenant.Store,
	providers provider.Store,
	buckets bucket.Store,
	principals principalstore.Store,
	policies bucketpolicystore.Store,
	secrets vault.Vault,
) *Authorizer {
	return &Authorizer{
		logger:     logger,
		accessKeys: accessKeys,
		tenants:    tenants,
		providers:  providers,
		buckets:    buckets,
		principals: principals,
		policies:   policies,
		secrets:    secrets,
	}
}

// Authorize authenticates and authorizes an S3 RPC request. It verifies the
// SigV4/SigV4a signature and time bounds, resolves the access key and its
// tenant, confirms the invocation issuer is the tenant's provider, and
// validates the request region against that provider.
//
// Finally, the requested S3 operation is authorized for the credential. A
// service key is checked against its own permissions and bucket scope. A
// principal-bound key holds what the bucket's policy grants its principal: the
// effective set is computed per request, an empty one hides the bucket
// ([ErrUnknownBucket]) and an action outside a non-empty one is refused
// ([ErrOperationNotPermitted]). The key, the principal and the policy rows are
// read with a share lock, so a request arriving while a change to any of them
// is committing waits for the outcome and is answered from the new state.
//
// Note that the caller must still check the operation matches the handler's
// operation, since Authorize is operation-agnostic.
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

	akRec, err := a.accessKeys.Get(ctx, accessKeyID, store.WithLock(store.LockShare))
	if errors.Is(err, store.ErrRecordNotFound) {
		log.Debug("rejecting unknown access key")
		return nil, ErrUnknownAccessKey
	} else if err != nil {
		return nil, lookupError(log, "access key", err)
	}
	log = log.With(zap.Stringer("tenant", akRec.Tenant))

	// Reject expired access keys before touching the vault. ValidateTimeBounds
	// (below) bounds the signature's freshness, not the credential's lifetime.
	if akRec.ExpiresAt != nil && time.Now().After(*akRec.ExpiresAt) {
		log.Debug("rejecting expired access key", zap.Timep("expires_at", akRec.ExpiresAt))
		return nil, ErrAccessKeyExpired
	}

	// Authenticate: verify the request signature using the access key's secret.
	signer, err := a.AccessKeySigner(ctx, akRec)
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
	prov, region, err := validateRegion(ctx, a.providers, sr.Regions, tenantRec.Provider)
	if err != nil {
		log.Debug("rejecting request region", zap.Error(err))
		return nil, err
	}
	log = log.With(zap.String("region", region))

	// Determine the S3 operation the (verified) request performs and confirm the
	// access key is permitted to perform it. The operation is returned so the
	// handler can check it matches the operation it serves.
	c, err := classifyRequest(req)
	if err != nil {
		log.Debug("rejecting unsupported operation", zap.Error(err))
		return nil, ErrUnsupportedOperation
	}
	op, bucketName := c.op, c.bucket

	// A copy also reads its source, named by a header. The path is always
	// signed; a header only when listed, so the naming must be covered by the
	// signature before anything is decided from it. What the credential needs on
	// the source is decided with the rest of its access.
	if op.CopiesSource() && !sr.HeaderSigned(copySourceHeader) {
		log.Debug("rejecting copy whose source header is not signed", zap.Stringer("operation", op))
		return nil, ErrUnsignedCopySource
	}

	permissions, resolved, source, err := a.authorizeOperation(ctx, log, akRec, tenantRec, c)
	if err != nil {
		return nil, err
	}

	log.Debug("request authorized", zap.Stringer("operation", op))
	return &AuthorizedRequest{
		AccessKey:        akRec,
		Tenant:           tenantRec,
		Provider:         prov,
		Region:           region,
		Permissions:      permissions,
		Principal:        akRec.Principal,
		Operation:        op,
		BucketName:       bucketName,
		Bucket:           resolved,
		SourceBucketName: c.srcBucket,
		SourceBucket:     source,
		Signed:           sr,
	}, nil
}

// authorizeOperation decides what the credential may do: its own permission
// set, within its own bucket scope, for a service key, and the principal's
// effective set on the addressed bucket for a principal-bound key. It returns
// the permissions, the resolved bucket, which is nil for the operations that
// address none, and the resolved copy source, which is nil unless the
// operation copies one.
func (a *Authorizer) authorizeOperation(
	ctx context.Context,
	log *zap.Logger,
	akRec accesskey.Record,
	tenantRec tenant.Record,
	c classification,
) ([]string, *bucket.Record, *bucket.Record, error) {
	op, bucketName := c.op, c.bucket

	// A service key carries its own permissions and bucket scope, evaluated
	// against no policy.
	if akRec.Principal == nil {
		if !slices.Contains(akRec.Permissions, op.Permission()) {
			log.Debug("rejecting operation the access key lacks permission for", zap.Stringer("operation", op))
			return nil, nil, nil, ErrOperationNotPermitted
		}
		if !op.addressesExistingBucket() {
			return akRec.Permissions, nil, nil, nil
		}
		b, err := a.resolveBucketInScope(ctx, log, akRec, tenantRec.ID, bucketName)
		if err != nil {
			return nil, nil, nil, err
		}
		// The copy's source is read under the same rules as its destination:
		// the key must hold the read permission, and the source bucket must be
		// the tenant's and within the key's scope.
		var source *bucket.Record
		if op.CopiesSource() {
			if !slices.Contains(akRec.Permissions, SourcePermission) {
				log.Debug("rejecting copy by a key lacking the source permission", zap.Stringer("operation", op))
				return nil, nil, nil, ErrOperationNotPermitted
			}
			if c.srcBucket == bucketName {
				source = b
			} else if source, err = a.resolveBucketInScope(ctx, log, akRec, tenantRec.ID, c.srcBucket); err != nil {
				return nil, nil, nil, err
			}
		}
		return akRec.Permissions, b, source, nil
	}

	principalID := *akRec.Principal
	log = log.With(zap.String("principal", principalID))

	// The share lock makes the read wait on a removal of this principal that is
	// committing, so the request is answered from the settled state.
	if _, err := a.principals.Get(ctx, tenantRec.ID, principalID, store.WithLock(store.LockShare)); err != nil {
		if errors.Is(err, store.ErrRecordNotFound) {
			// The key outlived its principal, which removal deletes it with. It
			// is on its way out; report it as the unknown credential it is about
			// to be.
			log.Debug("rejecting access key whose principal is gone")
			return nil, nil, nil, ErrUnknownAccessKey
		}
		return nil, nil, nil, lookupError(log, "principal", err)
	}

	switch op {
	case OpListBuckets:
		// Every principal lists the tenant's buckets; no policy is consulted.
		// The console filters the listing against the principal's access.
		return []string{"s3:ListAllMyBuckets"}, nil, nil, nil
	case OpCreateBucket, OpDeleteBucket:
		// No policy grants them: a key holding them would act outside the policy
		// that granted it.
		log.Debug("rejecting bucket operation no policy grants", zap.Stringer("operation", op))
		return nil, nil, nil, ErrOperationNotPermitted
	}

	b, err := a.resolveBucket(ctx, log, tenantRec.ID, bucketName)
	if err != nil {
		return nil, nil, nil, err
	}

	eff, err := a.effectiveActions(ctx, log, principalID, b.ID)
	if err != nil {
		return nil, nil, nil, err
	}
	// A bucket the principal holds no action on is not a bucket it may learn
	// exists, so an empty set reads as an unknown bucket rather than a refusal.
	if len(eff) == 0 {
		log.Debug("rejecting bucket outside the principal's reach", zap.String("bucket", bucketName))
		return nil, nil, nil, ErrUnknownBucket
	}
	if !slices.Contains(eff, op.Permission()) {
		log.Debug("rejecting operation outside the principal's effective set", zap.Stringer("operation", op))
		return nil, nil, nil, ErrOperationNotPermitted
	}

	// The copy's source is a second decision, taken on the source bucket's own
	// policy: the principal's effective set there must permit the read, exactly
	// as the destination's set must permit the write. A source within the
	// destination bucket is decided on the set already computed.
	var source *bucket.Record
	if op.CopiesSource() {
		if c.srcBucket == bucketName {
			source = b
			if !slices.Contains(eff, SourcePermission) {
				log.Debug("rejecting copy source outside the principal's effective set", zap.String("bucket", c.srcBucket))
				return nil, nil, nil, ErrOperationNotPermitted
			}
			return eff, b, source, nil
		}
		source, err = a.resolveBucket(ctx, log, tenantRec.ID, c.srcBucket)
		if err != nil {
			return nil, nil, nil, err
		}
		srcEff, err := a.effectiveActions(ctx, log, principalID, source.ID)
		if err != nil {
			return nil, nil, nil, err
		}
		if len(srcEff) == 0 {
			log.Debug("rejecting copy source outside the principal's reach", zap.String("bucket", c.srcBucket))
			return nil, nil, nil, ErrUnknownBucket
		}
		if !slices.Contains(srcEff, SourcePermission) {
			log.Debug("rejecting copy source outside the principal's effective set", zap.String("bucket", c.srcBucket))
			return nil, nil, nil, ErrOperationNotPermitted
		}
	}
	return eff, b, source, nil
}

// effectiveActions computes the actions the principal holds on a bucket from
// that bucket's policy, which is read with a share lock so a request arriving
// while the policy is being changed waits for the outcome. A bucket with no
// policy grants nothing.
func (a *Authorizer) effectiveActions(ctx context.Context, log *zap.Logger, principalID string, bucketID did.DID) ([]string, error) {
	var doc *bucketpolicy.Policy
	rec, err := a.policies.Get(ctx, bucketID, store.WithLock(store.LockShare))
	if err == nil {
		doc = &rec.Policy
	} else if !errors.Is(err, store.ErrRecordNotFound) {
		return nil, lookupError(log, "bucket policy", err)
	}
	return bucketpolicy.Effective(doc, principalID), nil
}

// lookupError reports a failed share-locked read of the named record. A wait
// the store gave up on, behind a write still committing, is
// [ErrTemporarilyUnavailable], wrapping the store's timeout, and the caller
// retries; anything else is an internal failure and is logged as such.
func lookupError(log *zap.Logger, what string, err error) error {
	if errors.Is(err, store.ErrLockTimeout) {
		log.Info("share-locked read waited out a write in flight", zap.String("record", what), zap.Error(err))
		return fmt.Errorf("%w: looking up %s: %w", ErrTemporarilyUnavailable, what, err)
	}
	log.Error("looking up "+what, zap.Error(err))
	return fmt.Errorf("looking up %s: %w", what, err)
}

// resolveBucketInScope resolves a bucket a service key addresses and confirms
// it lies within the key's bucket scope (an empty scope admits every bucket).
func (a *Authorizer) resolveBucketInScope(ctx context.Context, log *zap.Logger, akRec accesskey.Record, tenantID did.DID, name string) (*bucket.Record, error) {
	b, err := a.resolveBucket(ctx, log, tenantID, name)
	if err != nil {
		return nil, err
	}
	if len(akRec.Buckets) > 0 && !slices.Contains(akRec.Buckets, b.ID) {
		log.Debug("rejecting bucket the access key is not scoped to", zap.String("bucket", name))
		return nil, ErrBucketNotPermitted
	}
	return b, nil
}

// resolveBucket resolves a bucket name within the tenant. A missing bucket and
// a bucket of another tenant are distinct rejections: names are global, so S3
// answers the latter with AccessDenied, and the gateway needs to tell them
// apart.
func (a *Authorizer) resolveBucket(ctx context.Context, log *zap.Logger, tenantID did.DID, name string) (*bucket.Record, error) {
	b, err := a.buckets.GetByName(ctx, name)
	if errors.Is(err, store.ErrRecordNotFound) {
		log.Debug("rejecting unknown bucket", zap.String("bucket", name))
		return nil, ErrUnknownBucket
	} else if err != nil {
		log.Error("looking up bucket", zap.Error(err))
		return nil, fmt.Errorf("looking up bucket: %w", err)
	}
	if b.Tenant != tenantID {
		log.Debug("rejecting another tenant's bucket", zap.String("bucket", name))
		return nil, ErrForeignBucket
	}
	return &b, nil
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
func (a *Authorizer) AccessKeySigner(ctx context.Context, rec accesskey.Record) (multikey.Signer, error) {
	keyBytes, err := a.secrets.Read(ctx, vault.AccessKeyPath(rec.Tenant, rec.ID))
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
// request is scoped to, returning the provider record and the matched region.
func validateRegion(ctx context.Context, providers provider.Store, regions []string, tenantProvider did.DID) (provider.Record, string, error) {
	for _, r := range regions {
		prov, err := providers.GetByRegion(ctx, r)
		if errors.Is(err, store.ErrRecordNotFound) {
			continue // no provider serves this region
		}
		if err != nil {
			return provider.Record{}, "", fmt.Errorf("looking up provider for region %q: %w", r, err)
		}
		if prov.ID == tenantProvider {
			return prov, r, nil
		}
	}
	return provider.Record{}, "", ErrRegionNotServed
}
