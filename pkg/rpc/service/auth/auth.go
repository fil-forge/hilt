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

	s3bkt "github.com/fil-forge/libforge/commands/s3/bucket"

	"github.com/fil-forge/hilt/pkg/bucketpolicy"
	"github.com/fil-forge/hilt/pkg/grant"
	"github.com/fil-forge/hilt/pkg/s3perm"
	"github.com/fil-forge/hilt/pkg/sigv4"
	"github.com/fil-forge/hilt/pkg/store"
	"github.com/fil-forge/hilt/pkg/store/accesskey"
	"github.com/fil-forge/hilt/pkg/store/bucket"
	bucketpolicystore "github.com/fil-forge/hilt/pkg/store/bucketpolicy"
	principalstore "github.com/fil-forge/hilt/pkg/store/principal"
	"github.com/fil-forge/hilt/pkg/store/provider"
	"github.com/fil-forge/hilt/pkg/store/tenant"
	"github.com/fil-forge/hilt/pkg/tasks"
	"github.com/fil-forge/hilt/pkg/vault"
	s3 "github.com/fil-forge/libforge/commands/s3"
	"github.com/fil-forge/libforge/taskrunner"
	"github.com/fil-forge/ucantone/did"
	"github.com/fil-forge/ucantone/multikey"
	"github.com/fil-forge/ucantone/multikey/ed25519"
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
	// on Bucket, or s3:ListAllMyBuckets alone for ListBuckets. For a
	// write-locked tenant it is that set less the actions a write-locked
	// tenant does not keep ([grant.LimitToTenantStatus]).
	Permissions []string
	// Operation is the S3 operation the (signature-verified) request performs. The
	// access key is confirmed to hold its permissions, and those the request's
	// headers add; handlers check it matches the operation they serve.
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
	// SourcePermission there. Empty and nil for every other operation.
	// SourceBucket is Bucket itself when the copy stays within one bucket.
	SourceBucketName string
	SourceBucket     *bucket.Record
	// SourcePermission is the S3 permission confirmed on the copy source:
	// the version read when the source names a version, the object read
	// otherwise. Empty for every other operation.
	SourcePermission string
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
	// changes finds and waits for the queued changes to a tenant's authority.
	// Nil skips the wait.
	changes TenantChanges
}

// TenantChanges is what [Authorizer.Authorize] needs of the task runner to
// hold a request back while a change to its tenant's authority is queued or
// running. [*taskrunner.Runner] satisfies it.
type TenantChanges interface {
	// PendingOn returns the subject's unfinished tasks on the queue, running
	// or waiting, oldest first.
	PendingOn(ctx context.Context, queueName, subject string) ([]taskrunner.TaskID, error)
	// WaitAll waits until every one of the tasks has finished, however it
	// ended. Its error is the wait's own: ctx ended, or a read failed.
	WaitAll(ctx context.Context, queueName string, ids ...taskrunner.TaskID) (map[taskrunner.TaskID]taskrunner.Completion, error)
}

// Option configures an [Authorizer].
type Option func(*Authorizer)

// WithTenantChanges makes [Authorizer.Authorize] wait for the tenant's
// unfinished tasks on queue-tenant before it reads the tenant's state.
func WithTenantChanges(changes TenantChanges) Option {
	return func(a *Authorizer) { a.changes = changes }
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
	opts ...Option,
) *Authorizer {
	a := &Authorizer{
		logger:     logger,
		accessKeys: accessKeys,
		tenants:    tenants,
		providers:  providers,
		buckets:    buckets,
		principals: principals,
		policies:   policies,
		secrets:    secrets,
	}
	for _, opt := range opts {
		opt(a)
	}
	return a
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
// ([ErrOperationNotPermitted]). A key whose principal was removed is refused
// ([ErrUnknownAccessKey]).
//
// The tenant's status decides first. A disabled tenant is refused every
// request ([ErrTenantDisabled]). A write-locked tenant is refused a request
// that needs a permission it does not keep ([ErrTenantWriteLocked],
// [s3perm.KeptWhenWriteLocked]), whatever the credential holds: an upload, a
// copy, a bucket creation, a change to configuration. Its reads, listings
// and deletions are decided as an active tenant's are, and the permissions
// returned are the credential's less those the tenant does not keep, so the
// set a gateway caches lets it refuse the same requests itself.
//
// The key, the principal and the policy rows are read with a share lock, so
// a request arriving while one of the writes that hold those rows locked is
// committing waits for the outcome and is answered from the new state. Those
// writes are the ones that run outside the tenant's task queue. A principal
// removal holds its principal's row while it revokes and deletes the
// principal's keys, whose rows it holds from their deletion on. A bucket
// deletion holds the bucket's policy lock while it revokes the bucket's
// grants and deletes the bucket.
//
// A change to the tenant's authority that is queued or running on the task
// runner holds the request back too (see [WithTenantChanges]), a policy
// write among them: once the
// request is authenticated, and before the tenant's status is read, Authorize
// waits for every unfinished task on queue-tenant for the tenant, for up to
// [store.LockTimeout], and answers from the state they leave. The access key
// is read before the wait, since it names the tenant, so a request that
// waited reads it again and is refused when a change it waited for deleted
// the key ([ErrUnknownAccessKey]). A wait that runs out is
// [ErrTemporarilyUnavailable].
//
// A change submitted after that wait can still commit while Authorize is
// reading. The tenant's status is therefore read first, before the policies
// and before the stored grants a handler goes on to read: see the comment
// at that read.
//
// Note that the caller must still check the operation matches the handler's
// operation: Authorize decides any operation, and a handler serves one.
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

	akRec, err := a.accessKeys.Get(ctx, accessKeyID, store.WithShareLock())
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

	waited, err := a.awaitTenantChanges(ctx, log, akRec.Tenant)
	if err != nil {
		return nil, err
	}
	if waited {
		// The key was read before the wait, to learn which tenant to wait
		// for, and a change the request waited for may have deleted it. The
		// request is decided on the key as it is now.
		akRec, err = a.accessKeys.Get(ctx, accessKeyID, store.WithShareLock())
		if errors.Is(err, store.ErrRecordNotFound) {
			log.Debug("rejecting an access key deleted while the request waited")
			return nil, ErrUnknownAccessKey
		} else if err != nil {
			return nil, lookupError(log, "access key", err)
		}
		if akRec.ExpiresAt != nil && time.Now().After(*akRec.ExpiresAt) {
			log.Debug("rejecting expired access key", zap.Timep("expires_at", akRec.ExpiresAt))
			return nil, ErrAccessKeyExpired
		}
	}

	// The status is read before the policies below and before the key's
	// stored grants, which a handler reads after Authorize returns, and that
	// order is what makes the separate reads safe. A status change commits
	// the status together with the grants it withdraws or issues, so one
	// that commits between two of these reads can only make the later reads
	// newer than the status read here. Either way the answer grants no more
	// than the older status allows:
	//
	//   - Read as active, then disabled: the key's stored grants are gone by
	//     the time they are read, so nothing the key delegates has a chain
	//     to the bucket. The answer is the one a request that finished just
	//     before the change would have had, without the key's grants.
	//   - Read as disabled, then reactivated: the request is refused below,
	//     whatever grants have been issued since.
	//   - Read as write-locked, then active: the request is decided, and
	//     its permissions reported, as write-locked, which is within what
	//     an active tenant is allowed.
	//   - Read as write-locked, then disabled: as the first case, the
	//     key's stored grants are gone by the time they are read.
	//   - Read as active, then write-locked: the request is decided as
	//     active, as one that finished just before the change would have
	//     been, and the permissions reported are the full set. This is the
	//     one case the order does not narrow, because the grants a
	//     write-locked key holds carry commands an upload uses too
	//     ([s3perm.KeptWhenWriteLocked]): the gateway holds the full set
	//     until it asks again.
	//
	// Keep the status read ahead of the others, and keep a status change's
	// grant writes in the commit that writes the status.
	tenantRec, err := a.tenants.Get(ctx, akRec.Tenant)
	if err != nil {
		log.Error("looking up tenant", zap.Error(err))
		return nil, fmt.Errorf("looking up tenant: %w", err)
	}
	// Disabled is the hard lock-out state (lifecycle Active → Disabled → delete).
	// A write-locked tenant is decided below, once the operation is known.
	if tenantRec.Status == tenant.Disabled {
		log.Debug("rejecting disabled tenant")
		return nil, ErrTenantDisabled
	}

	// The request is scoped to a region; the provider registered for it must be
	// the invocation issuer. Tenants are region-free, so this is the only issuer
	// check: any registered provider may act for any tenant, but only on
	// requests signed for its own region.
	prov, region, err := resolveProvider(ctx, a.providers, sr.Regions, issuer)
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
		if errors.Is(err, ErrConflictingQuery) || errors.Is(err, ErrUnsupportedOperation) || errors.Is(err, ErrInvalidBody) {
			log.Debug("rejecting request", zap.Error(err))
			return nil, err
		}
		log.Debug("rejecting unsupported operation", zap.Error(err))
		return nil, ErrUnsupportedOperation
	}
	op, bucketName := c.op, c.bucket

	// A copy reads its source, and a write may set a lock or tags, each named
	// by a header. The path is always signed; a header only when listed, so
	// every header a decision was taken from must be covered by the signature
	// before the decision is trusted. What the credential needs is decided
	// with the rest of its access.
	if h, ok := unsignedHeader(sr, c.headers); ok {
		log.Debug("rejecting request whose header is not signed", zap.Stringer("operation", op), zap.String("header", h))
		return nil, fmt.Errorf("%w: %s", ErrUnsignedHeader, h)
	}
	// A DeleteObjects is decided on its body too, forwarded for that
	// operation alone: bound to the signature first, then read.
	if err := c.bindBody(sr, req); err != nil {
		log.Debug("rejecting request on its body", zap.Stringer("operation", op), zap.Error(err))
		return nil, err
	}

	// A write-locked tenant is refused whatever needs a permission it does
	// not keep, before the credential's own access is looked at: the refusal
	// is the tenant's, the same for every key. It is decided here, after the
	// headers and the body have added their permissions, so a delete is
	// decided on everything it asks for.
	if tenantRec.Status == tenant.WriteLocked {
		for _, perm := range c.permissions() {
			if !s3perm.KeptWhenWriteLocked(perm) {
				log.Debug("rejecting operation a write-locked tenant does not keep", zap.Stringer("operation", op), zap.String("permission", perm))
				return nil, ErrTenantWriteLocked
			}
		}
	}

	permissions, resolved, source, err := a.authorizeOperation(ctx, log, akRec, tenantRec, prov, c)
	if err != nil {
		return nil, err
	}
	// The gateway caches this set and decides later requests from it, so it
	// carries only what the tenant's status keeps.
	permissions = grant.LimitToTenantStatus(tenantRec.Status, permissions)
	var sourcePermission string
	if op.CopiesSource() {
		sourcePermission = c.sourcePermission()
	}

	log.Debug("request authorized", zap.Stringer("operation", op))
	return &AuthorizedRequest{
		AccessKey:        akRec,
		Tenant:           tenantRec,
		Provider:         prov,
		Region:           region,
		Permissions:      permissions,
		Operation:        op,
		BucketName:       bucketName,
		Bucket:           resolved,
		SourceBucketName: c.srcBucket,
		SourceBucket:     source,
		SourcePermission: sourcePermission,
		Signed:           sr,
	}, nil
}

// awaitTenantChanges waits for the tenant's unfinished tasks on queue-tenant,
// each a change to what the tenant's keys may do, so that what is read after
// it is the state they leave. It reports whether there was anything to wait
// for, in which case what the caller read before it may have changed. With
// none pending, the usual case, it costs one indexed read. A task that failed
// has finished and changed nothing, so how each ended is not read. The wait
// is bounded by [store.LockTimeout], and one that runs out is
// [ErrTemporarilyUnavailable]: nothing about the request was decided, and
// the caller retries.
func (a *Authorizer) awaitTenantChanges(ctx context.Context, log *zap.Logger, tenantID did.DID) (bool, error) {
	if a.changes == nil {
		return false, nil
	}
	pending, err := a.changes.PendingOn(ctx, tasks.QueueTenant, tenantID.String())
	if err != nil {
		log.Error("looking up the tenant's pending changes", zap.Error(err))
		return false, fmt.Errorf("looking up the tenant's pending changes: %w", err)
	}
	if len(pending) == 0 {
		return false, nil
	}
	waitCtx, cancel := context.WithTimeout(ctx, store.LockTimeout)
	defer cancel()
	if _, err := a.changes.WaitAll(waitCtx, tasks.QueueTenant, pending...); err != nil {
		if errors.Is(err, context.DeadlineExceeded) && ctx.Err() == nil {
			log.Info("waited out a change to the tenant still pending", zap.Int("tasks", len(pending)))
			return true, fmt.Errorf("%w: waited %s for a change to the tenant", ErrTemporarilyUnavailable, store.LockTimeout)
		}
		log.Error("waiting for the tenant's pending changes", zap.Error(err))
		return true, fmt.Errorf("waiting for the tenant's pending changes: %w", err)
	}
	return true, nil
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
	prov provider.Record,
	c classification,
) ([]string, *bucket.Record, *bucket.Record, error) {
	op, bucketName := c.op, c.bucket

	// A service key carries its own permissions and bucket scope, evaluated
	// against no policy.
	if akRec.Principal == nil {
		for _, perm := range c.permissions() {
			if !slices.Contains(akRec.Permissions, perm) {
				log.Debug("rejecting operation the access key lacks permission for", zap.Stringer("operation", op), zap.String("permission", perm))
				return nil, nil, nil, ErrOperationNotPermitted
			}
		}
		if !op.addressesExistingBucket() {
			return akRec.Permissions, nil, nil, nil
		}
		b, err := a.resolveBucketInScope(ctx, log, akRec, prov, tenantRec.ID, bucketName)
		if err != nil {
			return nil, nil, nil, err
		}
		// The copy's source is read under the same rules as its destination:
		// the key must hold the read permission, and the source bucket must be
		// the tenant's and within the key's scope.
		var source *bucket.Record
		if op.CopiesSource() {
			if !slices.Contains(akRec.Permissions, c.sourcePermission()) {
				log.Debug("rejecting copy by a key lacking the source permission", zap.Stringer("operation", op))
				return nil, nil, nil, ErrOperationNotPermitted
			}
			if c.srcBucket == bucketName {
				source = b
			} else if source, err = a.resolveBucketInScope(ctx, log, akRec, prov, tenantRec.ID, c.srcBucket); err != nil {
				return nil, nil, nil, err
			}
		}
		return akRec.Permissions, b, source, nil
	}

	principalID := *akRec.Principal
	log = log.With(zap.String("principal", principalID))

	// The share lock makes the read wait on a removal of this principal that is
	// committing, so the request is answered from the settled state.
	if _, err := a.principals.Get(ctx, tenantRec.ID, principalID, store.WithShareLock()); err != nil {
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
	case OpCreateBucket, OpDeleteBucket, OpGetBucketPolicy, OpPutBucketPolicy, OpDeleteBucketPolicy, OpGetBucketPolicyStatus,
		OpGetBucketEncryption, OpPutBucketEncryption, OpDeleteBucketEncryption,
		OpPutBucketTagging, OpDeleteBucketTagging, OpPutBucketVersioning, OpPutObjectLockConfiguration,
		OpPutBucketCors, OpDeleteBucketCors:
		// No policy grants them: a key holding them would act outside, or
		// rewrite, the policy that granted it, or change the bucket's
		// configuration for every principal.
		log.Debug("rejecting bucket operation no policy grants", zap.Stringer("operation", op))
		return nil, nil, nil, ErrOperationNotPermitted
	}

	b, eff, err := a.principalAccess(ctx, log, prov, tenantRec.ID, principalID, bucketName, c.permissions()...)
	if err != nil {
		return nil, nil, nil, err
	}

	// The copy's source is a second decision, taken on the source bucket's own
	// policy: the principal's effective set there must permit the read, exactly
	// as the destination's set must permit the write. A source within the
	// destination bucket is decided on the set already computed.
	var source *bucket.Record
	if op.CopiesSource() {
		if c.srcBucket == bucketName {
			source = b
			if !slices.Contains(eff, c.sourcePermission()) {
				log.Debug("rejecting copy source outside the principal's effective set", zap.String("bucket", c.srcBucket))
				return nil, nil, nil, ErrOperationNotPermitted
			}
		} else if source, _, err = a.principalAccess(ctx, log, prov, tenantRec.ID, principalID, c.srcBucket, c.sourcePermission()); err != nil {
			return nil, nil, nil, err
		}
	}
	return eff, b, source, nil
}

// principalAccess resolves the bucket and confirms the principal holds every
// one of perms on it under the bucket's policy, returning the bucket and the
// principal's effective set there. A bucket the principal holds no action on
// is not a bucket it may learn exists, so an empty set reads as an unknown
// bucket rather than a refusal.
func (a *Authorizer) principalAccess(ctx context.Context, log *zap.Logger, prov provider.Record, tenantID did.DID, principalID, bucketName string, perms ...string) (*bucket.Record, []string, error) {
	b, err := a.resolveBucket(ctx, log, tenantID, bucketName)
	if err != nil {
		return nil, nil, err
	}
	eff, _, err := a.effectiveActions(ctx, log, principalID, b.ID)
	if err != nil {
		return nil, nil, err
	}
	if len(eff) == 0 {
		log.Debug("rejecting bucket outside the principal's reach", zap.String("bucket", bucketName))
		return nil, nil, ErrUnknownBucket
	}
	for _, perm := range perms {
		if !slices.Contains(eff, perm) {
			log.Debug("rejecting operation outside the principal's effective set", zap.String("permission", perm))
			return nil, nil, ErrOperationNotPermitted
		}
	}
	if err := a.assertServedBy(ctx, log, prov, b); err != nil {
		return nil, nil, err
	}
	return b, eff, nil
}

// EffectiveActions computes the actions the tenant's principal holds on the
// bucket, for a caller that has resolved both: the principal is read with a
// share lock, so a request arriving while it is being removed waits for the
// outcome, and a removed principal is [ErrUnknownAccessKey], the key bound to
// it being on its way out; the policy is read the same way. A wait the store
// gave up on is [ErrTemporarilyUnavailable]. An empty set is a bucket the
// principal cannot reach.
//
// It also returns the ETag of the policy the actions came from, so a caller
// that goes on to read something the same policy write touches can tell
// whether the two came from one revision. A bucket with no policy reports "".
func (a *Authorizer) EffectiveActions(ctx context.Context, tenantID did.DID, principalID string, bucketID did.DID) ([]string, string, error) {
	log := a.logger.With(zap.Stringer("tenant", tenantID), zap.String("principal", principalID), zap.Stringer("bucket", bucketID))
	if _, err := a.principals.Get(ctx, tenantID, principalID, store.WithShareLock()); err != nil {
		if errors.Is(err, store.ErrRecordNotFound) {
			return nil, "", fmt.Errorf("%w: its principal is gone", ErrUnknownAccessKey)
		}
		return nil, "", lookupError(log, "principal", err)
	}
	return a.effectiveActions(ctx, log, principalID, bucketID)
}

// effectiveActions computes the actions the principal holds on a bucket from
// that bucket's policy, which is read with a share lock so a request arriving
// while the bucket is being deleted, which holds the policy's lock while it
// revokes the bucket's grants, waits for the outcome. Authorize waits for a
// policy write on the tenant's queue before it gets here. A bucket with no
// policy grants nothing, and reports no ETag.
func (a *Authorizer) effectiveActions(ctx context.Context, log *zap.Logger, principalID string, bucketID did.DID) ([]string, string, error) {
	var doc *s3bkt.PolicyDocument
	var etag string
	rec, err := a.policies.Get(ctx, bucketID, store.WithShareLock())
	if err == nil {
		doc, etag = &rec.Policy, rec.ETag
	} else if !errors.Is(err, store.ErrRecordNotFound) {
		return nil, "", lookupError(log, "bucket policy", err)
	}
	return bucketpolicy.Effective(doc, principalID), etag, nil
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
func (a *Authorizer) resolveBucketInScope(ctx context.Context, log *zap.Logger, akRec accesskey.Record, prov provider.Record, tenantID did.DID, name string) (*bucket.Record, error) {
	b, err := a.resolveBucket(ctx, log, tenantID, name)
	if err != nil {
		return nil, err
	}
	if len(akRec.Buckets) > 0 && !slices.Contains(akRec.Buckets, b.ID) {
		log.Debug("rejecting bucket the access key is not scoped to", zap.String("bucket", name))
		return nil, ErrBucketNotPermitted
	}
	if err := a.assertServedBy(ctx, log, prov, b); err != nil {
		return nil, err
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

// assertServedBy confirms the provider handling the request is the one serving
// the bucket. It is asked after the caller's own access has been settled, so a
// caller the bucket is not scoped to learns nothing about where it lives.
func (a *Authorizer) assertServedBy(ctx context.Context, log *zap.Logger, prov provider.Record, b *bucket.Record) error {
	if b.Provider == prov.ID {
		return nil
	}
	served, err := a.providers.Get(ctx, b.Provider)
	if err != nil {
		log.Error("looking up the provider serving a bucket", zap.Stringer("bucket", b.ID), zap.Stringer("bucket_provider", b.Provider), zap.Error(err))
		return fmt.Errorf("looking up provider %s of bucket %q: %w", b.Provider, b.Name, err)
	}
	log.Debug("rejecting bucket served by another region", zap.Stringer("bucket", b.ID), zap.String("bucket_region", served.Region))
	return &BucketRegionMismatchError{Expected: served.Region, Actual: prov.Region}
}

// TenantIssuer loads the tenant's secp256k1 signing key from the vault and
// returns an issuer that signs as the tenant — used to act on the tenant's
// behalf (e.g. provisioning a bucket's space with Sprue).
func (a *Authorizer) TenantIssuer(ctx context.Context, tenantID did.DID) (ucan.Issuer, error) {
	return vault.TenantIssuer(ctx, a.secrets, tenantID)
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

// resolveProvider finds the provider serving one of the regions the request is
// scoped to (the SigV4 credential-scope region, or the SigV4a region set) and
// confirms it is the invocation issuer, returning the provider record and the
// matched region. A region no provider serves is skipped: when every region is
// unserved the request names nowhere this Hilt reaches, which is a different
// answer from naming somewhere another provider serves.
func resolveProvider(ctx context.Context, providers provider.Store, regions []string, issuer did.DID) (provider.Record, string, error) {
	served := false
	for _, r := range regions {
		prov, err := providers.GetByRegion(ctx, r)
		if errors.Is(err, store.ErrRecordNotFound) {
			continue // no provider serves this region
		}
		if err != nil {
			return provider.Record{}, "", fmt.Errorf("looking up provider for region %q: %w", r, err)
		}
		if prov.ID == issuer {
			return prov, r, nil
		}
		served = true
	}
	if served {
		return provider.Record{}, "", ErrIssuerForbidden
	}
	return provider.Record{}, "", ErrRegionNotServed
}
