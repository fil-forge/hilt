// Package bucket provides the S3 bucket business logic for the UCAN RPC API:
// create (authenticate + create the bucket, its bucket→tenant root delegation, and
// Sprue space, returning the access key's proof chains), delete (authenticate,
// then a task on the tenant's queue that verifies the bucket is empty via Sprue
// and tears it down), list, and info (a lookup returning proof chains,
// authorized by the invocation issuer rather than by a signed request). It
// returns the known errors in errors.go so handlers surface stable failure names;
// unexpected failures are returned wrapped.
package bucket

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"slices"
	"strconv"
	"time"

	bucketpolicysvc "github.com/fil-forge/hilt/pkg/api/service/bucketpolicy"
	"github.com/fil-forge/hilt/pkg/client/upload"
	"github.com/fil-forge/hilt/pkg/grant"
	"github.com/fil-forge/hilt/pkg/rpc/service/auth"
	"github.com/fil-forge/hilt/pkg/sigv4"
	"github.com/fil-forge/hilt/pkg/store"
	"github.com/fil-forge/hilt/pkg/store/accesskey"
	bucketstore "github.com/fil-forge/hilt/pkg/store/bucket"
	bucketpolicystore "github.com/fil-forge/hilt/pkg/store/bucketpolicy"
	delegationstore "github.com/fil-forge/hilt/pkg/store/delegation"
	providerstore "github.com/fil-forge/hilt/pkg/store/provider"
	tenantstore "github.com/fil-forge/hilt/pkg/store/tenant"
	"github.com/fil-forge/hilt/pkg/tasks/tenantqueue"
	s3 "github.com/fil-forge/libforge/commands/s3"
	s3bkt "github.com/fil-forge/libforge/commands/s3/bucket"
	s3req "github.com/fil-forge/libforge/commands/s3/request"
	"github.com/fil-forge/libforge/taskrunner"
	"github.com/fil-forge/ucantone/did"
	"github.com/fil-forge/ucantone/multikey"
	"github.com/fil-forge/ucantone/multikey/ed25519"
	"github.com/fil-forge/ucantone/ucan"
	"github.com/fil-forge/ucantone/ucan/command"
	"github.com/fil-forge/ucantone/ucan/delegation"
	"github.com/fil-forge/ucantone/validator"
	"github.com/ipfs/go-cid"
	"go.uber.org/zap"
)

// maxListBuckets is the S3 ListBuckets max-buckets ceiling, also used as the
// page size when the parameter is absent.
const maxListBuckets = 10000

// UploadClient is the subset of the upload service (Sprue) the bucket operations
// need. It is satisfied by [*upload.Client]; the interface lets the logic be
// unit tested without a live Sprue.
type UploadClient interface {
	ProvisionSpace(ctx context.Context, account ucan.Issuer, space did.DID) (string, error)
	SpaceEmpty(ctx context.Context, space did.DID, opts ...upload.MethodOption) (bool, error)
	UseRoutingPolicy(ctx context.Context, space did.DID, policy *did.DID, opts ...upload.MethodOption) error
}

// Service implements the S3 bucket operations shared by the UCAN command handlers.
type Service struct {
	logger      *zap.Logger
	authorizer  *auth.Authorizer
	buckets     bucketstore.Store
	delegations delegationstore.Store
	accessKeys  accesskey.Store
	tenants     tenantstore.Store
	policies    bucketpolicystore.Store
	providers   providerstore.Store
	uploads     UploadClient
	// policyWrites stores a policy as the management API stores a policy PUT.
	policyWrites *bucketpolicysvc.Service
	runner       *taskrunner.Runner
}

// New constructs the bucket service. runner runs the bucket deletions, and
// must have queue-tenant's handlers registered ([tenantqueue.New]) and be
// started before Delete is called.
func New(
	logger *zap.Logger,
	authorizer *auth.Authorizer,
	buckets bucketstore.Store,
	delegations delegationstore.Store,
	accessKeys accesskey.Store,
	tenants tenantstore.Store,
	policies bucketpolicystore.Store,
	providers providerstore.Store,
	uploads UploadClient,
	policyWrites *bucketpolicysvc.Service,
	runner *taskrunner.Runner,
) *Service {
	return &Service{
		logger:       logger,
		authorizer:   authorizer,
		buckets:      buckets,
		delegations:  delegations,
		accessKeys:   accessKeys,
		tenants:      tenants,
		policies:     policies,
		providers:    providers,
		uploads:      uploads,
		policyWrites: policyWrites,
		runner:       runner,
	}
}

// Create authenticates the request, checks the s3:CreateBucket permission, creates
// the bucket (an ephemeral bucket key signs a bucket→tenant "top" root delegation
// and is then discarded), provisions the bucket's space with Sprue as the tenant,
// points the space at the provider's routing policy so its writes land on the
// provider's storage nodes, and returns the AuthorizeOK: the new bucket DID, the
// access key's permissions and derived verification key, and the proof chains for
// the access key's powerline delegations (which now reach the new bucket).
//
// A write-locked tenant creates no bucket: Authorize refuses the request
// ([auth.ErrTenantWriteLocked]). The permissions returned are those the
// tenant's status keeps when the proof chains have been read
// ([Service.permissionsUnderStatus]).
func (s *Service) Create(ctx context.Context, issuer did.DID, args *s3bkt.CreateArguments) (*s3req.AuthorizeOK, []ucan.Delegation, error) {
	authz, err := s.authorizer.Authorize(ctx, issuer, args.Request)
	if err != nil {
		return nil, nil, err
	}
	accessKeyID := authz.AccessKey.ID

	if authz.Operation != auth.OpCreateBucket {
		return nil, nil, fmt.Errorf("%w: %s", ErrOperationMismatch, authz.Operation)
	}

	rec, err := s.buckets.GetByName(ctx, authz.BucketName)
	if err == nil {
		// An existing name owned by the requesting tenant is
		// BucketAlreadyOwnedByYou; owned by anyone else is BucketAlreadyExists.
		if rec.Tenant == authz.Tenant.ID {
			return nil, nil, fmt.Errorf("%w: %q", ErrBucketAlreadyOwned, authz.BucketName)
		}
		return nil, nil, fmt.Errorf("%w: %q", ErrBucketExists, authz.BucketName)
	} else if !errors.Is(err, store.ErrRecordNotFound) {
		return nil, nil, fmt.Errorf("looking up bucket: %w", err)
	}

	// Generate an ephemeral bucket key; its DID is the bucket DID. The key signs
	// the root delegation below and is then discarded (the space is managed by
	// Sprue).
	bucketSigner, err := ed25519.Generate()
	if err != nil {
		return nil, nil, fmt.Errorf("generating bucket key: %w", err)
	}
	bucketID := bucketSigner.KeyDID()
	log := s.logger.With(zap.Stringer("bucket", bucketID), zap.String("name", authz.BucketName))

	// The bucket is served by the provider handling this request: its space is
	// routed to that provider's storage nodes below, and only that provider may
	// act on it afterwards.
	if err := s.buckets.Add(ctx, bucketID, authz.Tenant.ID, authz.Provider.ID, authz.BucketName); err != nil {
		return nil, nil, fmt.Errorf("storing bucket: %w", err)
	}
	// Best-effort rollback of the bucket record on a later failure. The root
	// delegation (if already stored) becomes unreachable — its bucket record is
	// gone — so it is inert; the delegation store has no delete-by-CID.
	//
	// Cleanup runs on a context detached from the request (values retained, but
	// cancellation/deadline dropped) so a client disconnect — which cancels ctx —
	// cannot abort the rollback partway and leave an orphaned bucket record.
	rollback := func() {
		cleanupCtx := context.WithoutCancel(ctx)
		if err := s.buckets.Delete(cleanupCtx, bucketID); err != nil {
			log.Error("rollback: deleting bucket", zap.Error(err))
		}
	}

	// Root delegation: the bucket delegates top authority over itself to the tenant
	// (iss == sub == bucket, aud == tenant). It lives as long as the bucket does —
	// without WithNoExpiration, ucantone defaults to a 30-second expiry, which
	// killed every proof chain through the bucket root.
	root, err := delegation.Delegate(multikey.NewIssuer(bucketID, bucketSigner), authz.Tenant.ID, bucketID, command.Top(), delegation.WithNoExpiration())
	if err != nil {
		rollback()
		return nil, nil, fmt.Errorf("issuing root delegation: %w", err)
	}
	if err := s.delegations.PutBatch(ctx, []ucan.Delegation{root}); err != nil {
		rollback()
		return nil, nil, fmt.Errorf("storing root delegation: %w", err)
	}

	// Provision the bucket's space with Sprue, acting as the tenant.
	account, err := s.authorizer.TenantIssuer(ctx, authz.Tenant.ID)
	if err != nil {
		rollback()
		return nil, nil, err
	}
	subscription, err := s.uploads.ProvisionSpace(ctx, account, bucketID)
	if err != nil {
		rollback()
		return nil, nil, fmt.Errorf("provisioning bucket space: %w", err)
	}
	log.Debug("provisioned bucket space", zap.String("subscription", subscription))

	// Route the space to the provider's storage nodes. The tenant issues the
	// invocation, proven by the bucket→tenant root stored above. A bucket that
	// cannot be routed is not created: the provisioned space is left behind, inert,
	// as it is on every later failure (a retry generates a fresh bucket key). A
	// provider without a policy leaves the space on default routing.
	if policy := authz.Provider.Policy; policy != nil {
		if err := s.uploads.UseRoutingPolicy(ctx, bucketID, policy, upload.WithIssuer(account), upload.WithProofs(s.delegations)); err != nil {
			rollback()
			return nil, nil, fmt.Errorf("applying routing policy %s: %w", *policy, err)
		}
		log.Debug("applied routing policy", zap.Stringer("policy", policy))
	} else {
		log.Debug("provider has no routing policy, using default routing")
	}

	// Derive the verification key the gateway uses to validate the caller's request
	// signatures for this bucket.
	signer, err := s.authorizer.AccessKeySigner(ctx, authz.AccessKey.Tenant, accessKeyID)
	if err != nil {
		rollback()
		return nil, nil, err
	}
	secret, err := auth.EncodeSecret(signer)
	if err != nil {
		rollback()
		return nil, nil, err
	}
	key, err := sigv4.DeriveKey(authz.Signed, secret)
	if err != nil {
		rollback()
		return nil, nil, fmt.Errorf("deriving signing key: %w", err)
	}
	kind := s3.KeyKindSigV4
	if authz.Signed.Scheme == sigv4.SchemeV4a {
		kind = s3.KeyKindSigV4a
	}

	// Return the proof chains for the access key's powerline (undefined-subject)
	// delegations, which now reach the new bucket via the root delegation above.
	stored, err := store.Collect(ctx, func(ctx context.Context, opts store.PaginationConfig) (store.Page[ucan.Delegation], error) {
		var o []store.PaginationOption
		if opts.Cursor != nil {
			o = append(o, store.WithCursor(*opts.Cursor))
		}
		return s.delegations.ListByAudience(ctx, accessKeyID, o...)
	})
	if err != nil {
		rollback()
		return nil, nil, fmt.Errorf("listing delegations: %w", err)
	}

	proofSet := map[cid.Cid][]cid.Cid{}
	var blocks []ucan.Delegation
	seen := map[string]bool{}
	for _, d := range stored {
		if d.Subject().Defined() {
			continue // only powerline delegations reach a brand-new bucket
		}
		if validator.ValidateNotExpired(d, ucan.Now()) != nil {
			continue // stored until it is deleted, and in no chain
		}
		proofs, links, err := s.delegations.ProofChain(ctx, accessKeyID, d.Command(), bucketID)
		if err != nil {
			rollback()
			return nil, nil, fmt.Errorf("building proof chain for %s: %w", d.Command(), err)
		}
		if len(proofs) == 0 {
			continue
		}
		proofSet[d.Link()] = links
		for _, p := range proofs {
			if k := p.Link().String(); !seen[k] {
				seen[k] = true
				blocks = append(blocks, p)
			}
		}
	}

	permissions, err := s.permissionsUnderStatus(ctx, authz.Tenant.ID, authz.Permissions)
	if err != nil {
		rollback()
		return nil, nil, err
	}

	log.Debug("created bucket", zap.Int("delegations", len(proofSet)))
	return &s3req.AuthorizeOK{
		Bucket: &bucketID,
		Tenant: authz.Tenant.ID,
		Permissions: s3.PermissionSet{Entries: map[did.DID][]string{
			accessKeyID: permissions,
		}},
		Keys: s3.KeySet{Entries: map[did.DID][]s3.VerificationKey{
			accessKeyID: {{Kind: kind, Data: key}},
		}},
		Delegations: s3.ProofSet{Entries: proofSet},
	}, blocks, nil
}

// DeleteTimeout is the longest a bucket deletion waits for its turn on the
// tenant's queue. A deletion that has not started by then is abandoned with
// nothing written, and the caller repeats the call.
const DeleteTimeout = 30 * time.Second

// Delete authenticates the request, checks it is a DeleteBucket the key may
// make, asks Sprue, as the tenant, whether the bucket's space is empty,
// refuses a bucket that is not ([ErrBucketNotEmpty]), and deletes the
// bucket. The deletion is a queue-tenant.delete-bucket task ([tenantqueue]),
// which Delete waits for, behind any other change to the tenant: in one
// commit it records every delegation the tenant issued over the bucket as a
// revocation owed and deletes the bucket's delegations and the bucket, which
// takes its policy with it. The revocations are published after the
// commit, by the task the commit queues, and retried until the revocation
// service takes them, so Delete returns before the gateway has been told of
// them, and succeeds while the revocation service is down. The policy goes
// without a revocation of its own: the gateway refuses a bucket it no longer
// knows, so nothing cached for it can be used.
//
// Sprue is asked before the task is queued, so a slow answer holds up this
// call alone and not every change and authorization for the tenant. Asking
// inside the task would be no safer: uploads are not on the tenant's queue,
// so the space can gain a blob between the answer and the commit either
// way, as it could before the deletion was a task.
//
// A deletion still waiting for its turn after [DeleteTimeout], or at ctx's
// deadline if that is sooner, is abandoned with nothing written and reported
// as [auth.ErrTemporarilyUnavailable].
func (s *Service) Delete(ctx context.Context, issuer did.DID, args *s3bkt.DeleteArguments) (*s3bkt.DeleteOK, error) {
	authz, err := s.authorizer.Authorize(ctx, issuer, args.Request)
	if err != nil {
		return nil, err
	}

	if authz.Operation != auth.OpDeleteBucket {
		return nil, fmt.Errorf("%w: %s", ErrOperationMismatch, authz.Operation)
	}

	// The bucket's root delegation to the tenant authorizes the /blob/list
	// invocation that lists the space's blobs.
	account, err := s.authorizer.TenantIssuer(ctx, authz.Tenant.ID)
	if err != nil {
		return nil, err
	}
	empty, err := s.uploads.SpaceEmpty(ctx, authz.Bucket.ID, upload.WithIssuer(account), upload.WithProofs(s.delegations))
	if err != nil {
		return nil, fmt.Errorf("checking bucket is empty: %w", err)
	}
	if !empty {
		return nil, fmt.Errorf("%w: %q", ErrBucketNotEmpty, authz.BucketName)
	}

	spec := tenantqueue.DeleteBucketSpec(authz.Tenant.ID, authz.Bucket.ID)
	expires := time.Now().Add(DeleteTimeout)
	if deadline, ok := ctx.Deadline(); ok && deadline.Before(expires) {
		expires = deadline
	}
	spec.Expires = &expires
	if _, err := s.runner.Run(ctx, spec); err != nil {
		if errors.Is(err, taskrunner.ErrExpired) {
			return nil, fmt.Errorf("%w: other changes to the tenant held the deletion of %q", auth.ErrTemporarilyUnavailable, authz.BucketName)
		}
		return nil, fmt.Errorf("deleting bucket %q: %w", authz.BucketName, err)
	}

	s.logger.Debug("deleted bucket", zap.Stringer("bucket", authz.Bucket.ID), zap.String("name", authz.BucketName))
	return &s3bkt.DeleteOK{}, nil
}

// permissionsUnderStatus reduces the S3 permissions of one of the tenant's
// access keys to those the tenant's status keeps
// ([grant.LimitToTenantStatus]): all of them while it is active, the reads,
// listings and deletions while it is write-locked, none while it is
// disabled. The gateway caches the result beside the key's proof chains and
// decides requests from it without asking again.
//
// Call it after the proof chains it is returned with have been read, or in
// the same snapshot. A status change commits its status with the grants it
// withdraws and issues, so a status read after the chains is at least as new
// as they are, and the pair allows no more than that status does: chains read
// before a change are revoked by it, and a write-locked key's chains, which
// carry commands an upload uses too, are never paired with the permissions of
// an active tenant unless the tenant is active again. Read in one snapshot,
// the two are of one state.
func (s *Service) permissionsUnderStatus(ctx context.Context, tenantID did.DID, permissions []string) ([]string, error) {
	rec, err := s.tenants.Get(ctx, tenantID)
	if err != nil {
		return nil, fmt.Errorf("looking up tenant: %w", err)
	}
	return grant.LimitToTenantStatus(rec.Status, permissions), nil
}

// List authorizes the request (which also verifies the access key holds the
// operation's permission), confirms the request is a ListBuckets operation, and
// returns one page of the tenant's buckets in name order, honouring the
// request's prefix, continuation-token and max-buckets parameters.
func (s *Service) List(ctx context.Context, issuer did.DID, args *s3bkt.ListArguments) (*s3bkt.ListOK, error) {
	authz, err := s.authorizer.Authorize(ctx, issuer, args.Request)
	if err != nil {
		return nil, err
	}
	// Bind the verified signature to this handler's operation: reject a
	// (validly-signed) request for any other S3 operation.
	if authz.Operation != auth.OpListBuckets {
		return nil, fmt.Errorf("%w: %s", ErrOperationMismatch, authz.Operation)
	}

	// The ListBuckets options ride as query parameters on the signed URL, which
	// the verified signature covers in full.
	u, err := url.Parse(args.Request.URL)
	if err != nil {
		return nil, fmt.Errorf("parsing request URL: %w", err)
	}
	query := u.Query()
	prefix := query.Get("prefix")
	token := query.Get("continuation-token")
	max := maxListBuckets
	if v := query.Get("max-buckets"); v != "" {
		max, err = strconv.Atoi(v)
		if err != nil || max < 1 || max > maxListBuckets {
			return nil, fmt.Errorf("%w: max-buckets: %q", ErrInvalidArgument, v)
		}
	}

	listOpts := []bucketstore.ListOption{bucketstore.WithLimit(max)}
	if prefix != "" {
		listOpts = append(listOpts, bucketstore.WithPrefix(prefix))
	}
	if token != "" {
		listOpts = append(listOpts, bucketstore.WithCursor(token))
	}

	// bucket-region narrows the listing to the buckets one region holds. S3 does
	// not answer the parameter from another region's endpoint, so the only
	// region this one answers for is the region the request was signed for,
	// whose provider is already resolved. A bucket records the provider serving
	// it, so the filter is applied in the read: a page is then a page of
	// matches, and the continuation token keeps meaning what it says.
	if region := query.Get("bucket-region"); region != "" {
		if region != authz.Region {
			return nil, fmt.Errorf("%w: bucket-region %q is not the region the request is signed for", ErrInvalidArgument, region)
		}
		listOpts = append(listOpts, bucketstore.WithProvider(authz.Provider.ID))
	}

	page, err := s.buckets.ListByTenant(ctx, authz.Tenant.ID, listOpts...)
	if err != nil {
		return nil, fmt.Errorf("listing buckets: %w", err)
	}

	out := &s3bkt.ListOK{
		Buckets: make([]s3bkt.Bucket, 0, len(page.Results)),
		Prefix:  prefix,
		Owner: s3bkt.Owner{
			DisplayName: "",
			ID:          authz.Tenant.ID.String(),
		},
	}
	if page.Cursor != nil {
		out.ContinuationToken = *page.Cursor
	}
	// A tenant's buckets may span providers; each is reported in the region of
	// the provider serving it, resolved once per provider.
	regions := map[did.DID]string{authz.Provider.ID: authz.Region}
	for _, b := range page.Results {
		region, ok := regions[b.Provider]
		if !ok {
			prov, err := s.providers.Get(ctx, b.Provider)
			if err != nil {
				return nil, fmt.Errorf("looking up provider %s of bucket %q: %w", b.Provider, b.Name, err)
			}
			region = prov.Region
			regions[b.Provider] = region
		}
		out.Buckets = append(out.Buckets, s3bkt.Bucket{
			ARN:          "arn:aws:s3:::" + b.Name,
			Region:       region,
			CreationDate: b.CreatedAt.UTC().Format(time.RFC3339),
			Name:         b.Name,
		})
	}
	return out, nil
}

// Info resolves the named bucket and returns its DID, the access key's permissions,
// and the proof chains for the access key's delegations that reach the bucket.
// It carries no signed S3 request, so there is no signature to authenticate:
// what it checks is the caller, which must be the provider acting for the
// bucket's tenant, and the access key, which must belong to that tenant.
//
// The permissions are those the tenant's status keeps
// ([Service.permissionsUnderStatus]): a write-locked tenant's key is
// reported its reads, listings and deletions, and a disabled tenant's key
// none.
//
// Everything Info reads, it reads in one database snapshot
// ([auth.Authorizer.ReadSnapshot]): the bucket, the key, the principal, the
// policy, the key's grants and their chains, and the tenant's status. A
// change to the tenant that commits while Info reads is seen by none of the
// reads, so the answer is the state before it, whole: the permissions of the
// status and the policy then, with the grants they gave the key, which the
// change has withdrawn and is revoking. The gateway does not keep an answer
// that names a revoked delegation, and drops one when the revocation
// arrives.
func (s *Service) Info(ctx context.Context, issuer did.DID, args *s3bkt.InfoArguments) (*s3bkt.InfoOK, []ucan.Delegation, error) {
	var (
		ok     *s3bkt.InfoOK
		blocks []ucan.Delegation
	)
	err := s.authorizer.ReadSnapshot(ctx, func(ctx context.Context) error {
		var err error
		ok, blocks, err = s.info(ctx, issuer, args)
		return err
	})
	if err != nil {
		return nil, nil, err
	}
	return ok, blocks, nil
}

// info is [Service.Info], reading through ctx.
func (s *Service) info(ctx context.Context, issuer did.DID, args *s3bkt.InfoArguments) (*s3bkt.InfoOK, []ucan.Delegation, error) {
	b, err := s.buckets.GetByName(ctx, args.Name)
	if errors.Is(err, store.ErrRecordNotFound) {
		return nil, nil, fmt.Errorf("%w: %q", ErrUnknownBucket, args.Name)
	} else if err != nil {
		return nil, nil, fmt.Errorf("looking up bucket: %w", err)
	}

	// The proof chains this returns are the bucket tenant's, and a bucket is
	// served by one provider, so the caller must be that provider — the same
	// rule Authorize applies to the signature-bearing commands. A tenant is
	// region-free, so the binding is the bucket's rather than the tenant's.
	if issuer != b.Provider {
		s.logger.Debug("rejecting bucket info not from the bucket's provider",
			zap.Stringer("bucket", b.ID), zap.Stringer("issuer", issuer), zap.Stringer("provider", b.Provider))
		return nil, nil, auth.ErrIssuerForbidden
	}

	akRec, err := s.accessKeys.Get(ctx, args.AccessKey)
	if errors.Is(err, store.ErrRecordNotFound) {
		return nil, nil, fmt.Errorf("%w: %q", ErrUnknownAccessKey, args.AccessKey)
	} else if err != nil {
		return nil, nil, fmt.Errorf("looking up access key: %w", err)
	}
	// An access key only ever reaches the buckets of its own tenant. A key from
	// another tenant learns nothing about this one: the bucket is simply not its
	// tenant's.
	if akRec.Tenant != b.Tenant {
		s.logger.Debug("rejecting access key from another tenant",
			zap.Stringer("bucket", b.ID), zap.Stringer("accessKey", args.AccessKey))
		return nil, nil, auth.ErrForeignBucket
	}

	// A service key carries its own permission set; a principal-bound key its
	// principal's effective actions on the bucket, whose stored grants over the
	// bucket are the commands those actions map to. A removed principal is an
	// unknown key, and a bucket the principal cannot reach is unknown.
	permissions := akRec.Permissions
	if akRec.Principal != nil {
		eff, err := s.authorizer.EffectiveActions(ctx, b.Tenant, *akRec.Principal, b.ID)
		if errors.Is(err, auth.ErrUnknownAccessKey) {
			return nil, nil, fmt.Errorf("%w: %s outlived its principal", ErrUnknownAccessKey, akRec.ID)
		} else if err != nil {
			return nil, nil, err
		}
		if len(eff) == 0 {
			return nil, nil, fmt.Errorf("%w: %q is not within the principal's reach", ErrUnknownBucket, b.Name)
		}
		permissions = eff
	}

	// Build the proof chains from the bucket to the access key: for each grant to
	// the access key that reaches this bucket (scoped to it or powerline), resolve
	// its chain up to the bucket→tenant root.
	stored, err := store.Collect(ctx, func(ctx context.Context, opts store.PaginationConfig) (store.Page[ucan.Delegation], error) {
		var o []store.PaginationOption
		if opts.Cursor != nil {
			o = append(o, store.WithCursor(*opts.Cursor))
		}
		return s.delegations.ListByAudience(ctx, args.AccessKey, o...)
	})
	if err != nil {
		return nil, nil, fmt.Errorf("listing delegations: %w", err)
	}
	// An expired grant stays stored until it is deleted, and is in no chain.
	now := ucan.Now()
	stored = slices.DeleteFunc(stored, func(d ucan.Delegation) bool {
		return d.Subject().Defined() && d.Subject() != b.ID || validator.ValidateNotExpired(d, now) != nil
	})

	proofSet := map[cid.Cid][]cid.Cid{}
	var blocks []ucan.Delegation
	seen := map[string]bool{}
	for _, d := range stored {
		proofs, links, err := s.delegations.ProofChain(ctx, args.AccessKey, d.Command(), b.ID)
		if err != nil {
			return nil, nil, fmt.Errorf("building proof chain for %s: %w", d.Command(), err)
		}
		if len(proofs) == 0 {
			continue
		}
		proofSet[d.Link()] = links
		for _, p := range proofs {
			if k := p.Link().String(); !seen[k] {
				seen[k] = true
				blocks = append(blocks, p)
			}
		}
	}

	permissions, err = s.permissionsUnderStatus(ctx, b.Tenant, permissions)
	if err != nil {
		return nil, nil, err
	}

	s.logger.Debug("bucket info",
		zap.Stringer("bucket", b.ID),
		zap.String("name", args.Name),
		zap.Int("delegations", len(proofSet)),
	)
	return &s3bkt.InfoOK{
		ID: b.ID,
		Permissions: s3.PermissionSet{Entries: map[did.DID][]string{
			args.AccessKey: permissions,
		}},
		Delegations: s3.ProofSet{Entries: proofSet},
	}, blocks, nil
}
