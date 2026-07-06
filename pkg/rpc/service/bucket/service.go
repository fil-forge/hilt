// Package bucket provides the S3 bucket business logic for the UCAN RPC API:
// create (authenticate + create the bucket, its bucket→tenant root delegation, and
// Sprue space, returning the access key's proof chains), delete (verify empty via
// Sprue, then tear down), list, and info (a lookup returning proof chains). It
// returns the known errors in errors.go so handlers surface stable failure names;
// unexpected failures are returned wrapped.
package bucket

import (
	"context"
	"errors"
	"fmt"
	"time"

	client "github.com/fil-forge/hilt/pkg/client"
	"github.com/fil-forge/hilt/pkg/rpc/service/auth"
	"github.com/fil-forge/hilt/pkg/sigv4"
	"github.com/fil-forge/hilt/pkg/store"
	"github.com/fil-forge/hilt/pkg/store/accesskey"
	bucketstore "github.com/fil-forge/hilt/pkg/store/bucket"
	delegationstore "github.com/fil-forge/hilt/pkg/store/delegation"
	s3 "github.com/fil-forge/libforge/commands/s3"
	s3bkt "github.com/fil-forge/libforge/commands/s3/bucket"
	s3req "github.com/fil-forge/libforge/commands/s3/request"
	"github.com/fil-forge/ucantone/did"
	"github.com/fil-forge/ucantone/multikey"
	"github.com/fil-forge/ucantone/multikey/ed25519"
	"github.com/fil-forge/ucantone/ucan"
	"github.com/fil-forge/ucantone/ucan/command"
	"github.com/fil-forge/ucantone/ucan/delegation"
	"github.com/ipfs/go-cid"
	"go.uber.org/zap"
)

// UploadClient is the subset of the upload service (Sprue) the bucket operations
// need. It is satisfied by [*client.UploadClient]; the interface lets the logic be
// unit tested without a live Sprue.
type UploadClient interface {
	ProvisionSpace(ctx context.Context, account ucan.Issuer, space did.DID) (string, error)
	SpaceEmpty(ctx context.Context, space did.DID, opts ...client.MethodOption) (bool, error)
}

// Service implements the S3 bucket operations shared by the UCAN command handlers.
type Service struct {
	logger      *zap.Logger
	authorizer  *auth.Authorizer
	buckets     bucketstore.Store
	delegations delegationstore.Store
	accessKeys  accesskey.Store
	uploads     UploadClient
}

// New constructs the bucket service.
func New(
	logger *zap.Logger,
	authorizer *auth.Authorizer,
	buckets bucketstore.Store,
	delegations delegationstore.Store,
	accessKeys accesskey.Store,
	uploads UploadClient,
) *Service {
	return &Service{
		logger:      logger,
		authorizer:  authorizer,
		buckets:     buckets,
		delegations: delegations,
		accessKeys:  accessKeys,
		uploads:     uploads,
	}
}

// Create authenticates the request, checks the s3:CreateBucket permission, creates
// the bucket (an ephemeral bucket key signs a bucket→tenant "top" root delegation
// and is then discarded), provisions the bucket's space with Sprue as the tenant,
// and returns the AuthorizeOK: the new bucket DID, the access key's permissions and
// derived verification key, and the proof chains for the access key's powerline
// delegations (which now reach the new bucket).
func (s *Service) Create(ctx context.Context, issuer did.DID, args *s3bkt.CreateArguments) (*s3req.AuthorizeOK, []ucan.Delegation, error) {
	authz, err := s.authorizer.Authorize(ctx, issuer, args.Request)
	if err != nil {
		return nil, nil, err
	}
	accessKeyID := authz.AccessKey.ID

	if authz.Operation != auth.OpCreateBucket {
		return nil, nil, fmt.Errorf("%w: %s", ErrOperationMismatch, authz.Operation)
	}

	_, err = s.buckets.GetByName(ctx, authz.BucketName)
	if err == nil {
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

	if err := s.buckets.Add(ctx, bucketID, authz.Tenant.ID, authz.BucketName); err != nil {
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
	// (iss == sub == bucket, aud == tenant).
	root, err := delegation.Delegate(multikey.NewIssuer(bucketID, bucketSigner), authz.Tenant.ID, bucketID, command.Top())
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

	// Derive the verification key the gateway uses to validate the caller's request
	// signatures for this bucket.
	signer, err := s.authorizer.AccessKeySigner(ctx, authz.AccessKey.Tenant, accessKeyID)
	if err != nil {
		return nil, nil, err
	}
	secret, err := auth.EncodeSecret(signer)
	if err != nil {
		return nil, nil, err
	}
	key, err := sigv4.DeriveKey(authz.Signed, secret)
	if err != nil {
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
		return nil, nil, fmt.Errorf("listing delegations: %w", err)
	}

	proofSet := map[cid.Cid][]cid.Cid{}
	var blocks []ucan.Delegation
	seen := map[string]bool{}
	for _, d := range stored {
		if d.Subject().Defined() {
			continue // only powerline delegations reach a brand-new bucket
		}
		proofs, links, err := s.delegations.ProofChain(ctx, accessKeyID, d.Command(), bucketID)
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

	log.Debug("created bucket", zap.Int("delegations", len(proofSet)))
	return &s3req.AuthorizeOK{
		Bucket: bucketID,
		Permissions: s3.PermissionSet{Entries: map[did.DID][]string{
			accessKeyID: authz.AccessKey.Permissions,
		}},
		Keys: s3.KeySet{Entries: map[did.DID][]s3.VerificationKey{
			accessKeyID: {{Kind: kind, Data: key}},
		}},
		Delegations: s3.ProofSet{Entries: proofSet},
	}, blocks, nil
}

// Delete authenticates the request, checks the s3:DeleteBucket permission, resolves
// the bucket, verifies its space is empty via Sprue (acting as the tenant), then
// deletes the bucket's delegations (subject == bucket) and the bucket record.
func (s *Service) Delete(ctx context.Context, issuer did.DID, args *s3bkt.DeleteArguments) (*s3bkt.DeleteOK, error) {
	authz, err := s.authorizer.Authorize(ctx, issuer, args.Request)
	if err != nil {
		return nil, err
	}

	if authz.Operation != auth.OpDeleteBucket {
		return nil, fmt.Errorf("%w: %s", ErrOperationMismatch, authz.Operation)
	}

	// Verify the bucket is empty, listing its blobs via Sprue as the tenant (the
	// bucket→tenant root delegation authorizes the /blob/list invocation).
	account, err := s.authorizer.TenantIssuer(ctx, authz.Tenant.ID)
	if err != nil {
		return nil, err
	}
	empty, err := s.uploads.SpaceEmpty(ctx, authz.Bucket.ID, client.WithIssuer(account), client.WithProofs(s.delegations))
	if err != nil {
		return nil, fmt.Errorf("checking bucket is empty: %w", err)
	}
	if !empty {
		return nil, fmt.Errorf("%w: %q", ErrBucketNotEmpty, authz.BucketName)
	}

	// TODO: revoke the delegations where subject == bucket, via external revocation
	// service to inform Ingot that these are no longer valid.

	// Remove the bucket's delegations (subject == bucket), then the record.
	if err := s.delegations.DeleteBySubject(ctx, authz.Bucket.ID); err != nil {
		return nil, fmt.Errorf("deleting bucket delegations: %w", err)
	}
	if err := s.buckets.Delete(ctx, authz.Bucket.ID); err != nil {
		return nil, fmt.Errorf("deleting bucket: %w", err)
	}

	s.logger.Debug("deleted bucket", zap.Stringer("bucket", authz.Bucket.ID), zap.String("name", authz.BucketName))
	return &s3bkt.DeleteOK{}, nil
}

// List authorizes the request (which also verifies the access key holds the
// operation's permission), confirms the request is a ListBuckets operation, and
// returns the tenant's buckets.
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

	recs, err := store.Collect(ctx, func(ctx context.Context, opts store.PaginationConfig) (store.Page[bucketstore.Record], error) {
		var listOpts []bucketstore.ListOption
		if opts.Cursor != nil {
			listOpts = append(listOpts, bucketstore.WithCursor(*opts.Cursor))
		}
		return s.buckets.ListByTenant(ctx, authz.Tenant.ID, listOpts...)
	})
	if err != nil {
		return nil, fmt.Errorf("listing buckets: %w", err)
	}

	out := &s3bkt.ListOK{
		Buckets: make([]s3bkt.Bucket, 0, len(recs)),
		Owner: s3bkt.Owner{
			DisplayName: "",
			ID:          authz.Tenant.ID.String(),
		},
	}
	for _, b := range recs {
		out.Buckets = append(out.Buckets, s3bkt.Bucket{
			ARN:          "arn:aws:s3:::" + b.Name,
			Region:       authz.Region,
			CreationDate: b.CreatedAt.UTC().Format(time.RFC3339),
			Name:         b.Name,
		})
	}
	return out, nil
}

// Info resolves the named bucket and returns its DID, the access key's permissions,
// and the proof chains for the access key's delegations that reach the bucket. It
// is a lookup: it carries no signed S3 request, so it neither authenticates a
// signature nor checks the invocation issuer.
func (s *Service) Info(ctx context.Context, args *s3bkt.InfoArguments) (*s3bkt.InfoOK, []ucan.Delegation, error) {
	b, err := s.buckets.GetByName(ctx, args.Name)
	if errors.Is(err, store.ErrRecordNotFound) {
		return nil, nil, fmt.Errorf("%w: %q", ErrUnknownBucket, args.Name)
	} else if err != nil {
		return nil, nil, fmt.Errorf("looking up bucket: %w", err)
	}

	akRec, err := s.accessKeys.Get(ctx, args.AccessKey)
	if errors.Is(err, store.ErrRecordNotFound) {
		return nil, nil, fmt.Errorf("%w: %q", ErrUnknownAccessKey, args.AccessKey)
	} else if err != nil {
		return nil, nil, fmt.Errorf("looking up access key: %w", err)
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

	proofSet := map[cid.Cid][]cid.Cid{}
	var blocks []ucan.Delegation
	seen := map[string]bool{}
	for _, d := range stored {
		if d.Subject().Defined() && d.Subject() != b.ID {
			continue // grant scoped to a different bucket
		}
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

	s.logger.Debug("bucket info",
		zap.Stringer("bucket", b.ID),
		zap.String("name", args.Name),
		zap.Int("delegations", len(proofSet)),
	)
	return &s3bkt.InfoOK{
		ID: b.ID,
		Permissions: s3.PermissionSet{Entries: map[did.DID][]string{
			args.AccessKey: akRec.Permissions,
		}},
		Delegations: s3.ProofSet{Entries: proofSet},
	}, blocks, nil
}
