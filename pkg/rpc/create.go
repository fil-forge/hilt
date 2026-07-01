package rpc

import (
	"context"
	"errors"
	"fmt"
	"slices"

	client "github.com/fil-forge/hilt/pkg/client"
	"github.com/fil-forge/hilt/pkg/rpc/service/auth"
	"github.com/fil-forge/hilt/pkg/sigv4"
	"github.com/fil-forge/hilt/pkg/store"
	"github.com/fil-forge/hilt/pkg/store/bucket"
	delegationstore "github.com/fil-forge/hilt/pkg/store/delegation"
	s3 "github.com/fil-forge/libforge/commands/s3"
	s3bkt "github.com/fil-forge/libforge/commands/s3/bucket"
	s3req "github.com/fil-forge/libforge/commands/s3/request"
	"github.com/fil-forge/ucantone/binding"
	"github.com/fil-forge/ucantone/did"
	"github.com/fil-forge/ucantone/multikey"
	"github.com/fil-forge/ucantone/multikey/ed25519"
	"github.com/fil-forge/ucantone/server"
	"github.com/fil-forge/ucantone/ucan"
	"github.com/fil-forge/ucantone/ucan/command"
	"github.com/fil-forge/ucantone/ucan/container"
	"github.com/fil-forge/ucantone/ucan/delegation"
	"github.com/ipfs/go-cid"
	"go.uber.org/zap"
)

// SpaceProvisioner provisions a bucket's storage space with the upload service
// (Sprue). It is satisfied by [*client.UploadClient]; the interface lets the
// handler logic be unit tested without a live Sprue.
type SpaceProvisioner interface {
	ProvisionSpace(ctx context.Context, account ucan.Issuer, space did.DID) (string, error)
}

// NewCreateBucketHandler handles /s3/bucket/create — authenticate an AWS S3
// CreateBucket request, create the bucket (and its bucket→tenant root
// delegation), provision its space with Sprue, and return the bucket DID with
// the delegation chains that now grant the access key access to it.
func NewCreateBucketHandler(
	logger *zap.Logger,
	authorizer *auth.Authorizer,
	buckets bucket.Store,
	delegations delegationstore.Store,
	upload *client.UploadClient,
) server.Route {
	log := logger.With(zap.Stringer("command", s3bkt.Create.Command))
	return s3bkt.Create.Route(func(req *binding.Request[*s3bkt.CreateArguments], res *binding.Response[*s3req.AuthorizeOK]) error {
		ok, dlgs, err := CreateBucket(req.Context(), log, authorizer, buckets, delegations, upload, req.Invocation().Issuer(), req.Task().Arguments())
		if err != nil {
			log.Error("create bucket failed", zap.Error(err))
			return res.SetFailure(err)
		}
		// The delegation map in the result carries only CIDs; the blocks ride back
		// in the response container via the metadata.
		if len(dlgs) > 0 {
			if err := res.SetMetadata(container.New(container.WithDelegations(dlgs...))); err != nil {
				log.Error("attaching delegations", zap.Error(err))
				return err
			}
		}
		return res.SetSuccess(ok)
	})
}

// CreateBucket authenticates the request, checks the s3:CreateBucket permission,
// creates the bucket (an ephemeral bucket key signs a bucket→tenant "top" root
// delegation and is then discarded), provisions the bucket's space with Sprue as
// the tenant, and returns the AuthorizeOK: the new bucket DID, the access key's
// permissions and derived verification key, and the proof chains for the access
// key's powerline delegations (which now reach the new bucket). It is factored
// out of the handler so it can be unit tested without a UCAN invocation.
func CreateBucket(
	ctx context.Context,
	logger *zap.Logger,
	authorizer *auth.Authorizer,
	buckets bucket.Store,
	delegations delegationstore.Store,
	provisioner SpaceProvisioner,
	issuer did.DID,
	args *s3bkt.CreateArguments,
) (*s3req.AuthorizeOK, []ucan.Delegation, error) {
	authz, err := authorizer.Authorize(ctx, issuer, args.Request)
	if err != nil {
		return nil, nil, err
	}
	accessKeyID := authz.AccessKey.ID

	if !slices.Contains(authz.AccessKey.Permissions, permCreateBucket) {
		return nil, nil, fmt.Errorf("access key is not permitted to %s", permCreateBucket)
	}

	// Resolve the bucket name from the request URL and confirm it is free (bucket
	// names are globally unique).
	target, err := parseS3Target(args.Request.URL)
	if err != nil {
		return nil, nil, err
	}
	_, err = buckets.GetByName(ctx, target.bucket)
	if err == nil {
		return nil, nil, fmt.Errorf("bucket %q already exists", target.bucket)
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
	bucketDID := bucketSigner.KeyDID()
	log := logger.With(zap.Stringer("bucket", bucketDID), zap.String("name", target.bucket))

	if err := buckets.Add(ctx, bucketDID, authz.Tenant.ID, target.bucket); err != nil {
		return nil, nil, fmt.Errorf("storing bucket: %w", err)
	}
	// Best-effort rollback of the bucket record on a later failure. The root
	// delegation (if already stored) becomes unreachable — its bucket record is
	// gone — so it is inert; the delegation store has no delete-by-CID.
	rollback := func() {
		if err := buckets.Delete(ctx, bucketDID); err != nil {
			log.Error("rollback: deleting bucket", zap.Error(err))
		}
	}

	// Root delegation: the bucket delegates top authority over itself to the
	// tenant (iss == sub == bucket, aud == tenant).
	root, err := delegation.Delegate(multikey.NewIssuer(bucketDID, bucketSigner), authz.Tenant.ID, bucketDID, command.Top())
	if err != nil {
		rollback()
		return nil, nil, fmt.Errorf("issuing root delegation: %w", err)
	}
	if err := delegations.PutBatch(ctx, []ucan.Delegation{root}); err != nil {
		rollback()
		return nil, nil, fmt.Errorf("storing root delegation: %w", err)
	}

	// Provision the bucket's space with Sprue, acting as the tenant.
	account, err := authorizer.TenantIssuer(ctx, authz.Tenant.ID)
	if err != nil {
		rollback()
		return nil, nil, err
	}
	subscription, err := provisioner.ProvisionSpace(ctx, account, bucketDID)
	if err != nil {
		rollback()
		return nil, nil, fmt.Errorf("provisioning bucket space: %w", err)
	}
	log.Debug("provisioned bucket space", zap.String("subscription", subscription))

	// Derive the verification key the gateway uses to validate the caller's
	// request signatures for this bucket.
	signer, err := authorizer.AccessKeySigner(ctx, authz.AccessKey.Tenant, accessKeyID)
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
		return delegations.ListByAudience(ctx, accessKeyID, o...)
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
		proofs, links, err := delegations.ProofChain(ctx, accessKeyID, d.Command(), bucketDID)
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
		Bucket: bucketDID,
		Permissions: s3.PermissionSet{Entries: map[did.DID][]string{
			accessKeyID: authz.AccessKey.Permissions,
		}},
		Keys: s3.KeySet{Entries: map[did.DID][]s3.VerificationKey{
			accessKeyID: {{Kind: kind, Data: key}},
		}},
		Delegations: s3.ProofSet{Entries: proofSet},
	}, blocks, nil
}
