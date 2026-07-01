package rpc

import (
	"context"
	"errors"
	"fmt"
	"slices"

	client "github.com/fil-forge/hilt/pkg/client"
	"github.com/fil-forge/hilt/pkg/rpc/service/auth"
	"github.com/fil-forge/hilt/pkg/store"
	"github.com/fil-forge/hilt/pkg/store/bucket"
	delegationstore "github.com/fil-forge/hilt/pkg/store/delegation"
	s3bkt "github.com/fil-forge/libforge/commands/s3/bucket"
	"github.com/fil-forge/ucantone/binding"
	"github.com/fil-forge/ucantone/did"
	"github.com/fil-forge/ucantone/server"
	"go.uber.org/zap"
)

// SpaceChecker reports whether a bucket's storage space is empty. It is
// satisfied by [*client.UploadClient]; the interface lets the handler logic be
// unit tested without a live Sprue.
type SpaceChecker interface {
	SpaceEmpty(ctx context.Context, space did.DID, opts ...client.UploadClientMethodOption) (bool, error)
}

// NewDeleteBucketHandler handles /s3/bucket/delete — authenticate an AWS S3
// DeleteBucket request, verify the bucket is empty (via Sprue), then remove its
// delegations and record.
func NewDeleteBucketHandler(
	logger *zap.Logger,
	authorizer *auth.Authorizer,
	buckets bucket.Store,
	delegations delegationstore.Store,
	upload *client.UploadClient,
) server.Route {
	log := logger.With(zap.Stringer("command", s3bkt.Delete.Command))
	return s3bkt.Delete.Route(func(req *binding.Request[*s3bkt.DeleteArguments], res *binding.Response[*s3bkt.DeleteOK]) error {
		ok, err := DeleteBucket(req.Context(), log, authorizer, buckets, delegations, upload, req.Invocation().Issuer(), req.Task().Arguments())
		if err != nil {
			log.Error("delete bucket failed", zap.Error(err))
			return res.SetFailure(err)
		}
		return res.SetSuccess(ok)
	})
}

// DeleteBucket authenticates the request, checks the s3:DeleteBucket permission,
// resolves the bucket, verifies its space is empty via Sprue (acting as the
// tenant), then deletes the bucket's delegations (subject == bucket) and the
// bucket record. It is factored out of the handler so it can be unit tested
// without a UCAN invocation.
func DeleteBucket(
	ctx context.Context,
	logger *zap.Logger,
	authorizer *auth.Authorizer,
	buckets bucket.Store,
	delegations delegationstore.Store,
	checker SpaceChecker,
	issuer did.DID,
	args *s3bkt.DeleteArguments,
) (*s3bkt.DeleteOK, error) {
	authz, err := authorizer.Authorize(ctx, issuer, args.Request)
	if err != nil {
		return nil, err
	}

	if !slices.Contains(authz.AccessKey.Permissions, permDeleteBucket) {
		return nil, fmt.Errorf("access key is not permitted to %s", permDeleteBucket)
	}

	// Resolve the addressed bucket.
	target, err := parseS3Target(args.Request.URL)
	if err != nil {
		return nil, err
	}
	b, err := buckets.GetByName(ctx, target.bucket)
	if errors.Is(err, store.ErrRecordNotFound) || (err == nil && b.Tenant != authz.Tenant.ID) {
		return nil, fmt.Errorf("unknown bucket %q", target.bucket)
	} else if err != nil {
		return nil, fmt.Errorf("looking up bucket: %w", err)
	}

	// Verify the bucket is empty, listing its blobs via Sprue as the tenant (the
	// bucket→tenant root delegation authorizes the /blob/list invocation).
	account, err := authorizer.TenantIssuer(ctx, authz.Tenant.ID)
	if err != nil {
		return nil, err
	}
	empty, err := checker.SpaceEmpty(ctx, b.ID, client.WithIssuer(account), client.WithProofs(delegations))
	if err != nil {
		return nil, fmt.Errorf("checking bucket is empty: %w", err)
	}
	if !empty {
		return nil, fmt.Errorf("bucket %q is not empty", target.bucket)
	}

	// TODO: revoke the delegations where subject == bucket, so that the bucket's
	// delegations cannot be used after deletion.

	// Remove the bucket's delegations (subject == bucket), then the record.
	if err := delegations.DeleteBySubject(ctx, b.ID); err != nil {
		return nil, fmt.Errorf("deleting bucket delegations: %w", err)
	}
	if err := buckets.Delete(ctx, b.ID); err != nil {
		return nil, fmt.Errorf("deleting bucket: %w", err)
	}

	logger.Debug("deleted bucket", zap.Stringer("bucket", b.ID), zap.String("name", target.bucket))
	return &s3bkt.DeleteOK{}, nil
}
