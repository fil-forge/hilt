package rpc

import (
	"context"
	"fmt"
	"time"

	"github.com/fil-forge/hilt/pkg/rpc/service/auth"
	"github.com/fil-forge/hilt/pkg/store"
	"github.com/fil-forge/hilt/pkg/store/bucket"
	s3bkt "github.com/fil-forge/libforge/commands/s3/bucket"
	"github.com/fil-forge/ucantone/binding"
	"github.com/fil-forge/ucantone/did"
	"github.com/fil-forge/ucantone/server"
	"go.uber.org/zap"
)

// NewListBucketsHandler handles /s3/bucket/list — list the tenant's buckets. The
// caller is identified and authenticated by the access key in the request's
// SigV4/SigV4a signature.
func NewListBucketsHandler(
	logger *zap.Logger,
	authorizer *auth.Authorizer,
	buckets bucket.Store,
) server.Route {
	log := logger.With(zap.Stringer("command", s3bkt.List.Command))
	return s3bkt.List.Route(func(req *binding.Request[*s3bkt.ListArguments], res *binding.Response[*s3bkt.ListOK]) error {
		ok, err := ListBuckets(req.Context(), log, authorizer, buckets, req.Invocation().Issuer(), req.Task().Arguments())
		if err != nil {
			log.Error("list buckets failed", zap.Error(err))
			return res.SetFailure(err)
		}
		return res.SetSuccess(ok)
	})
}

// ListBuckets authorizes the request (see [auth.Authorizer.Authorize], which also
// verifies the access key holds the operation's permission), confirms the request
// is a ListBuckets operation, and returns the tenant's buckets. It is factored out
// of the handler so it can be unit tested without constructing a UCAN invocation.
func ListBuckets(
	ctx context.Context,
	logger *zap.Logger,
	authorizer *auth.Authorizer,
	buckets bucket.Store,
	issuer did.DID,
	args *s3bkt.ListArguments,
) (*s3bkt.ListOK, error) {
	authz, err := authorizer.Authorize(ctx, issuer, args.Request)
	if err != nil {
		return nil, err
	}
	// Bind the verified signature to this handler's operation: reject a
	// (validly-signed) request for any other S3 operation.
	if authz.Operation != auth.OpListBuckets {
		return nil, fmt.Errorf("request is not a ListBuckets operation: %s", authz.Operation)
	}

	recs, err := store.Collect(ctx, func(ctx context.Context, opts store.PaginationConfig) (store.Page[bucket.Record], error) {
		var listOpts []bucket.ListOption
		if opts.Cursor != nil {
			listOpts = append(listOpts, bucket.WithCursor(*opts.Cursor))
		}
		return buckets.ListByTenant(ctx, authz.Tenant.ID, listOpts...)
	})
	if err != nil {
		return nil, fmt.Errorf("listing buckets: %w", err)
	}

	out := &s3bkt.ListOK{
		Buckets: make([]s3bkt.Bucket, 0, len(recs)),
		Owner: s3bkt.Owner{
			DisplayName: authz.Tenant.Name,
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
