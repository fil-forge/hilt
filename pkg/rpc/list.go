package rpc

import (
	"context"
	"fmt"
	"slices"
	"time"

	"github.com/fil-forge/hilt/pkg/store"
	"github.com/fil-forge/hilt/pkg/store/accesskey"
	"github.com/fil-forge/hilt/pkg/store/bucket"
	"github.com/fil-forge/hilt/pkg/store/provider"
	"github.com/fil-forge/hilt/pkg/store/tenant"
	"github.com/fil-forge/hilt/pkg/vault"
	s3bkt "github.com/fil-forge/libforge/commands/s3/bucket"
	"github.com/fil-forge/ucantone/binding"
	"github.com/fil-forge/ucantone/did"
	"github.com/fil-forge/ucantone/server"
	"go.uber.org/zap"
)

// permListAllMyBuckets is the S3 permission required to list a tenant's buckets.
const permListAllMyBuckets = "s3:ListAllMyBuckets"

// NewListBucketsHandler handles /s3/bucket/list — list the tenant's buckets. The
// caller is identified and authenticated by the access key in the request's
// SigV4/SigV4a signature.
func NewListBucketsHandler(
	logger *zap.Logger,
	accessKeys accesskey.Store,
	tenants tenant.Store,
	buckets bucket.Store,
	providers provider.Store,
	secrets vault.Vault,
) server.Route {
	log := logger.With(zap.Stringer("command", s3bkt.List.Command))
	return s3bkt.List.Route(func(req *binding.Request[*s3bkt.ListArguments], res *binding.Response[*s3bkt.ListOK]) error {
		ok, err := ListBuckets(req.Context(), log, accessKeys, tenants, buckets, providers, secrets, req.Invocation().Issuer(), req.Task().Arguments())
		if err != nil {
			log.Error("list buckets failed", zap.Error(err))
			return res.SetFailure(err)
		}
		return res.SetSuccess(ok)
	})
}

// ListBuckets authorizes the request (see [Authorize]), checks the
// s3:ListAllMyBuckets permission, and returns the tenant's buckets. It is
// factored out of the handler so it can be unit tested without constructing a
// UCAN invocation.
func ListBuckets(
	ctx context.Context,
	logger *zap.Logger,
	accessKeys accesskey.Store,
	tenants tenant.Store,
	buckets bucket.Store,
	providers provider.Store,
	secrets vault.Vault,
	issuer did.DID,
	args *s3bkt.ListArguments,
) (*s3bkt.ListOK, error) {
	auth, err := Authorize(ctx, logger, accessKeys, tenants, providers, secrets, issuer, args.Request)
	if err != nil {
		return nil, err
	}
	if !slices.Contains(auth.AccessKey.Permissions, permListAllMyBuckets) {
		return nil, fmt.Errorf("access key is not permitted to %s", permListAllMyBuckets)
	}

	recs, err := store.Collect(ctx, func(ctx context.Context, opts store.PaginationConfig) (store.Page[bucket.Record], error) {
		var listOpts []bucket.ListOption
		if opts.Cursor != nil {
			listOpts = append(listOpts, bucket.WithCursor(*opts.Cursor))
		}
		return buckets.ListByTenant(ctx, auth.Tenant.ID, listOpts...)
	})
	if err != nil {
		return nil, fmt.Errorf("listing buckets: %w", err)
	}

	out := &s3bkt.ListOK{
		Buckets: make([]s3bkt.Bucket, 0, len(recs)),
		Owner: s3bkt.Owner{
			DisplayName: auth.Tenant.Name,
			ID:          auth.Tenant.ID.String(),
		},
	}
	for _, b := range recs {
		out.Buckets = append(out.Buckets, s3bkt.Bucket{
			ARN:          "arn:aws:s3:::" + b.Name,
			Region:       auth.Region,
			CreationDate: b.CreatedAt.UTC().Format(time.RFC3339),
			Name:         b.Name,
		})
	}
	return out, nil
}
