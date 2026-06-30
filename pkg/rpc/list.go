package rpc

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
	"github.com/fil-forge/hilt/pkg/store/tenant"
	"github.com/fil-forge/hilt/pkg/vault"
	s3bkt "github.com/fil-forge/libforge/commands/s3/bucket"
	"github.com/fil-forge/ucantone/binding"
	"github.com/fil-forge/ucantone/did"
	"github.com/fil-forge/ucantone/multikey/ed25519"
	"github.com/fil-forge/ucantone/server"
	"github.com/multiformats/go-multibase"
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
	secrets vault.Vault,
) server.Route {
	log := logger.With(zap.Stringer("command", s3bkt.List.Command))
	return s3bkt.List.Route(func(req *binding.Request[*s3bkt.ListArguments], res *binding.Response[*s3bkt.ListOK]) error {
		ok, err := ListBuckets(req.Context(), accessKeys, tenants, buckets, secrets, req.Task().Arguments())
		if err != nil {
			log.Error("list buckets failed", zap.Error(err))
			return res.SetFailure(err)
		}
		return res.SetSuccess(ok)
	})
}

// ListBuckets authenticates the request (SigV4/SigV4a) against the access key's
// secret, authorizes it, and returns the tenant's buckets. It is factored out of
// the handler so it can be unit tested without constructing a UCAN invocation.
func ListBuckets(
	ctx context.Context,
	accessKeys accesskey.Store,
	tenants tenant.Store,
	buckets bucket.Store,
	secrets vault.Vault,
	args *s3bkt.ListArguments,
) (*s3bkt.ListOK, error) {
	sr, err := sigv4.Parse(sigv4.Request{
		Method:  args.Request.Method,
		Headers: args.Request.Headers,
		URL:     args.Request.URL,
	})
	if err != nil {
		return nil, fmt.Errorf("parsing request signature: %w", err)
	}

	accessKeyDID, err := did.Parse(did.KeyPrefix + sr.AccessKeyID)
	if err != nil {
		return nil, fmt.Errorf("invalid access key id %q: %w", sr.AccessKeyID, err)
	}

	akRec, err := accessKeys.Get(ctx, accessKeyDID)
	if errors.Is(err, store.ErrRecordNotFound) {
		return nil, fmt.Errorf("unknown access key %q", sr.AccessKeyID)
	} else if err != nil {
		return nil, fmt.Errorf("looking up access key: %w", err)
	}

	// Authenticate: verify the request signature using the access key's secret.
	secret, err := accessKeySecret(ctx, secrets, akRec.Tenant, accessKeyDID)
	if err != nil {
		return nil, err
	}
	if err := sigv4.Verify(sr, secret); err != nil {
		return nil, fmt.Errorf("invalid request signature: %w", err)
	}

	// Authorize.
	if !slices.Contains(akRec.Permissions, permListAllMyBuckets) {
		return nil, fmt.Errorf("access key is not permitted to %s", permListAllMyBuckets)
	}

	tenantRec, err := tenants.Get(ctx, akRec.Tenant)
	if err != nil {
		return nil, fmt.Errorf("looking up tenant: %w", err)
	}

	recs, err := store.Collect(ctx, func(ctx context.Context, opts store.PaginationConfig) (store.Page[bucket.Record], error) {
		var listOpts []bucket.ListOption
		if opts.Cursor != nil {
			listOpts = append(listOpts, bucket.WithCursor(*opts.Cursor))
		}
		return buckets.ListByTenant(ctx, tenantRec.ID, listOpts...)
	})
	if err != nil {
		return nil, fmt.Errorf("listing buckets: %w", err)
	}

	out := &s3bkt.ListOK{
		Buckets: make([]s3bkt.Bucket, 0, len(recs)),
		Owner: s3bkt.Owner{
			DisplayName: tenantRec.Name,
			ID:          tenantRec.ID.String(),
		},
	}
	for _, b := range recs {
		out.Buckets = append(out.Buckets, s3bkt.Bucket{
			ARN:          "arn:aws:s3:::" + b.Name,
			Region:       sr.Region,
			CreationDate: b.CreatedAt.UTC().Format(time.RFC3339),
			Name:         b.Name,
		})
	}
	return out, nil
}

// accessKeySecret reads the access key's private key from the vault and returns
// the multibase base64url secretAccessKey string the client signs with.
func accessKeySecret(ctx context.Context, secrets vault.Vault, tenantDID, accessKeyDID did.DID) (string, error) {
	keyBytes, err := secrets.Read(ctx, vault.AccessKeyPath(tenantDID, accessKeyDID))
	if err != nil {
		return "", fmt.Errorf("reading access key secret: %w", err)
	}
	signer, err := ed25519.Decode(keyBytes)
	if err != nil {
		return "", fmt.Errorf("decoding access key: %w", err)
	}
	secret, err := multibase.Encode(multibase.Base64url, signer.Bytes())
	if err != nil {
		return "", fmt.Errorf("encoding access key secret: %w", err)
	}
	return secret, nil
}
