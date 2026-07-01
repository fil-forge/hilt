package rpc

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/fil-forge/hilt/pkg/rpc/service/auth"
	"github.com/fil-forge/hilt/pkg/s3perm"
	"github.com/fil-forge/hilt/pkg/sigv4"
	"github.com/fil-forge/hilt/pkg/store"
	"github.com/fil-forge/hilt/pkg/store/bucket"
	s3 "github.com/fil-forge/libforge/commands/s3"
	s3req "github.com/fil-forge/libforge/commands/s3/request"
	"github.com/fil-forge/ucantone/binding"
	"github.com/fil-forge/ucantone/did"
	"github.com/fil-forge/ucantone/multikey"
	"github.com/fil-forge/ucantone/server"
	"github.com/fil-forge/ucantone/ucan"
	"github.com/fil-forge/ucantone/ucan/container"
	"github.com/fil-forge/ucantone/ucan/delegation"
	"github.com/ipfs/go-cid"
	"go.uber.org/zap"
)

// S3 permissions checked against the access key for the requested action.
const (
	permGetObject    = "s3:GetObject"
	permPutObject    = "s3:PutObject"
	permDeleteObject = "s3:DeleteObject"
	permListBucket   = "s3:ListBucket"
	permCreateBucket = "s3:CreateBucket"
	permDeleteBucket = "s3:DeleteBucket"
)

// NewAuthorizeRequestHandler handles /s3/request/authorize — authenticate an AWS
// S3 request, derive the verification key the gateway needs, and issue delegations
// for the requested action's Forge commands to the invocation issuer.
func NewAuthorizeRequestHandler(
	logger *zap.Logger,
	authorizer *auth.Authorizer,
	buckets bucket.Store,
) server.Route {
	log := logger.With(zap.Stringer("command", s3req.Authorize.Command))
	return s3req.Authorize.Route(func(req *binding.Request[*s3req.AuthorizeArguments], res *binding.Response[*s3req.AuthorizeOK]) error {
		ok, dlgs, err := AuthorizeRequest(req.Context(), log, authorizer, buckets, req.Invocation().Issuer(), req.Task().Arguments())
		if err != nil {
			log.Error("authorize request failed", zap.Error(err))
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

// AuthorizeRequest authenticates the S3 request, resolves the addressed bucket,
// checks the access key's permission for the action, derives the verification
// key, and issues delegations for the action's Forge commands to the invocation
// issuer (TTL ≤ 24h). It returns the result and the delegation blocks to attach
// to the response. It is factored out of the handler so it can be unit tested
// without constructing a UCAN invocation.
func AuthorizeRequest(
	ctx context.Context,
	logger *zap.Logger,
	authorizer *auth.Authorizer,
	buckets bucket.Store,
	issuer did.DID,
	args *s3req.AuthorizeArguments,
) (*s3req.AuthorizeOK, []ucan.Delegation, error) {
	authz, err := authorizer.Authorize(ctx, issuer, args.Request)
	if err != nil {
		return nil, nil, err
	}
	accessKeyID := authz.AccessKey.ID

	// Resolve the addressed bucket and confirm the access key may use it.
	target, err := parseS3Target(args.Request.URL)
	if err != nil {
		return nil, nil, err
	}
	b, err := buckets.GetByName(ctx, target.bucket)
	if errors.Is(err, store.ErrRecordNotFound) || (err == nil && b.Tenant != authz.Tenant.ID) {
		return nil, nil, fmt.Errorf("unknown bucket %q", target.bucket)
	} else if err != nil {
		return nil, nil, fmt.Errorf("looking up bucket: %w", err)
	}
	if len(authz.AccessKey.Buckets) > 0 && !slices.Contains(authz.AccessKey.Buckets, b.ID) {
		return nil, nil, fmt.Errorf("access key is not permitted to use bucket %q", target.bucket)
	}

	// Verify the access key holds the permission required for the requested action.
	perm, err := requiredPermission(args.Request.Method, target.key != "")
	if err != nil {
		return nil, nil, err
	}
	if !slices.Contains(authz.AccessKey.Permissions, perm) {
		return nil, nil, fmt.Errorf("access key is not permitted to %s", perm)
	}

	// Derive the verification key the gateway uses to validate request signatures.
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

	// Issue a delegation to the invocation issuer (the gateway) for each Forge
	// command the action maps to, signing as the access key with the bucket as
	// subject. We assume the access key already holds these commands (delegated at
	// access-key creation); if not, the delegation simply has no proof chain to a
	// root and is unusable — harmless. The gateway obtains the chain to the
	// access key via `/s3/bucket/info`.
	akIssuer := multikey.NewIssuer(accessKeyID, signer)
	// Expire when the derived key does: 00:00:00 UTC of the following day (≤24h,
	// satisfying the RFC TTL), capped to the access key's own expiry if sooner.
	exp := ucan.UnixTimestamp(nextUTCMidnight(time.Now()).Unix())
	if authz.AccessKey.ExpiresAt != nil {
		if capExp := authz.AccessKey.ExpiresAt.Unix(); capExp < int64(exp) {
			exp = ucan.UnixTimestamp(capExp)
		}
	}

	proofSet := map[cid.Cid][]cid.Cid{}
	var blocks []ucan.Delegation
	for _, cmd := range s3perm.CommandsFor(perm) {
		reDel, err := delegation.Delegate(akIssuer, issuer, b.ID, cmd, delegation.WithExpiration(exp))
		if err != nil {
			return nil, nil, fmt.Errorf("delegating %s: %w", cmd, err)
		}
		proofSet[reDel.Link()] = []cid.Cid{reDel.Link()}
		blocks = append(blocks, reDel)
	}

	logger.Debug("authorized request",
		zap.Stringer("bucket", b.ID),
		zap.String("permission", perm),
		zap.Int("delegations", len(proofSet)),
	)
	return &s3req.AuthorizeOK{
		Bucket: b.ID,
		Permissions: s3.PermissionSet{Entries: map[did.DID][]string{
			accessKeyID: authz.AccessKey.Permissions,
		}},
		Keys: s3.KeySet{Entries: map[did.DID][]s3.VerificationKey{
			accessKeyID: {{Kind: kind, Data: key}},
		}},
		Delegations: s3.ProofSet{Entries: proofSet},
	}, blocks, nil
}

// nextUTCMidnight returns 00:00:00 UTC of the day after t — when a date-scoped
// SigV4 signing key derived for t's date stops being usable.
func nextUTCMidnight(t time.Time) time.Time {
	t = t.UTC()
	return time.Date(t.Year(), t.Month(), t.Day(), 0, 0, 0, 0, time.UTC).AddDate(0, 0, 1)
}

// s3Target identifies the bucket and object key addressed by an S3 request. key
// is empty for bucket-level operations.
type s3Target struct {
	bucket string
	key    string
}

// parseS3Target extracts the bucket and object key from an S3 request URL using
// path-style addressing (https://<host>/<bucket>/<key...>), which is what Ingot
// uses. The path is part of the SigV4-signed canonical request, so it is
// authenticated by the time this runs.
//
// Virtual-hosted-style (bucket as the host's leftmost label) can be added here
// when Ingot adopts it — gated on a configured service endpoint domain so the two
// styles can be told apart reliably.
func parseS3Target(rawURL string) (s3Target, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return s3Target{}, fmt.Errorf("parsing request URL: %w", err)
	}
	bucket, key, _ := strings.Cut(strings.TrimPrefix(u.EscapedPath(), "/"), "/")
	if bucket == "" {
		return s3Target{}, errors.New("request URL has no bucket in its path")
	}
	return s3Target{bucket: bucket, key: key}, nil
}

// requiredPermission maps an S3 request (method + whether it addresses an object)
// to the S3 permission the access key must hold. It covers the core operations;
// finer-grained actions can be added as needed.
func requiredPermission(method string, hasObject bool) (string, error) {
	switch strings.ToUpper(method) {
	case http.MethodGet, http.MethodHead:
		if hasObject {
			return permGetObject, nil
		}
		return permListBucket, nil
	case http.MethodPut, http.MethodPost:
		if hasObject {
			return permPutObject, nil
		}
		return permCreateBucket, nil
	case http.MethodDelete:
		if hasObject {
			return permDeleteObject, nil
		}
		return permDeleteBucket, nil
	default:
		return "", fmt.Errorf("unsupported S3 method %q", method)
	}
}
