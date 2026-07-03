package rpc

import (
	"context"
	"fmt"
	"time"

	"github.com/fil-forge/hilt/pkg/rpc/service/auth"
	"github.com/fil-forge/hilt/pkg/s3perm"
	"github.com/fil-forge/hilt/pkg/sigv4"
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

// NewAuthorizeRequestHandler handles /s3/request/authorize — authenticate an AWS
// S3 request, derive the verification key the gateway needs, and issue delegations
// for the requested action's Forge commands to the invocation issuer.
func NewAuthorizeRequestHandler(
	logger *zap.Logger,
	authorizer *auth.Authorizer,
) server.Route {
	log := logger.With(zap.Stringer("command", s3req.Authorize.Command))
	return s3req.Authorize.Route(func(req *binding.Request[*s3req.AuthorizeArguments], res *binding.Response[*s3req.AuthorizeOK]) error {
		ok, dlgs, err := AuthorizeRequest(req.Context(), log, authorizer, req.Invocation().Issuer(), req.Task().Arguments())
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

// AuthorizeRequest authenticates the S3 request (which resolves and scope-checks
// the addressed bucket and the access key's permission for the action), derives the
// verification key, and mints delegations for the action's Forge commands to the
// invocation issuer (TTL ≤ 24h). It returns the result and the delegation blocks to
// attach to the response. It is factored out of the handler so it can be unit
// tested without constructing a UCAN invocation.
func AuthorizeRequest(
	ctx context.Context,
	logger *zap.Logger,
	authorizer *auth.Authorizer,
	issuer did.DID,
	args *s3req.AuthorizeArguments,
) (*s3req.AuthorizeOK, []ucan.Delegation, error) {
	authz, err := authorizer.Authorize(ctx, issuer, args.Request)
	if err != nil {
		return nil, nil, err
	}
	accessKeyID := authz.AccessKey.ID

	// Authorize resolved and scope-checked the addressed bucket; the gateway path
	// only handles requests that operate on a bucket.
	if authz.Bucket == nil {
		return nil, nil, fmt.Errorf("request does not address a bucket")
	}
	b := authz.Bucket

	// Authorize also verified the access key holds the operation's permission; the
	// permission drives which Forge commands to re-delegate.
	perm := authz.Operation.Permission()

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
