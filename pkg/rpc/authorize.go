package rpc

import (
	"context"
	"fmt"
	"slices"
	"time"

	"github.com/fil-forge/hilt/pkg/rpc/service/auth"
	"github.com/fil-forge/hilt/pkg/s3perm"
	"github.com/fil-forge/hilt/pkg/sigv4"
	delegationstore "github.com/fil-forge/hilt/pkg/store/delegation"
	"github.com/fil-forge/libforge/commands/blob"
	s3 "github.com/fil-forge/libforge/commands/s3"
	s3req "github.com/fil-forge/libforge/commands/s3/request"
	"github.com/fil-forge/libforge/commands/upload"
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
	delegations delegationstore.Store,
) server.Route {
	log := logger.With(zap.Stringer("command", s3req.Authorize.Command))
	return s3req.Authorize.Route(func(req *binding.Request[*s3req.AuthorizeArguments], res *binding.Response[*s3req.AuthorizeOK]) error {
		ok, dlgs, err := AuthorizeRequest(req.Context(), log, authorizer, delegations, req.Invocation().Issuer(), req.Task().Arguments())
		if err != nil {
			log.Error("authorize request failed", zap.Error(err))
			return authFailure(res, err)
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

// AuthorizeRequest authenticates the S3 request (which resolves the addressed
// bucket and computes the actions the credential holds on it), derives the
// verification key, and issues delegations for the action's Forge commands to the
// invocation issuer (TTL ≤ 24h + clock skew + AsyncOverhang), signed by the
// credential for either kind of key. The cleanup commands among them are also
// issued by the tenant, lasting CleanupLifetime past the request delegations'
// day, with the bucket's root delegation
// (see issueCleanupDelegations). It returns the result and the delegation
// blocks to attach to the response. It is factored out of the handler so it can
// be unit tested without constructing a UCAN invocation.
func AuthorizeRequest(
	ctx context.Context,
	logger *zap.Logger,
	authorizer *auth.Authorizer,
	delegations delegationstore.Store,
	issuer did.DID,
	args *s3req.AuthorizeArguments,
) (*s3req.AuthorizeOK, []ucan.Delegation, error) {
	authz, err := authorizer.Authorize(ctx, issuer, args.Request)
	if err != nil {
		return nil, nil, err
	}
	accessKeyID := authz.AccessKey.ID

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
	// subject. The key holds these commands over the bucket, a service key from
	// its creation and a principal-bound key from the bucket's policy, which the
	// action check above is the mirror of. If it does not, the delegation simply
	// has no proof chain to a root and is unusable — harmless. The gateway
	// obtains the chain to the access key via `/s3/bucket/info`.
	akIssuer := multikey.NewIssuer(accessKeyID, signer)
	// Expire when the derived key does — 00:00:00 UTC of the following day —
	// plus the max clock skew, so the gateway can still enact a request signed
	// just before midnight but received within the skew window after it, plus
	// the async overhang so work the request set going outlives the boundary.
	// Capped to the access key's own expiry if sooner.
	exp := ucan.UnixTimestamp(nextUTCMidnight(time.Now()).Add(sigv4.MaxClockSkew).Add(AsyncOverhang).Unix())
	if authz.AccessKey.ExpiresAt != nil {
		if capExp := authz.AccessKey.ExpiresAt.Unix(); capExp < int64(exp) {
			exp = ucan.UnixTimestamp(capExp)
		}
	}

	var bucketID *did.DID
	if authz.Bucket != nil {
		bucketID = &authz.Bucket.ID
	}
	// A copy also names the source bucket it was authorized to read, so the
	// gateway can key what it caches for the copy by both bucket DIDs.
	var sourceBucketID *did.DID
	if authz.SourceBucket != nil {
		sourceBucketID = &authz.SourceBucket.ID
	}

	issued, err := issuePermissionDelegations(akIssuer, issuer, bucketID, perm, exp)
	if err != nil {
		return nil, nil, err
	}
	// A copy from another bucket also needs the read commands over the source:
	// the destination grant's retrieve is scoped to the destination. A copy
	// within one bucket is already covered.
	if src := authz.SourceBucket; src != nil && (bucketID == nil || src.ID != *bucketID) {
		srcDlgs, err := issuePermissionDelegations(akIssuer, issuer, &src.ID, authz.SourcePermission, exp)
		if err != nil {
			return nil, nil, err
		}
		issued = append(issued, srcDlgs...)
	}
	// The proof set keys each issued delegation to its own one-element chain.
	proofSet := make(map[cid.Cid][]cid.Cid, len(issued))
	for _, d := range issued {
		proofSet[d.Link()] = []cid.Cid{d.Link()}
	}
	if bucketID != nil {
		cleanup, root, err := issueCleanupDelegations(ctx, authorizer, delegations, authz.Tenant.ID, issuer, *bucketID, perm)
		if err != nil {
			return nil, nil, err
		}
		switch {
		case root != nil:
			// The tenant-issued delegations reach the bucket through its root,
			// so each is keyed to the two-link chain, and the root rides back
			// once with them.
			for _, d := range cleanup {
				proofSet[d.Link()] = []cid.Cid{root.Link(), d.Link()}
			}
			issued = append(issued, cleanup...)
			issued = append(issued, root)
		case hasCleanupCommands(perm):
			logger.Warn("no root delegation for the bucket; issuing no cleanup delegations", zap.Stringer("bucket", bucketID))
		}
	}

	logger.Debug("authorized request",
		zap.Stringer("bucket", bucketID),
		zap.String("permission", perm),
		zap.Int("delegations", len(proofSet)),
	)
	return &s3req.AuthorizeOK{
		Bucket:       bucketID,
		SourceBucket: sourceBucketID,
		Tenant:       authz.Tenant.ID,
		Permissions: s3.PermissionSet{Entries: map[did.DID][]string{
			accessKeyID: authz.Permissions,
		}},
		Keys: s3.KeySet{Entries: map[did.DID][]s3.VerificationKey{
			accessKeyID: {{Kind: kind, Data: key}},
		}},
		Delegations: s3.ProofSet{Entries: proofSet},
	}, issued, nil
}

// cleanupCommands are the Forge commands a gateway runs long after the request
// that caused them: releasing blobs a delete or overwrite left unreferenced,
// abandoning blobs an upload never committed, and retracting a superseded
// version's registration.
var cleanupCommands = []ucan.Command{blob.Remove.Command, blob.Abort.Command, upload.Remove.Command}

// CleanupLifetime is how long the cleanup delegations last, counted from the
// end of the day the gateway reuses them for. The gateway's longest delay
// before a cleanup is the abort of a multipart upload abandoned for a week; a
// day more covers its retries.
const CleanupLifetime = 8 * 24 * time.Hour

// permissionCleanupCommands returns the cleanup commands among the
// permission's commands.
func permissionCleanupCommands(perm string) []ucan.Command {
	var cmds []ucan.Command
	for _, cmd := range s3perm.CommandsFor(perm) {
		if slices.Contains(cleanupCommands, cmd) {
			cmds = append(cmds, cmd)
		}
	}
	return cmds
}

func hasCleanupCommands(perm string) bool { return len(permissionCleanupCommands(perm)) > 0 }

// issueCleanupDelegations issues, for each cleanup command the permission's
// commands include, a delegation from the tenant to audience over the bucket
// that lasts CleanupLifetime past the next UTC midnight plus the max clock
// skew, and returns them with the bucket's root
// delegation, which their chains go through. It issues nothing, and returns
// no root, when the permission has no cleanup commands or the bucket has no
// root.
//
// The access-key-signed delegations expire with the key and with the derived
// signing key at midnight, which is right for authorizing requests but cuts
// short cleanup the gateway schedules for later. These do not pass through
// the access key, so a key that expires, is deleted or is rotated leaves the
// cleanup of work already done able to finish. They grant nothing beyond the
// commands the request was authorized for, over the bucket it addressed. The
// gateway must not let them authorize requests: it accepts a request locally
// only on a chain the access key issued.
func issueCleanupDelegations(ctx context.Context, authorizer *auth.Authorizer, delegations delegationstore.Store, tenantID, audience, bucketID did.DID, perm string) ([]ucan.Delegation, ucan.Delegation, error) {
	cmds := permissionCleanupCommands(perm)
	if len(cmds) == 0 {
		return nil, nil, nil
	}
	chain, _, err := delegations.ProofChain(ctx, tenantID, cmds[0], bucketID)
	if err != nil {
		return nil, nil, fmt.Errorf("finding the bucket's root delegation: %w", err)
	}
	if len(chain) == 0 {
		return nil, nil, nil
	}
	root := chain[0]
	tenant, err := authorizer.TenantIssuer(ctx, tenantID)
	if err != nil {
		return nil, nil, err
	}
	// The gateway keeps using what one authorize returned, without asking
	// again, until the derived key expires at the next UTC midnight, and
	// schedules cleanup for requests it authorized from that cache with the
	// cleanup delegations it already holds. Counting the lifetime from that
	// midnight gives cleanup scheduled at any point in the day its full
	// CleanupLifetime.
	exp := ucan.UnixTimestamp(nextUTCMidnight(time.Now()).Add(sigv4.MaxClockSkew).Add(CleanupLifetime).Unix())
	out := make([]ucan.Delegation, 0, len(cmds))
	for _, cmd := range cmds {
		d, err := delegation.Delegate(tenant, audience, bucketID, cmd, delegation.WithExpiration(exp))
		if err != nil {
			return nil, nil, fmt.Errorf("delegating %s: %w", cmd, err)
		}
		out = append(out, d)
	}
	return out, root, nil
}

// issuePermissionDelegations issues one delegation from issuer to audience for
// each Forge command the S3 permission maps to, over the bucket named by
// subject, expiring at exp. A permission that maps to commands needs a bucket;
// one that maps to none (the bucket-level permissions) issues nothing and
// tolerates a nil subject.
func issuePermissionDelegations(from ucan.Issuer, audience did.DID, subject *did.DID, perm string, exp ucan.UnixTimestamp) ([]ucan.Delegation, error) {
	var out []ucan.Delegation
	for _, cmd := range s3perm.CommandsFor(perm) {
		if subject == nil {
			return nil, fmt.Errorf("delegating %s: missing bucket", cmd)
		}
		d, err := delegation.Delegate(from, audience, *subject, cmd, delegation.WithExpiration(exp))
		if err != nil {
			return nil, fmt.Errorf("delegating %s: %w", cmd, err)
		}
		out = append(out, d)
	}
	return out, nil
}

// AsyncOverhang is how far past the derived key's own life a delegation stays
// usable, so that work a request set going can still be finished after the
// boundary.
//
// Aligning the two is right for authorizing requests: the derived key is
// date-scoped, so the first request after midnight re-authorizes anyway and
// caches a fresh full day of authority. It is wrong for work that outlives the
// request. A gateway queues a write's bookkeeping — registering the object
// with the upload service, releasing a superseded body — and retries it until
// the service takes it. A request authorized at 23:59 would otherwise hold
// minutes of authority to finish hours of work, and the queued change would be
// stuck for good.
//
// The size is set by the longest such retry budget, which is the gateway's
// upload-registration sweep: ten attempts with the backoff capping at thirty
// minutes, so about three hours. Four leaves headroom. A gateway that retries
// for longer than this will see work expire rather than complete, so the two
// have to move together.
const AsyncOverhang = 4 * time.Hour

// nextUTCMidnight returns 00:00:00 UTC of the day after t — when a date-scoped
// SigV4 signing key derived for t's date stops being usable.
func nextUTCMidnight(t time.Time) time.Time {
	t = t.UTC()
	return time.Date(t.Year(), t.Month(), t.Day(), 0, 0, 0, 0, time.UTC).AddDate(0, 0, 1)
}
