package bucket

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"github.com/fil-forge/hilt/pkg/store"

	bucketpolicysvc "github.com/fil-forge/hilt/pkg/api/service/bucketpolicy"
	"github.com/fil-forge/hilt/pkg/bucketpolicy"
	"github.com/fil-forge/hilt/pkg/rpc/service/auth"
	"github.com/fil-forge/hilt/pkg/sigv4"
	s3bkt "github.com/fil-forge/libforge/commands/s3/bucket"
	"github.com/fil-forge/ucantone/did"
	"go.uber.org/zap"
)

// Policy serves the three S3 bucket policy operations, which reach Hilt as one
// command: the request's method selects among GetBucketPolicy,
// PutBucketPolicy and DeleteBucketPolicy. The request is authenticated and
// authorized as every bucket operation is; a service key holding the
// operation's permission reaches it, a principal-bound key never does. A PUT's
// body must hash to the request's signed payload hash, so nothing on the path
// can replace the document, and is validated and stored as the policy service
// stores a policy, rotating the affected principals' keys. If-Match and
// If-None-Match, when present, must be signed headers.
func (s *Service) Policy(ctx context.Context, issuer did.DID, args *s3bkt.PolicyArguments) (*s3bkt.PolicyOK, error) {
	authz, err := s.authorizer.Authorize(ctx, issuer, args.Request)
	if err != nil {
		return nil, err
	}
	// The bucket the authorizer resolved and scope-checked, by DID: looking it
	// up again by name could reach a bucket recreated under that name since.
	tenantID, bucketID, name := authz.Tenant.ID, authz.Bucket.ID, authz.BucketName
	log := s.logger.With(zap.Stringer("tenant", authz.Tenant.ID), zap.String("bucket", name), zap.Stringer("operation", authz.Operation))

	switch authz.Operation {
	case auth.OpGetBucketPolicy:
		rec, err := s.policies.Get(ctx, bucketID)
		if errors.Is(err, store.ErrRecordNotFound) {
			return nil, bucketpolicysvc.ErrPolicyNotFound
		} else if err != nil {
			return nil, fmt.Errorf("reading the policy of bucket %q: %w", name, err)
		}
		return &s3bkt.PolicyOK{ETag: rec.ETag, Policy: bucketpolicy.Canonical(rec.Policy)}, nil

	case auth.OpPutBucketPolicy:
		if err := bodyMatchesSignature(authz, args.Body); err != nil {
			return nil, err
		}
		doc, err := bucketpolicy.Decode(args.Body)
		if err != nil {
			return nil, err
		}
		ifMatch, unconditional, err := precondition(authz, args.Request.Headers)
		if err != nil {
			return nil, err
		}
		var opts []bucketpolicysvc.WriteOption
		if unconditional {
			opts = append(opts, bucketpolicysvc.Unconditional())
		}
		etag, _, err := s.policyWrites.Write(ctx, tenantID, bucketID, name, doc, ifMatch, opts...)
		if errors.Is(err, bucketpolicysvc.ErrBucketNotFound) {
			return nil, fmt.Errorf("%w: %q", ErrUnknownBucket, name)
		} else if err != nil {
			return nil, err
		}
		log.Info("wrote bucket policy over S3")
		return &s3bkt.PolicyOK{ETag: etag}, nil

	case auth.OpDeleteBucketPolicy:
		ifMatch, unconditional, err := precondition(authz, args.Request.Headers)
		if err != nil {
			return nil, err
		}
		tag := ""
		switch {
		case unconditional:
		case ifMatch == nil:
			// If-None-Match: * conditions a create; a delete has nothing to create.
			return nil, fmt.Errorf("a DeleteBucketPolicy cannot carry If-None-Match: %w", bucketpolicysvc.ErrInvalidPrecondition)
		default:
			tag = *ifMatch
		}
		if err := s.policyWrites.Remove(ctx, tenantID, bucketID, name, tag); err != nil {
			return nil, err
		}
		log.Info("deleted bucket policy over S3")
		return &s3bkt.PolicyOK{}, nil

	default:
		return nil, fmt.Errorf("%w: %s", ErrOperationMismatch, authz.Operation)
	}
}

// bodyMatchesSignature checks that the PUT's body is the payload the
// signature covers: the request must carry a payload hash (an unsigned
// payload leaves the document open to replacement on the path) and the body
// must hash to it. Either failure is a signature mismatch.
func bodyMatchesSignature(authz *auth.AuthorizedRequest, body []byte) error {
	want := authz.Signed.PayloadHash()
	if want == sigv4.UnsignedPayload {
		return fmt.Errorf("PutBucketPolicy body is not covered by the request signature: %w", auth.ErrSignatureMismatch)
	}
	sum := sha256.Sum256(body)
	if !strings.EqualFold(hex.EncodeToString(sum[:]), want) {
		return fmt.Errorf("PutBucketPolicy body does not match the signed payload hash: %w", auth.ErrSignatureMismatch)
	}
	return nil
}

// precondition reads a policy write's conditional headers. Neither header is
// the unconditional write AWS defines for these operations. If-Match with the
// current ETag replaces or deletes, and If-None-Match: * creates (a nil tag).
// Both headers, an If-None-Match other than *, or a header the signature does
// not cover is [bucketpolicysvc.ErrInvalidPrecondition].
func precondition(authz *auth.AuthorizedRequest, headers map[string]string) (ifMatch *string, unconditional bool, err error) {
	// HeaderValue reads an empty value as absent, which would turn a malformed
	// precondition into an unconditional write; only a header that is not sent
	// at all means unconditional.
	for k, v := range headers {
		if (strings.EqualFold(k, "If-Match") || strings.EqualFold(k, "If-None-Match")) && strings.TrimSpace(v) == "" {
			return nil, false, fmt.Errorf("%s is empty: %w", k, bucketpolicysvc.ErrInvalidPrecondition)
		}
	}
	match, hasMatch := auth.HeaderValue(headers, "If-Match")
	noneMatch, hasNoneMatch := auth.HeaderValue(headers, "If-None-Match")
	for name, present := range map[string]bool{"If-Match": hasMatch, "If-None-Match": hasNoneMatch} {
		if present && !authz.Signed.HeaderSigned(name) {
			return nil, false, fmt.Errorf("%s is not covered by the request signature: %w", name, bucketpolicysvc.ErrInvalidPrecondition)
		}
	}
	switch {
	case !hasMatch && !hasNoneMatch:
		return nil, true, nil
	case hasMatch && hasNoneMatch:
		return nil, false, fmt.Errorf("If-Match and If-None-Match together: %w", bucketpolicysvc.ErrInvalidPrecondition)
	case hasNoneMatch && strings.TrimSpace(noneMatch) != "*":
		return nil, false, fmt.Errorf("If-None-Match must be *: %w", bucketpolicysvc.ErrInvalidPrecondition)
	case hasNoneMatch:
		return nil, false, nil
	default:
		match = strings.TrimSpace(match)
		return &match, false, nil
	}
}
