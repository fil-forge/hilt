package rpc

import (
	"context"
	"errors"
	"fmt"

	"github.com/fil-forge/hilt/pkg/store"
	"github.com/fil-forge/hilt/pkg/store/accesskey"
	"github.com/fil-forge/hilt/pkg/store/bucket"
	delegationstore "github.com/fil-forge/hilt/pkg/store/delegation"
	s3 "github.com/fil-forge/libforge/commands/s3"
	s3bkt "github.com/fil-forge/libforge/commands/s3/bucket"
	"github.com/fil-forge/ucantone/binding"
	"github.com/fil-forge/ucantone/did"
	"github.com/fil-forge/ucantone/server"
	"github.com/fil-forge/ucantone/ucan"
	"github.com/fil-forge/ucantone/ucan/container"
	"github.com/ipfs/go-cid"
	"go.uber.org/zap"
)

// NewBucketInfoHandler handles /s3/bucket/info — look up a bucket by name and
// return its DID, the access key's S3 permissions, and the delegation proof
// chain(s) from the bucket to that access key. It is a lookup: it carries no
// signed S3 request, so it neither authenticates a signature nor checks the
// invocation issuer.
func NewBucketInfoHandler(
	logger *zap.Logger,
	buckets bucket.Store,
	accessKeys accesskey.Store,
	delegations delegationstore.Store,
) server.Route {
	log := logger.With(zap.Stringer("command", s3bkt.Info.Command))
	return s3bkt.Info.Route(func(req *binding.Request[*s3bkt.InfoArguments], res *binding.Response[*s3bkt.InfoOK]) error {
		ok, dlgs, err := BucketInfo(req.Context(), log, buckets, accessKeys, delegations, req.Task().Arguments())
		if err != nil {
			log.Error("bucket info failed", zap.Error(err))
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

// BucketInfo resolves the named bucket and returns its DID, the access key's
// permissions, and the proof chains for the access key's delegations that reach
// the bucket. It is factored out of the handler so it can be unit tested without
// a UCAN invocation.
func BucketInfo(
	ctx context.Context,
	logger *zap.Logger,
	buckets bucket.Store,
	accessKeys accesskey.Store,
	delegations delegationstore.Store,
	args *s3bkt.InfoArguments,
) (*s3bkt.InfoOK, []ucan.Delegation, error) {
	b, err := buckets.GetByName(ctx, args.Name)
	if errors.Is(err, store.ErrRecordNotFound) {
		return nil, nil, fmt.Errorf("unknown bucket %q", args.Name)
	} else if err != nil {
		return nil, nil, fmt.Errorf("looking up bucket: %w", err)
	}

	akRec, err := accessKeys.Get(ctx, args.AccessKey)
	if errors.Is(err, store.ErrRecordNotFound) {
		return nil, nil, fmt.Errorf("unknown access key %q", args.AccessKey)
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
		return delegations.ListByAudience(ctx, args.AccessKey, o...)
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
		proofs, links, err := delegations.ProofChain(ctx, args.AccessKey, d.Command(), b.ID)
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

	logger.Debug("bucket info",
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
