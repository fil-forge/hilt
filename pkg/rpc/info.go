package rpc

import (
	bucketsvc "github.com/fil-forge/hilt/pkg/rpc/service/bucket"
	s3bkt "github.com/fil-forge/libforge/commands/s3/bucket"
	"github.com/fil-forge/ucantone/binding"
	"github.com/fil-forge/ucantone/server"
	"github.com/fil-forge/ucantone/ucan/container"
	"go.uber.org/zap"
)

// NewBucketInfoHandler handles /s3/bucket/info — look up a bucket by name and
// return its DID, the access key's S3 permissions, and the delegation proof
// chain(s) from the bucket to that access key. It is a lookup: it carries no
// signed S3 request, so it neither authenticates a signature nor checks the
// invocation issuer.
func NewBucketInfoHandler(logger *zap.Logger, buckets *bucketsvc.Service) server.Route {
	log := logger.With(zap.Stringer("command", s3bkt.Info.Command))
	return s3bkt.Info.Route(func(req *binding.Request[*s3bkt.InfoArguments], res *binding.Response[*s3bkt.InfoOK]) error {
		ok, dlgs, err := buckets.Info(req.Context(), req.Task().Arguments())
		if err != nil {
			log.Error("bucket info failed", zap.Error(err))
			return bucketFailure(res, err)
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
