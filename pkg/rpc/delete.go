package rpc

import (
	bucketsvc "github.com/fil-forge/hilt/pkg/rpc/service/bucket"
	s3bkt "github.com/fil-forge/libforge/commands/s3/bucket"
	"github.com/fil-forge/ucantone/binding"
	"github.com/fil-forge/ucantone/server"
	"go.uber.org/zap"
)

// NewDeleteBucketHandler handles /s3/bucket/delete — authenticate an AWS S3
// DeleteBucket request, verify the bucket is empty (via Sprue), then remove its
// delegations and record.
func NewDeleteBucketHandler(logger *zap.Logger, buckets *bucketsvc.Service) server.Route {
	log := logger.With(zap.Stringer("command", s3bkt.Delete.Command))
	return s3bkt.Delete.Route(func(req *binding.Request[*s3bkt.DeleteArguments], res *binding.Response[*s3bkt.DeleteOK]) error {
		ok, err := buckets.Delete(req.Context(), req.Invocation().Issuer(), req.Task().Arguments())
		if err != nil {
			log.Error("delete bucket failed", zap.Error(err))
			return bucketFailure(res, err)
		}
		return res.SetSuccess(ok)
	})
}
