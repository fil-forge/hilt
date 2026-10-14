package rpc

import (
	bucketsvc "github.com/fil-forge/hilt/pkg/rpc/service/bucket"
	s3bkt "github.com/fil-forge/libforge/commands/s3/bucket"
	"github.com/fil-forge/ucantone/binding"
	"github.com/fil-forge/ucantone/server"
	"go.uber.org/zap"
)

// NewPolicyHandler handles /s3/bucket/policy — authenticate a forwarded AWS S3
// GetBucketPolicy, PutBucketPolicy or DeleteBucketPolicy request and read,
// write or delete the bucket's policy accordingly.
func NewPolicyHandler(logger *zap.Logger, buckets *bucketsvc.Service) server.Route {
	log := logger.With(zap.Stringer("command", s3bkt.Policy.Command))
	return s3bkt.Policy.Route(func(req *binding.Request[*s3bkt.PolicyArguments], res *binding.Response[*s3bkt.PolicyOK]) error {
		ok, err := buckets.Policy(req.Context(), req.Invocation().Issuer(), req.Task().Arguments())
		if err != nil {
			log.Error("bucket policy operation failed", zap.Error(err))
			return bucketFailure(res, err)
		}
		return res.SetSuccess(ok)
	})
}
