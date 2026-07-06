package rpc

import (
	bucketsvc "github.com/fil-forge/hilt/pkg/rpc/service/bucket"
	s3bkt "github.com/fil-forge/libforge/commands/s3/bucket"
	"github.com/fil-forge/ucantone/binding"
	"github.com/fil-forge/ucantone/server"
	"go.uber.org/zap"
)

// NewListBucketsHandler handles /s3/bucket/list — list the tenant's buckets. The
// caller is identified and authenticated by the access key in the request's
// SigV4/SigV4a signature.
func NewListBucketsHandler(logger *zap.Logger, buckets *bucketsvc.Service) server.Route {
	log := logger.With(zap.Stringer("command", s3bkt.List.Command))
	return s3bkt.List.Route(func(req *binding.Request[*s3bkt.ListArguments], res *binding.Response[*s3bkt.ListOK]) error {
		ok, err := buckets.List(req.Context(), req.Invocation().Issuer(), req.Task().Arguments())
		if err != nil {
			log.Error("list buckets failed", zap.Error(err))
			return bucketFailure(res, err)
		}
		return res.SetSuccess(ok)
	})
}
