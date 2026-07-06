package rpc

import (
	bucketsvc "github.com/fil-forge/hilt/pkg/rpc/service/bucket"
	s3bkt "github.com/fil-forge/libforge/commands/s3/bucket"
	s3req "github.com/fil-forge/libforge/commands/s3/request"
	"github.com/fil-forge/ucantone/binding"
	"github.com/fil-forge/ucantone/server"
	"github.com/fil-forge/ucantone/ucan/container"
	"go.uber.org/zap"
)

// NewCreateBucketHandler handles /s3/bucket/create — authenticate an AWS S3
// CreateBucket request, create the bucket (and its bucket→tenant root delegation),
// provision its space with Sprue, and return the bucket DID with the delegation
// chains that now grant the access key access to it.
func NewCreateBucketHandler(logger *zap.Logger, buckets *bucketsvc.Service) server.Route {
	log := logger.With(zap.Stringer("command", s3bkt.Create.Command))
	return s3bkt.Create.Route(func(req *binding.Request[*s3bkt.CreateArguments], res *binding.Response[*s3req.AuthorizeOK]) error {
		ok, dlgs, err := buckets.Create(req.Context(), req.Invocation().Issuer(), req.Task().Arguments())
		if err != nil {
			log.Error("create bucket failed", zap.Error(err))
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
