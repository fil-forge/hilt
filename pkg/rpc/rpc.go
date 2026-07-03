// Package rpc implements the Hilt UCAN RPC API — the S3 commands Ingot invokes
// on Hilt (see the Forge S3 tenant-management RFC). Handlers are exposed as
// [server.Route] values, collected via fx and registered on the UCAN server.
//
// The handlers are currently stubs that report "not implemented"; the bodies
// will be filled in a later pass.
package rpc

import (
	"errors"

	s3bkt "github.com/fil-forge/libforge/commands/s3/bucket"
	s3req "github.com/fil-forge/libforge/commands/s3/request"
	"github.com/fil-forge/ucantone/binding"
	"github.com/fil-forge/ucantone/server"
	"go.uber.org/zap"
)

var errNotImplemented = errors.New("not implemented")

// NewCreateBucketHandler handles /s3/bucket/create — create a bucket and
// provision it with Sprue.
func NewCreateBucketHandler(logger *zap.Logger) server.Route {
	log := logger.With(zap.Stringer("command", s3bkt.Create.Command))
	return s3bkt.Create.Route(func(req *binding.Request[*s3bkt.CreateArguments], res *binding.Response[*s3req.AuthorizeOK]) error {
		log.Debug("not implemented")
		return errNotImplemented
	})
}

// NewDeleteBucketHandler handles /s3/bucket/delete — delete an empty bucket and
// revoke the delegations that grant access to it.
func NewDeleteBucketHandler(logger *zap.Logger) server.Route {
	log := logger.With(zap.Stringer("command", s3bkt.Delete.Command))
	return s3bkt.Delete.Route(func(req *binding.Request[*s3bkt.DeleteArguments], res *binding.Response[*s3bkt.DeleteOK]) error {
		log.Debug("not implemented")
		return errNotImplemented
	})
}

// NewBucketInfoHandler handles /s3/bucket/info — return a bucket DID and the
// delegation chain to the given access key.
func NewBucketInfoHandler(logger *zap.Logger) server.Route {
	log := logger.With(zap.Stringer("command", s3bkt.Info.Command))
	return s3bkt.Info.Route(func(req *binding.Request[*s3bkt.InfoArguments], res *binding.Response[*s3bkt.InfoOK]) error {
		log.Debug("not implemented")
		return errNotImplemented
	})
}
