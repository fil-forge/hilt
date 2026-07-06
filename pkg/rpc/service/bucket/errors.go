package bucket

import "github.com/fil-forge/ucantone/errors"

// Error names for the bucket service's known errors, exported so callers (e.g.
// Ingot, mapping to canonical S3 error responses) can match on the stable Name()
// of a serialized failure.
const (
	OperationMismatchErrorName = "OperationMismatch"
	BucketExistsErrorName      = "BucketExists"
	BucketNotEmptyErrorName    = "BucketNotEmpty"
	UnknownBucketErrorName     = "UnknownBucket"
	UnknownAccessKeyErrorName  = "UnknownAccessKey"
)

// Known errors returned by the bucket [Service]. Handlers pass these to
// res.SetFailure, and their stable Name() lets Ingot map them to S3 errors;
// anything else is an unexpected (internal) failure. The auth service's own named
// errors propagated from Authorize keep their names.
var (
	// ErrOperationMismatch is returned when the signed request's S3 operation does
	// not match the invoked bucket command (create/delete/list).
	ErrOperationMismatch = errors.New(OperationMismatchErrorName, "request operation does not match the command")
	// ErrBucketExists is returned when creating a bucket whose name already exists.
	ErrBucketExists = errors.New(BucketExistsErrorName, "bucket already exists")
	// ErrBucketNotEmpty is returned when deleting a bucket whose space is not empty.
	ErrBucketNotEmpty = errors.New(BucketNotEmptyErrorName, "bucket is not empty")
	// ErrUnknownBucket is returned when the named bucket does not exist.
	ErrUnknownBucket = errors.New(UnknownBucketErrorName, "unknown bucket")
	// ErrUnknownAccessKey is returned when the access key does not exist.
	ErrUnknownAccessKey = errors.New(UnknownAccessKeyErrorName, "unknown access key")
)
