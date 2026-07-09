package rpc

import (
	"errors"

	"github.com/fil-forge/hilt/pkg/rpc/service/auth"
	bucketsvc "github.com/fil-forge/hilt/pkg/rpc/service/bucket"
)

// failer is the subset of *binding.Response[OK] used to record a receipt failure.
type failer interface{ SetFailure(error) error }

// authFailure records a known auth-service rejection as the invocation's receipt
// failure, so its stable Name() reaches the caller (Ingot maps it to a canonical S3
// error). SetFailure unwraps to find the Name, so the service's %w-wrapped error is
// passed as-is (its full message is preserved). Unknown/internal errors are returned
// unchanged; the dispatcher then reports them as a "HandlerExecutionError".
func authFailure(res failer, err error) error {
	switch {
	case errors.Is(err, auth.ErrMalformedSignature),
		errors.Is(err, auth.ErrInvalidAccessKeyID),
		errors.Is(err, auth.ErrUnknownAccessKey),
		errors.Is(err, auth.ErrSignatureMismatch),
		errors.Is(err, auth.ErrSignatureExpired),
		errors.Is(err, auth.ErrAccessKeyExpired),
		errors.Is(err, auth.ErrTenantDisabled),
		errors.Is(err, auth.ErrIssuerForbidden),
		errors.Is(err, auth.ErrRegionNotServed),
		errors.Is(err, auth.ErrUnsupportedOperation),
		errors.Is(err, auth.ErrOperationNotPermitted),
		errors.Is(err, auth.ErrUnknownBucket),
		errors.Is(err, auth.ErrBucketNotPermitted):
		return res.SetFailure(err)
	default:
		return err
	}
}

// adminFailure records a known admin-command rejection as the receipt failure so
// its stable Name() reaches the caller; other errors are returned unchanged (→
// "HandlerExecutionError").
func adminFailure(res failer, err error) error {
	switch {
	case errors.Is(err, ErrUnauthorized),
		errors.Is(err, ErrProviderExists):
		return res.SetFailure(err)
	default:
		return err
	}
}

// bucketFailure records a known bucket-service rejection, falling through to
// authFailure for the auth rejections the bucket service propagates from Authorize.
func bucketFailure(res failer, err error) error {
	switch {
	case errors.Is(err, bucketsvc.ErrOperationMismatch),
		errors.Is(err, bucketsvc.ErrBucketExists),
		errors.Is(err, bucketsvc.ErrBucketNotEmpty),
		errors.Is(err, bucketsvc.ErrUnknownBucket),
		errors.Is(err, bucketsvc.ErrUnknownAccessKey):
		return res.SetFailure(err)
	default:
		return authFailure(res, err)
	}
}
