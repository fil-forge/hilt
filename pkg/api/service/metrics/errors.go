package metrics

import "github.com/fil-forge/ucantone/errors"

// Error names for the metrics service's known errors, exported so callers can
// match on the stable Name() of a serialized failure.
const (
	TenantNotFoundErrorName = "TenantNotFound"
	BucketNotFoundErrorName = "BucketNotFound"
	InvalidRangeErrorName   = "InvalidRange"
	InvalidWindowErrorName  = "InvalidWindow"
)

// Known errors returned by the metrics [Service]. Handlers map these to HTTP
// status codes with errors.Is; anything else is an unexpected (500-class)
// failure.
//
// The upload service names its own failures — an unusable range, a window the
// series cannot be built at, a reading it could not take consistently — and
// those travel back through the client with their names intact, so the handler
// maps them by name rather than through a sentinel here.
var (
	// ErrTenantNotFound is returned when no tenant exists for the external id.
	ErrTenantNotFound = errors.New(TenantNotFoundErrorName, "tenant not found")
	// ErrBucketNotFound is returned when the tenant holds no bucket of that
	// name. A bucket belonging to another tenant reads the same way, so the
	// response never reveals that it exists.
	ErrBucketNotFound = errors.New(BucketNotFoundErrorName, "bucket not found")
	// ErrInvalidRange is returned when the range is not a non-empty interval.
	ErrInvalidRange = errors.New(InvalidRangeErrorName, "range must be a non-empty interval of RFC 3339 timestamps")
	// ErrInvalidWindow is returned when the window is not a positive number of
	// hours.
	ErrInvalidWindow = errors.New(InvalidWindowErrorName, "window must be a positive number of hours, as <integer>h")
)
