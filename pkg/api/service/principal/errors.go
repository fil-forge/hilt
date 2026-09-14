package principal

import "github.com/fil-forge/ucantone/errors"

// Error names for the principal service's known errors, exported so callers can
// match on the stable Name() of a serialized failure.
const (
	TenantNotFoundErrorName    = "TenantNotFound"
	PrincipalNotFoundErrorName = "PrincipalNotFound"
	InvalidUserIDErrorName     = "InvalidUserID"
	ConcurrentChangeErrorName  = "ConcurrentChange"
)

// Known errors returned by the principal [Service]. Handlers map these to HTTP
// status codes with errors.Is; anything else is an unexpected (500-class)
// failure.
var (
	// ErrTenantNotFound is returned when no tenant exists for the external id.
	ErrTenantNotFound = errors.New(TenantNotFoundErrorName, "tenant not found")
	// ErrPrincipalNotFound is returned when the tenant has no principal with
	// that userId.
	ErrPrincipalNotFound = errors.New(PrincipalNotFoundErrorName, "principal not found")
	// ErrInvalidUserID is returned when the userId is empty, too long, or the
	// reserved policy wildcard.
	ErrInvalidUserID = errors.New(InvalidUserIDErrorName, `userId must be between 1 and 255 characters and must not be "*", which is reserved for the policy wildcard`)
	// ErrConcurrentChange is returned when another write to the principal or to
	// one of its bucket policies was in flight and this call gave up rather
	// than wait on it. Nothing was changed and the call can be repeated.
	ErrConcurrentChange = errors.New(ConcurrentChangeErrorName, "the principal is being changed concurrently, retry the request")
)
