package principal

import "github.com/fil-forge/ucantone/errors"

// Error names for the principal service's known errors, exported so callers can
// match on the stable Name() of a serialized failure.
const (
	TenantNotFoundErrorName     = "TenantNotFound"
	PrincipalNotFoundErrorName  = "PrincipalNotFound"
	InvalidPrincipalIDErrorName = "InvalidPrincipalID"
)

// Known errors returned by the principal [Service]. Handlers map these to HTTP
// status codes with errors.Is; anything else is an unexpected (500-class)
// failure.
var (
	// ErrTenantNotFound is returned when no tenant exists for the external id.
	ErrTenantNotFound = errors.New(TenantNotFoundErrorName, "tenant not found")
	// ErrPrincipalNotFound is returned when the tenant has no principal with
	// that principalId.
	ErrPrincipalNotFound = errors.New(PrincipalNotFoundErrorName, "principal not found")
	// ErrInvalidPrincipalID is returned when the principalId is not one
	// [ValidID] accepts.
	ErrInvalidPrincipalID = errors.New(InvalidPrincipalIDErrorName, `principalId must be between 1 and 255 bytes of valid UTF-8 without NUL, "/", ";", ",", "?" or "%", and must not be ".", "..", or "*", which is reserved for the policy wildcard`)
)
