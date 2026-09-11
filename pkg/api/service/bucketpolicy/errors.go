package bucketpolicy

import "github.com/fil-forge/ucantone/errors"

// Error names for the policy service's known errors, exported so callers can
// match on the stable Name() of a serialized failure.
const (
	TenantNotFoundErrorName     = "TenantNotFound"
	BucketNotFoundErrorName     = "BucketNotFound"
	PolicyNotFoundErrorName     = "PolicyNotFound"
	PrincipalNotFoundErrorName  = "PrincipalNotFound"
	InvalidPreconditionName     = "InvalidPrecondition"
	PreconditionFailedErrorName = "PreconditionFailed"
	ConcurrentChangeErrorName   = "ConcurrentChange"
)

// Known errors returned by the policy [Service]. Handlers map these to HTTP
// status codes with errors.Is; a policy the caller may not store is reported
// as an error wrapping [bucketpolicy.ErrInvalidPolicy], and anything else is an
// unexpected (500-class) failure.
var (
	// ErrTenantNotFound is returned when no tenant exists for the external id.
	ErrTenantNotFound = errors.New(TenantNotFoundErrorName, "tenant not found")
	// ErrBucketNotFound is returned when the tenant has no bucket with that
	// name. A bucket owned by another tenant is reported the same way.
	ErrBucketNotFound = errors.New(BucketNotFoundErrorName, "bucket not found")
	// ErrPolicyNotFound is returned when the bucket exists and has no policy.
	// It is distinct from [ErrBucketNotFound] so a caller can tell a bucket it
	// may not see from one no principal reaches yet.
	ErrPolicyNotFound = errors.New(PolicyNotFoundErrorName, "bucket has no policy")
	// ErrPrincipalNotFound is returned when the tenant has no principal with
	// that userId.
	ErrPrincipalNotFound = errors.New(PrincipalNotFoundErrorName, "principal not found")
	// ErrInvalidPrecondition is returned when the request carries neither
	// If-Match nor If-None-Match: *, or carries both, or carries an
	// If-None-Match other than *. Every write to a policy states the version it
	// expects.
	ErrInvalidPrecondition = errors.New(InvalidPreconditionName,
		"a policy write must carry either If-Match with the current ETag or If-None-Match: *")
	// ErrPreconditionFailed is returned when the bucket's policy is not in the
	// state the request conditioned on. Nothing is written.
	ErrPreconditionFailed = errors.New(PreconditionFailedErrorName, "the bucket's policy has changed")
	// ErrConcurrentChange is returned when another write held a lock this call
	// gave up waiting for. Nothing was written and the call can be repeated.
	ErrConcurrentChange = errors.New(ConcurrentChangeErrorName, "the policy is being changed concurrently, retry the request")
)
