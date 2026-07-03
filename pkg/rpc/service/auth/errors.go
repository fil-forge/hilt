package auth

import "github.com/fil-forge/ucantone/errors"

// Error names for the named rejection errors, exported so callers (e.g. Ingot,
// mapping to canonical S3 error responses) can match on the stable Name() of a
// serialized failure.
const (
	MalformedSignatureErrorName = "MalformedSignature"
	InvalidAccessKeyIDErrorName = "InvalidAccessKeyID"
	UnknownAccessKeyErrorName   = "UnknownAccessKey"
	SignatureMismatchErrorName  = "SignatureMismatch"
	SignatureExpiredErrorName   = "SignatureExpired"
	AccessKeyExpiredErrorName   = "AccessKeyExpired"
	TenantDisabledErrorName     = "TenantDisabled"
	IssuerForbiddenErrorName    = "IssuerForbidden"
	RegionNotServedErrorName    = "RegionNotServed"
)

// Named rejection errors returned by [Authorizer.Authorize]. Each is a sentinel
// carrying a stable Name(), wrapped with per-request context at the return site,
// so callers can branch on the reason with errors.Is. Unexpected/internal
// failures (store or vault errors) are intentionally not named — they are
// 500-class, not authorization rejections.
var (
	// ErrMalformedSignature is returned when the request carries no parseable
	// signature — absent entirely, or present but unparseable (unsupported
	// algorithm, malformed credential, incomplete parameters). It is distinct
	// from [ErrSignatureMismatch], which is a cryptographic verification failure.
	ErrMalformedSignature = errors.New(MalformedSignatureErrorName, "request signature is missing or malformed")
	// ErrInvalidAccessKeyID is returned when the credential's access key id is
	// not a valid did:key.
	ErrInvalidAccessKeyID = errors.New(InvalidAccessKeyIDErrorName, "invalid access key id")
	// ErrUnknownAccessKey is returned when the access key is not found.
	ErrUnknownAccessKey = errors.New(UnknownAccessKeyErrorName, "unknown access key")
	// ErrSignatureMismatch is returned when the request signature does not verify
	// against the access key's secret.
	ErrSignatureMismatch = errors.New(SignatureMismatchErrorName, "request signature does not match")
	// ErrSignatureExpired is returned when the request is outside its signature
	// validity window (presigned expiry or clock skew).
	ErrSignatureExpired = errors.New(SignatureExpiredErrorName, "request signature is no longer valid")
	// ErrAccessKeyExpired is returned when the access key has passed its expiry.
	ErrAccessKeyExpired = errors.New(AccessKeyExpiredErrorName, "access key has expired")
	// ErrTenantDisabled is returned when the tenant is disabled.
	ErrTenantDisabled = errors.New(TenantDisabledErrorName, "tenant is disabled")
	// ErrIssuerForbidden is returned when the invocation issuer is not allowed to
	// act on the tenant's behalf (it is not the tenant's provider).
	ErrIssuerForbidden = errors.New(IssuerForbiddenErrorName, "issuer is not allowed to act for this tenant")
	// ErrRegionNotServed is returned when none of the request's regions are served
	// by the tenant's provider.
	ErrRegionNotServed = errors.New(RegionNotServedErrorName, "request region is not served by the tenant's provider")
)
