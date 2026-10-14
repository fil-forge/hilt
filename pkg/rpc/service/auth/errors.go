package auth

import "github.com/fil-forge/ucantone/errors"

// Error names for the named rejection errors, exported so callers (e.g. Ingot,
// mapping to canonical S3 error responses) can match on the stable Name() of a
// serialized failure.
const (
	MalformedSignatureErrorName     = "MalformedSignature"
	InvalidAccessKeyIDErrorName     = "InvalidAccessKeyID"
	UnknownAccessKeyErrorName       = "UnknownAccessKey"
	SignatureMismatchErrorName      = "SignatureMismatch"
	SignatureExpiredErrorName       = "SignatureExpired"
	AccessKeyExpiredErrorName       = "AccessKeyExpired"
	TenantDisabledErrorName         = "TenantDisabled"
	IssuerForbiddenErrorName        = "IssuerForbidden"
	RegionNotServedErrorName        = "RegionNotServed"
	UnsupportedOperationErrorName   = "UnsupportedOperation"
	OperationNotPermittedErrorName  = "OperationNotPermitted"
	UnknownBucketErrorName          = "UnknownBucket"
	ForeignBucketErrorName          = "ForeignBucket"
	BucketNotPermittedErrorName     = "BucketNotPermitted"
	UnsignedCopySourceErrorName     = "UnsignedCopySource"
	TemporarilyUnavailableErrorName = "TemporarilyUnavailable"
)

// Named rejection errors returned by [Authorizer.Authorize]. Each is a sentinel
// carrying a stable Name(), wrapped with per-request context at the return site,
// so callers can branch on the reason with errors.Is. Unexpected/internal
// failures (store or vault errors) are intentionally not named — they are
// 500-class, not authorization rejections. The one store failure that is named
// is the lock timeout, [ErrTemporarilyUnavailable], because the caller can
// retry it.
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
	// ErrUnsupportedOperation is returned when the request's method and path map to
	// no supported S3 operation.
	ErrUnsupportedOperation = errors.New(UnsupportedOperationErrorName, "unsupported S3 operation")
	// ErrOperationNotPermitted is returned when the credential does not hold the
	// permission required for the requested operation: an action outside a
	// service key's own permissions, an action outside a principal's non-empty
	// effective set on the bucket, or CreateBucket and DeleteBucket for a
	// principal-bound key, which no policy grants.
	ErrOperationNotPermitted = errors.New(OperationNotPermittedErrorName, "access key is not permitted to perform this operation")
	// ErrUnknownBucket is returned when a bucket the request addresses (its own,
	// or its copy source's) does not exist, or is out of the principal's reach.
	ErrUnknownBucket = errors.New(UnknownBucketErrorName, "unknown bucket")
	// ErrForeignBucket is returned when a bucket the request addresses belongs to
	// another tenant. It is distinct from ErrUnknownBucket so the gateway can
	// answer as S3 does for another account's bucket (AccessDenied, not
	// NoSuchBucket); bucket names are global, so their existence is not a secret
	// (CreateBucket already reports a taken name).
	ErrForeignBucket = errors.New(ForeignBucketErrorName, "bucket belongs to another tenant")
	// ErrBucketNotPermitted is returned when a service key's bucket scope does
	// not include a bucket the request addresses.
	ErrBucketNotPermitted = errors.New(BucketNotPermittedErrorName, "access key is not permitted to use this bucket")
	// ErrUnsignedCopySource is returned when a copy request's x-amz-copy-source
	// header is not covered by the request signature, so the source it names
	// cannot be trusted and the copy cannot be authorized.
	ErrUnsignedCopySource = errors.New(UnsignedCopySourceErrorName, "x-amz-copy-source is not covered by the request signature")
	// ErrTemporarilyUnavailable is returned when the share-locked read of the
	// key, its principal or the bucket's policy waited out the store's lock
	// timeout behind a write still committing. Nothing about the request was
	// decided; a retry is answered from whichever state the write leaves. The
	// returned error wraps [store.ErrLockTimeout] as well.
	ErrTemporarilyUnavailable = errors.New(TemporarilyUnavailableErrorName, "authorization state is being changed, retry the request")
)
