package accesskey

import "github.com/fil-forge/ucantone/errors"

// Error names for the access-key service's known errors, exported so callers can
// match on the stable Name() of a serialized failure.
const (
	TenantNotFoundErrorName    = "TenantNotFound"
	InvalidNameErrorName       = "InvalidAccessKeyName"
	NoPermissionsErrorName     = "NoPermissions"
	InvalidPermissionErrorName = "InvalidPermission"
	UnknownBucketErrorName     = "UnknownBucket"
	NameConflictErrorName      = "AccessKeyNameConflict"
	AccessKeyNotFoundErrorName = "AccessKeyNotFound"
)

// Known errors returned by the access-key [Service]. Handlers map these to HTTP
// status codes with errors.Is; anything else is an unexpected (500-class)
// failure. ErrInvalidPermission and ErrUnknownBucket are wrapped with the
// offending value at the return site so the message names it.
var (
	// ErrTenantNotFound is returned when no tenant exists for the external id.
	ErrTenantNotFound = errors.New(TenantNotFoundErrorName, "tenant not found")
	// ErrInvalidName is returned when the access key name is empty or too long.
	ErrInvalidName = errors.New(InvalidNameErrorName, "name must be between 1 and 100 characters")
	// ErrNoPermissions is returned when no permissions are requested.
	ErrNoPermissions = errors.New(NoPermissionsErrorName, "at least one permission is required")
	// ErrInvalidPermission is returned when a requested permission is unknown.
	ErrInvalidPermission = errors.New(InvalidPermissionErrorName, "unknown permission")
	// ErrUnknownBucket is returned when a requested bucket name is not one of the
	// tenant's buckets.
	ErrUnknownBucket = errors.New(UnknownBucketErrorName, "unknown bucket")
	// ErrNameConflict is returned when an access key with the same name already
	// exists for the tenant.
	ErrNameConflict = errors.New(NameConflictErrorName, "an access key with this name already exists")
	// ErrAccessKeyNotFound is returned when the access key does not exist (or
	// belongs to another tenant, or the id is unparseable).
	ErrAccessKeyNotFound = errors.New(AccessKeyNotFoundErrorName, "access key not found")
)
