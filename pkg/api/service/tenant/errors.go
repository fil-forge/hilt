package tenant

import "github.com/fil-forge/ucantone/errors"

// Error names for the tenant service's known errors, exported so callers can
// match on the stable Name() of a serialized failure.
const (
	TenantNotFoundErrorName     = "TenantNotFound"
	RegionRequiredErrorName     = "RegionRequired"
	UnknownRegionErrorName      = "UnknownRegion"
	InvalidStatusErrorName      = "InvalidStatus"
	TenantNotDisabledErrorName  = "TenantNotDisabled"
	DIDRegistrationErrorName    = "DIDRegistration"
	UploadRegistrationErrorName = "UploadRegistration"
	DIDDeactivationErrorName    = "DIDDeactivation"
)

// Known errors returned by the tenant [Service]. Handlers map these to HTTP
// status codes with errors.Is; anything else is an unexpected (500-class)
// failure. The operational failures (DID/upload) carry a fixed, caller-safe
// message — the underlying cause is logged by the service, not surfaced.
var (
	// ErrTenantNotFound is returned when no tenant exists for the external id.
	ErrTenantNotFound = errors.New(TenantNotFoundErrorName, "tenant not found")
	// ErrRegionRequired is returned when a provision request omits the region.
	ErrRegionRequired = errors.New(RegionRequiredErrorName, "region is required")
	// ErrUnknownRegion is returned when no provider serves the requested region.
	ErrUnknownRegion = errors.New(UnknownRegionErrorName, "unknown region")
	// ErrInvalidStatus is returned when a status update names an unknown status.
	ErrInvalidStatus = errors.New(InvalidStatusErrorName, "invalid status")
	// ErrTenantNotDisabled is returned when deleting a tenant that is not disabled.
	ErrTenantNotDisabled = errors.New(TenantNotDisabledErrorName, "tenant must be disabled before deletion")
	// ErrDIDRegistration is returned when publishing the tenant's did:plc fails.
	ErrDIDRegistration = errors.New(DIDRegistrationErrorName, "failed to register tenant DID")
	// ErrUploadRegistration is returned when registering the tenant with the
	// upload service fails.
	ErrUploadRegistration = errors.New(UploadRegistrationErrorName, "failed to register tenant with upload service")
	// ErrDIDDeactivation is returned when deactivating the tenant's did:plc fails.
	ErrDIDDeactivation = errors.New(DIDDeactivationErrorName, "failed to deactivate tenant DID")
)
