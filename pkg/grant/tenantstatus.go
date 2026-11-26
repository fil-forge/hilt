package grant

import (
	"slices"

	"github.com/fil-forge/hilt/pkg/s3perm"
	"github.com/fil-forge/hilt/pkg/store/tenant"
)

// LimitToTenantStatus reduces a set of S3 actions to those a tenant in the
// status keeps: all of them for an active tenant, those
// [s3perm.KeptWhenWriteLocked] keeps for a write-locked one, in the order
// given, and none for a disabled tenant or a status that is not one. The
// result is a new slice.
//
// It leaves what a key or a policy is configured with alone: the narrower
// set is what the tenant's keys are issued grants for, and what is reported
// to the gateway, while the tenant has the status, and the full set is what
// they are issued when it is active again.
func LimitToTenantStatus(status tenant.Status, actions []string) []string {
	switch status {
	case tenant.Active:
		return slices.Clone(actions)
	case tenant.WriteLocked:
		var kept []string
		for _, action := range actions {
			if s3perm.KeptWhenWriteLocked(action) {
				kept = append(kept, action)
			}
		}
		return kept
	default:
		return nil
	}
}
