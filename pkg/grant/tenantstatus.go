package grant

import (
	"slices"

	"github.com/fil-forge/hilt/pkg/s3perm"
	"github.com/fil-forge/hilt/pkg/store/tenant"
)

// LimitToTenantStatus preserves the key's configured permissions separately
// from its currently issued authority. Restoring active reissues fresh grants
// from that configuration; it never revives revoked delegation CIDs.
func LimitToTenantStatus(status tenant.Status, actions []string) []string {
	if status == tenant.Active {
		return slices.Clone(actions)
	}
	var allowed []string
	if status == tenant.WriteLocked {
		for _, action := range actions {
			if s3perm.AllowedWhenWriteLocked(action) {
				allowed = append(allowed, action)
			}
		}
	}
	return allowed
}
