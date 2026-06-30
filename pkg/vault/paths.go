package vault

import "github.com/fil-forge/ucantone/did"

// TenantKeyPath is the vault key under which a tenant's private key is stored.
func TenantKeyPath(tenantID did.DID) string {
	return "/tenant/" + tenantID.String()
}

// AccessKeyPath is the vault key under which an access key's private key is
// stored, scoped beneath its tenant.
func AccessKeyPath(tenantID, accessKeyID did.DID) string {
	return TenantKeyPath(tenantID) + "/access/" + accessKeyID.String()
}
