package api

import (
	"time"

	"github.com/fil-forge/hilt/pkg/bucketpolicy"
)

// TenantStatus is the access mode of a tenant.
type TenantStatus string

const (
	TenantStatusActive      TenantStatus = "active"
	TenantStatusWriteLocked TenantStatus = "write-locked"
	TenantStatusDisabled    TenantStatus = "disabled"
)

// Tenant is the operational state and quotas for a tenant.
type Tenant struct {
	TenantID       string       `json:"tenantId"`
	Status         TenantStatus `json:"status"`
	BucketCount    int          `json:"bucketCount"`
	BucketLimit    int          `json:"bucketLimit"`
	AccessKeyCount int          `json:"accessKeyCount"`
	AccessKeyLimit int          `json:"accessKeyLimit"`
	CreatedAt      time.Time    `json:"createdAt"`
}

// ProvisionTenantRequest is the body of PUT /tenants/{tenantId}.
type ProvisionTenantRequest struct {
	Region string `json:"region"`
}

// UpdateTenantStatusRequest is the body of POST /tenants/{tenantId}/status.
type UpdateTenantStatusRequest struct {
	Status TenantStatus `json:"status"`
}

// AccessKey is the metadata for an S3 access key (never includes the secret).
// A service key carries its permissions and buckets; a principal-bound key
// carries the principal it is bound to in their place.
type AccessKey struct {
	AccessKeyID string     `json:"accessKeyId"`
	Name        string     `json:"name"`
	Permissions []string   `json:"permissions,omitempty"`
	Buckets     []string   `json:"buckets,omitempty"`
	Principal   string     `json:"principal,omitempty"`
	ExpiresAt   *time.Time `json:"expiresAt"`
	CreatedAt   time.Time  `json:"createdAt"`
}

// CreatedAccessKey is returned only by POST /tenants/{tenantId}/access-keys and
// is the one time the secret access key is exposed.
type CreatedAccessKey struct {
	AccessKey
	SecretAccessKey string `json:"secretAccessKey"`
}

// AccessKeyList is the body of GET /tenants/{tenantId}/access-keys.
type AccessKeyList struct {
	Items []AccessKey `json:"items"`
}

// CreateAccessKeyRequest is the body of POST /tenants/{tenantId}/access-keys.
// Without a principal it creates a service key from the permissions and
// buckets. With one it creates a key bound to that principal, and permissions
// and buckets must be empty.
type CreateAccessKeyRequest struct {
	Name        string     `json:"name"`
	Permissions []string   `json:"permissions,omitempty"`
	Buckets     []string   `json:"buckets,omitempty"`
	PrincipalID string     `json:"principalId,omitempty"`
	ExpiresAt   *time.Time `json:"expiresAt,omitempty"`
}

// Principal is a console user of a tenant, identified by the console's userId.
// It holds no key material and no delegation: its access to the tenant's
// buckets is computed from the bucket policies naming it.
type Principal struct {
	UserID    string    `json:"userId"`
	CreatedAt time.Time `json:"createdAt"`
}

// PrincipalList is the body of GET /tenants/{tenantId}/principals.
type PrincipalList struct {
	Items []Principal `json:"items"`
}

// BucketPolicy is the body of GET and PUT
// /tenants/{tenantId}/buckets/{bucketName}/policy. It is the stored document
// (see [bucketpolicy.Policy]); the strong ETag the writes condition on travels in
// the ETag response header.
type BucketPolicy = bucketpolicy.Policy

// PrincipalPolicy is one of the policies naming a principal, addressed by the
// bucket it applies to.
type PrincipalPolicy struct {
	BucketName string              `json:"bucketName"`
	ETag       string              `json:"etag"`
	Policy     bucketpolicy.Policy `json:"policy"`
}

// PrincipalPolicyList is the body of
// GET /tenants/{tenantId}/principals/{userId}/policies.
type PrincipalPolicyList struct {
	Items []PrincipalPolicy `json:"items"`
}

// BucketAccess is a principal's effective actions on one bucket.
type BucketAccess struct {
	Name    string   `json:"name"`
	Actions []string `json:"actions"`
}

// PrincipalAccess is the body of
// GET /tenants/{tenantId}/principals/{userId}/access. Buckets the principal
// has no action on are omitted.
type PrincipalAccess struct {
	Buckets []BucketAccess `json:"buckets"`
}
