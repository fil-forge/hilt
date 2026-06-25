package api

import "time"

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
	DisplayName    string       `json:"displayName"`
	Status         TenantStatus `json:"status"`
	BucketCount    int          `json:"bucketCount"`
	BucketLimit    int          `json:"bucketLimit"`
	AccessKeyCount int          `json:"accessKeyCount"`
	AccessKeyLimit int          `json:"accessKeyLimit"`
	CreatedAt      time.Time    `json:"createdAt"`
}

// ProvisionTenantRequest is the body of PUT /tenants/{tenantId}.
type ProvisionTenantRequest struct {
	DisplayName string `json:"displayName"`
	Region      string `json:"region"`
}

// UpdateTenantStatusRequest is the body of POST /tenants/{tenantId}/status.
type UpdateTenantStatusRequest struct {
	Status TenantStatus `json:"status"`
}

// AccessKey is the metadata for an S3 access key (never includes the secret).
type AccessKey struct {
	AccessKeyID string     `json:"accessKeyId"`
	Name        string     `json:"name"`
	Permissions []string   `json:"permissions"`
	Buckets     []string   `json:"buckets,omitempty"`
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
type CreateAccessKeyRequest struct {
	Name        string     `json:"name"`
	Permissions []string   `json:"permissions"`
	Buckets     []string   `json:"buckets,omitempty"`
	ExpiresAt   *time.Time `json:"expiresAt,omitempty"`
}
