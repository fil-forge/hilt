package integration

import (
	"context"
	"net/url"
	"testing"

	"github.com/fil-forge/hilt/pkg/api"
	"github.com/fil-forge/hilt/pkg/client/management"
	"github.com/stretchr/testify/require"
)

// Console is a mock management console: the partner-facing means of creating
// tenants and access keys. It drives Hilt's REST management API using the existing
// management client, authenticating with the partner key.
type Console struct {
	client *management.Client
}

func newConsole(t *testing.T, baseURL, partnerKey string) *Console {
	t.Helper()
	u, err := url.Parse(baseURL)
	require.NoError(t, err)
	return &Console{client: management.NewClient(*u, partnerKey)}
}

// ProvisionTenant creates (or returns the existing) tenant for the given external
// id and region.
func (c *Console) ProvisionTenant(ctx context.Context, tenantID, region string) (api.Tenant, error) {
	return c.client.ProvisionTenant(ctx, tenantID, api.ProvisionTenantRequest{Region: region})
}

// CreateAccessKey creates an S3 access key with the given permissions and returns
// it, including the one-time secret access key.
func (c *Console) CreateAccessKey(ctx context.Context, tenantID, name string, perms []string) (api.CreatedAccessKey, error) {
	return c.client.CreateAccessKey(ctx, tenantID, api.CreateAccessKeyRequest{Name: name, Permissions: perms})
}
