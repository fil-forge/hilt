package integration

import (
	"testing"

	"github.com/fil-forge/hilt/pkg/s3perm"
	"github.com/stretchr/testify/require"
)

// TestDeleteAccessKeyRevokes drives access-key deletion end to end: the console
// deletes a key over the REST API, Hilt publishes a /ucan/revoke invocation to the
// real Swarf for every delegation the key held, and Swarf — which verifies the
// tenant's signature and that the tenant issued what it is revoking — records
// each one.
func TestDeleteAccessKeyRevokes(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test boots a real Hilt server; skipped under -short")
	}
	ctx := t.Context()

	net := Start(t)
	require.NoError(t, net.Admin.AddProvider(ctx, net.IngotDID, Region))

	const tenantID = "tenant-1"
	_, err := net.Console.ProvisionTenant(ctx, tenantID, Region)
	require.NoError(t, err)

	// The key's delegations are tenant-wide (powerline), and no bucket is needed to
	// revoke them: the tenant issued them, so no witness path is involved.
	perms := []string{"s3:CreateBucket", "s3:PutObject"}
	ak, err := net.Console.CreateAccessKey(ctx, tenantID, "key-1", perms)
	require.NoError(t, err)

	require.NoError(t, net.Console.DeleteAccessKey(ctx, tenantID, ak.AccessKeyID))

	// One delegation was issued per command mapped from the permissions, and each is
	// revoked. Swarf accepting them proves it agrees the tenant may revoke directly.
	revoked := net.Swarf.awaitRevocations(t, ctx, len(s3perm.CommandsFor(perms...)))

	for _, link := range revoked {
		record, err := net.Swarf.revocation(ctx, link)
		require.NoError(t, err)
		require.Equal(t, link, record.Revoke)
		// A direct revocation is recorded against the revoked delegation alone.
		require.Len(t, record.Path, 1)
		revokedDlg := record.Path[0]
		require.Equal(t, link, revokedDlg.Link())
		// The tenant (a did:plc) issued the delegation, so the tenant revoked it.
		require.Equal(t, "plc", record.Cause.Issuer().Method())
		require.Equal(t, revokedDlg.Issuer(), record.Cause.Issuer())
	}

	_, err = net.Console.GetAccessKey(ctx, tenantID, ak.AccessKeyID)
	require.Error(t, err, "the access key should be gone")
}
