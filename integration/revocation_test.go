package integration

import (
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/fil-forge/hilt/pkg/s3perm"
	"github.com/stretchr/testify/require"
)

// TestDeleteAccessKeyRevokes drives access-key deletion end to end: the console
// deletes a key over the REST API, Hilt publishes a /ucan/revoke invocation to the
// real Swarf for every delegation the key held, and Swarf — which verifies the
// tenant's signature and the path witness itself — records each one.
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

	perms := []string{"s3:CreateBucket", "s3:PutObject"}
	ak, err := net.Console.CreateAccessKey(ctx, tenantID, "key-1", perms)
	require.NoError(t, err)

	// A bucket must exist for the key's (powerline) delegations to have a chain: the
	// bucket→tenant root is what witnesses the revocation.
	s3c := net.S3Client(t, ak.AccessKeyID, ak.SecretAccessKey)
	_, err = s3c.CreateBucket(ctx, &s3.CreateBucketInput{Bucket: aws.String("test-bucket")})
	require.NoError(t, err)

	require.NoError(t, net.Console.DeleteAccessKey(ctx, tenantID, ak.AccessKeyID))

	// One delegation was issued per command mapped from the permissions, and each is
	// revoked. Swarf accepting them proves the witness paths verify.
	revoked := net.Swarf.awaitRevocations(t, ctx, len(s3perm.CommandsFor(perms...)))

	for _, link := range revoked {
		record, err := net.Swarf.revocation(ctx, link)
		require.NoError(t, err)
		require.Equal(t, link, record.Revoke)
		// Witness: rooted in the bucket's self-issued delegation, revoked one last.
		require.Len(t, record.Path, 2)
		require.Equal(t, record.Path[0].Issuer(), record.Path[0].Subject())
		revokedDlg := record.Path[len(record.Path)-1]
		require.Equal(t, link, revokedDlg.Link())
		// The tenant (a did:plc) issued the delegation, so the tenant revoked it.
		require.Equal(t, "plc", record.Cause.Issuer().Method())
		require.Equal(t, revokedDlg.Issuer(), record.Cause.Issuer())
	}

	_, err = net.Console.GetAccessKey(ctx, tenantID, ak.AccessKeyID)
	require.Error(t, err, "the access key should be gone")
}
