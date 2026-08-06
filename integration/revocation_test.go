package integration

import (
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/fil-forge/hilt/pkg/s3perm"
	"github.com/stretchr/testify/require"
)

// TestDeleteAccessKeyRevokes drives access-key deletion end to end: the console
// deletes a key over the REST API and Hilt publishes a /ucan/revoke invocation to
// the mock Swarf for every delegation the key held — witnessed by the bucket's
// delegation chain and signed by the tenant, which the mock verifies.
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
	require.Empty(t, net.Swarf.revocations(), "nothing is revoked before the key is deleted")

	require.NoError(t, net.Console.DeleteAccessKey(ctx, tenantID, ak.AccessKeyID))

	// One delegation was issued per command mapped from the permissions, and each is
	// revoked.
	require.Len(t, net.Swarf.revocations(), len(s3perm.CommandsFor(perms...)))
	_, err = net.Console.GetAccessKey(ctx, tenantID, ak.AccessKeyID)
	require.Error(t, err)
}
