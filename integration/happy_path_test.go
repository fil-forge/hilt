package integration

import (
	"bytes"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/stretchr/testify/require"
)

// TestHappyPath drives the whole network end to end: bring up Hilt + the mock
// Sprue/Ingot/PLC, register the Ingot as a provider, create a tenant and access key
// through the console (REST), then use the real AWS S3 SDK to create a bucket and
// upload an object — both of which the mock Ingot serves by calling Hilt's UCAN RPC.
func TestHappyPath(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test boots a real Hilt server; skipped under -short")
	}
	ctx := t.Context()

	// 1. Network up.
	net := Start(t)

	// 2. Register the mock Ingot with Hilt as the provider for the region.
	require.NoError(t, net.Admin.AddProvider(ctx, net.IngotDID, Region))

	// 3. Console creates a tenant and an access key via the REST management API.
	const tenantID = "tenant-1"
	_, err := net.Console.ProvisionTenant(ctx, tenantID, Region)
	require.NoError(t, err)

	customerAdds, _, _ := net.Sprue.counts()
	require.Equal(t, 1, customerAdds, "tenant provisioning should register one customer with Sprue")

	ak, err := net.Console.CreateAccessKey(ctx, tenantID, "key-1", []string{"s3:CreateBucket", "s3:PutObject"})
	require.NoError(t, err)
	require.True(t, strings.HasPrefix(ak.SecretAccessKey, "u"), "secret should be a multibase base64url string")

	s3c := net.S3Client(t, ak.AccessKeyID, ak.SecretAccessKey)

	// 4. Real S3 SDK CreateBucket → mock Ingot → Hilt /s3/bucket/create → Sprue.
	const bucket = "test-bucket"
	_, err = s3c.CreateBucket(ctx, &s3.CreateBucketInput{Bucket: aws.String(bucket)})
	require.NoError(t, err)

	_, providerAdds, _ := net.Sprue.counts()
	require.Equal(t, 1, providerAdds, "creating a bucket should provision one space with Sprue")

	// 5. Real S3 SDK PutObject → mock Ingot → Hilt /s3/request/authorize + verify.
	const objectKey = "hello.txt"
	payload := []byte("hello world")
	_, err = s3c.PutObject(ctx, &s3.PutObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(objectKey),
		Body:   bytes.NewReader(payload),
	})
	require.NoError(t, err)

	stored, ok := net.Ingot.object(bucket, objectKey)
	require.True(t, ok, "ingot should have stored the object")
	require.Equal(t, payload, stored)

	_, _, blobAdds := net.Sprue.counts()
	require.Equal(t, 1, blobAdds, "uploading an object should invoke /blob/add on Sprue")
}
