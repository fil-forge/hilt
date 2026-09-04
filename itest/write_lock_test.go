//go:build itest

package itest

import (
	"bytes"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/fil-forge/hilt/pkg/api"
	"github.com/stretchr/testify/require"
)

// testWriteLockBlocksWrites drives the write-lock through the real stack: an
// active tenant creates a bucket and writes an object, then the tenant is
// write-locked and the same operations must be refused while reads keep
// working.
//
// The credentials used after the lock are a second access key created after it,
// because ingot caches the delegations hilt issued for the first key (valid
// until midnight UTC) and would not re-authorize with hilt at all. This
// exercises the cold hilt authorization path; expiring warm ingot caches on a
// status change is ingot's side of the fix.
func testWriteLockBlocksWrites(t *testing.T, net *forgeNet) {
	ctx := t.Context()

	const tenantID = "tenant-write-lock"
	_, err := net.console.ProvisionTenant(ctx, tenantID, forgeRegion)
	require.NoError(t, err)

	perms := []string{"s3:CreateBucket", "s3:PutObject", "s3:GetObject", "s3:DeleteObject", "s3:DeleteBucket", "s3:ListAllMyBuckets"}
	ak, err := net.console.CreateAccessKey(ctx, tenantID, "before-lock", perms, nil)
	require.NoError(t, err)

	const bucket = "write-lock-bucket"
	s3c := net.s3Client(t, ak.AccessKeyID, ak.SecretAccessKey)
	_, err = s3c.CreateBucket(ctx, &s3.CreateBucketInput{Bucket: aws.String(bucket)})
	require.NoError(t, err)
	_, err = s3c.PutObject(ctx, &s3.PutObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String("before-lock.txt"),
		Body:   bytes.NewReader([]byte("written while active")),
	})
	require.NoError(t, err)

	require.NoError(t, net.console.SetTenantStatus(ctx, tenantID, api.TenantStatusWriteLocked))

	locked, err := net.console.CreateAccessKey(ctx, tenantID, "after-lock", perms, nil)
	require.NoError(t, err)
	lockedC := net.s3Client(t, locked.AccessKeyID, locked.SecretAccessKey)

	_, err = lockedC.PutObject(ctx, &s3.PutObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String("after-lock.txt"),
		Body:   bytes.NewReader([]byte("should be refused")),
	})
	require.Error(t, err, "PutObject must be refused while the tenant is write-locked")

	_, err = lockedC.CreateBucket(ctx, &s3.CreateBucketInput{Bucket: aws.String("write-lock-bucket-2")})
	require.Error(t, err, "CreateBucket must be refused while the tenant is write-locked")

	_, err = lockedC.DeleteObject(ctx, &s3.DeleteObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String("before-lock.txt"),
	})
	require.Error(t, err, "DeleteObject must be refused while the tenant is write-locked")

	_, err = lockedC.DeleteBucket(ctx, &s3.DeleteBucketInput{Bucket: aws.String(bucket)})
	require.Error(t, err, "DeleteBucket must be refused while the tenant is write-locked")

	// Reads stay available: listing the tenant's buckets still succeeds.
	out, err := lockedC.ListBuckets(ctx, &s3.ListBucketsInput{})
	require.NoError(t, err, "reads must keep working while the tenant is write-locked")
	require.NotEmpty(t, out.Buckets)
}
