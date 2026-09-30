//go:build itest

package itest

import (
	"bytes"
	"io"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/fil-forge/hilt/pkg/api"
	"github.com/fil-forge/hilt/pkg/s3perm"
	"github.com/stretchr/testify/require"
)

// testWriteLockBlocksWrites drives the write-lock through the real stack: an
// active tenant creates a bucket and writes an object, then the tenant is
// write-locked and the same operations must be refused while reads keep
// working, and once it is unlocked the same key writes again.
// The same S3 client and access key are used throughout, so the test covers
// Ingot's warm authorization cache. Hilt revokes the key's write grants when
// the lock is applied, so Ingot must re-authorize and receive the write-lock
// rejection; its read grant is left alone. Unlocking reissues the write grants.
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

	var writeGrants int
	for _, cmd := range s3perm.CommandsFor(perms...) {
		if s3perm.Mutates(cmd) {
			writeGrants++
		}
	}
	require.NoError(t, net.console.SetTenantStatus(ctx, tenantID, api.TenantStatusWriteLocked))
	net.awaitRevocations(t, ctx, writeGrants, "did:key:"+ak.AccessKeyID)

	require.Eventually(t, func() bool {
		_, err := s3c.PutObject(ctx, &s3.PutObjectInput{
			Bucket: aws.String(bucket),
			Key:    aws.String("after-lock.txt"),
			Body:   bytes.NewReader([]byte("should be refused")),
		})
		return err != nil
	}, 30*time.Second, 500*time.Millisecond, "PutObject must be refused after revocation propagation")

	_, err = s3c.CreateBucket(ctx, &s3.CreateBucketInput{Bucket: aws.String("write-lock-bucket-2")})
	require.Error(t, err, "CreateBucket must be refused while the tenant is write-locked")

	_, err = s3c.DeleteObject(ctx, &s3.DeleteObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String("before-lock.txt"),
	})
	require.Error(t, err, "DeleteObject must be refused while the tenant is write-locked")

	_, err = s3c.DeleteBucket(ctx, &s3.DeleteBucketInput{Bucket: aws.String(bucket)})
	require.Error(t, err, "DeleteBucket must be refused while the tenant is write-locked")

	// Reads stay available: listing the tenant's buckets still succeeds, and so
	// does reading an object, which needs the key's (unrevoked) retrieve grant.
	out, err := s3c.ListBuckets(ctx, &s3.ListBucketsInput{})
	require.NoError(t, err, "reads must keep working while the tenant is write-locked")
	require.NotEmpty(t, out.Buckets)
	requireObject(t, s3c, bucket, "before-lock.txt", "written while active")

	// Unlocking reissues the revoked write grants, so the same key writes again.
	require.NoError(t, net.console.SetTenantStatus(ctx, tenantID, api.TenantStatusActive))
	require.Eventually(t, func() bool {
		_, err := s3c.PutObject(ctx, &s3.PutObjectInput{
			Bucket: aws.String(bucket),
			Key:    aws.String("after-unlock.txt"),
			Body:   bytes.NewReader([]byte("written after unlock")),
		})
		return err == nil
	}, 30*time.Second, 500*time.Millisecond, "PutObject must succeed again once the tenant is unlocked")
	requireObject(t, s3c, bucket, "after-unlock.txt", "written after unlock")
}

// requireObject reads the object and checks its body.
func requireObject(t *testing.T, s3c *s3.Client, bucket, key, want string) {
	t.Helper()
	obj, err := s3c.GetObject(t.Context(), &s3.GetObjectInput{Bucket: aws.String(bucket), Key: aws.String(key)})
	require.NoError(t, err, "GetObject %s", key)
	defer obj.Body.Close()
	got, err := io.ReadAll(obj.Body)
	require.NoError(t, err)
	require.Equal(t, want, string(got))
}
