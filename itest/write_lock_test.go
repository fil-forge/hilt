//go:build itest

package itest

import (
	"bytes"
	"errors"
	"io"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awshttp "github.com/aws/aws-sdk-go-v2/aws/transport/http"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/smithy-go"
	"github.com/fil-forge/hilt/pkg/api"
	"github.com/fil-forge/hilt/pkg/s3perm"
	"github.com/stretchr/testify/require"
)

// requireWriteLockRefusal asserts how a write-locked tenant's mutation comes
// back to the client, not merely that it failed. The first version of this
// test asserted err != nil, and passed for months while every refusal arrived
// as a 500 InternalError: a write lock is a policy decision, and an SDK
// retries a 5xx.
//
// Hilt names the refusal TenantWriteLocked. Ingot maps hilt's authorization
// failures onto S3 errors in iam.mapAuthError, and until it learns that name
// it falls through to 500-class. So the published ingot :main image, which is
// what this suite boots by default, still answers 500; against a local ingot
// that carries the mapping the refusal is the 403 AccessDenied it should
// always have been. When :main carries it, drop the branch and keep the
// strict arm — same as the IAM gate in stack_test.go.
func requireWriteLockRefusal(t *testing.T, err error, op string) {
	t.Helper()
	require.Error(t, err, "%s must be refused while the tenant is write-locked", op)

	var respErr *awshttp.ResponseError
	require.ErrorAs(t, err, &respErr, "%s: want an HTTP response from the gateway, got %v", op, err)
	status := respErr.HTTPStatusCode()
	var code string
	if apiErr := smithy.APIError(nil); errors.As(err, &apiErr) {
		code = apiErr.ErrorCode()
	}
	t.Logf("%s on a write-locked tenant: HTTP %d %s", op, status, code)

	if os.Getenv("HILT_ITEST_INGOT_BINARY") == "" && os.Getenv("HILT_ITEST_IAM") != "1" {
		require.GreaterOrEqual(t, status, http.StatusBadRequest, "%s: want a refusal", op)
		return
	}
	require.Equal(t, http.StatusForbidden, status, "%s: a write lock is a policy refusal, not a server fault", op)
	require.Equal(t, "AccessDenied", code, "%s", op)
}

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
	ak, err := net.console.CreateAccessKey(ctx, tenantID, api.CreateAccessKeyRequest{
		Name:        "before-lock",
		Permissions: perms,
	})
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
	require.NoError(t, net.console.UpdateTenantStatus(ctx, tenantID, api.TenantStatusWriteLocked))
	net.awaitRevocations(t, ctx, writeGrants, "did:key:"+ak.AccessKeyID)

	var putErr error
	require.Eventually(t, func() bool {
		_, putErr = s3c.PutObject(ctx, &s3.PutObjectInput{
			Bucket: aws.String(bucket),
			Key:    aws.String("after-lock.txt"),
			Body:   bytes.NewReader([]byte("should be refused")),
		})
		return putErr != nil
	}, 30*time.Second, 500*time.Millisecond, "PutObject must be refused after revocation propagation")
	requireWriteLockRefusal(t, putErr, "PutObject")

	_, err = s3c.CreateBucket(ctx, &s3.CreateBucketInput{Bucket: aws.String("write-lock-bucket-2")})
	requireWriteLockRefusal(t, err, "CreateBucket")

	_, err = s3c.DeleteObject(ctx, &s3.DeleteObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String("before-lock.txt"),
	})
	requireWriteLockRefusal(t, err, "DeleteObject")

	_, err = s3c.DeleteBucket(ctx, &s3.DeleteBucketInput{Bucket: aws.String(bucket)})
	requireWriteLockRefusal(t, err, "DeleteBucket")

	// Reads stay available: listing the tenant's buckets still succeeds, and so
	// does reading an object, which needs the key's (unrevoked) retrieve grant.
	out, err := s3c.ListBuckets(ctx, &s3.ListBucketsInput{})
	require.NoError(t, err, "reads must keep working while the tenant is write-locked")
	require.NotEmpty(t, out.Buckets)
	requireObject(t, s3c, bucket, "before-lock.txt", "written while active")

	// Unlocking reissues the revoked write grants, so the same key writes again.
	require.NoError(t, net.console.UpdateTenantStatus(ctx, tenantID, api.TenantStatusActive))
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
