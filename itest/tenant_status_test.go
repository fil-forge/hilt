//go:build itest

package itest

import (
	"bytes"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/fil-forge/hilt/pkg/api"
	"github.com/fil-forge/hilt/pkg/s3perm"
	"github.com/stretchr/testify/require"
)

// testTenantStatusRestrictsWarmCaches exercises the real Hilt→Swarf→Ingot
// path, including old presigned URLs and cleanup's overlapping UCAN commands.
// Both tenants, their keys and their content belong only to this local stack.
func testTenantStatusRestrictsWarmCaches(t *testing.T, net *forgeNet) {
	ctx := t.Context()
	const target, control = "tenant-status-target", "tenant-status-control"
	const targetBucket, controlBucket = "status-target-bucket", "status-control-bucket"
	permissions := []string{"s3:CreateBucket", "s3:GetObject", "s3:ListBucket", "s3:PutObject",
		"s3:DeleteObject", "s3:DeleteObjectVersion", "s3:AbortMultipartUpload", "s3:DeleteObjectTagging",
		"s3:PutBucketCORS", "s3:PutEncryptionConfiguration", "s3:DeleteBucketPolicy", "s3:PutBucketTagging"}
	seed := func(tenantID, bucket string) (api.CreatedAccessKey, *s3.Client) {
		_, err := net.console.ProvisionTenant(ctx, tenantID)
		require.NoError(t, err)
		key, err := net.console.CreateAccessKey(ctx, tenantID, api.CreateAccessKeyRequest{Name: "status-fixture", Permissions: permissions})
		require.NoError(t, err)
		client := net.s3Client(t, key.AccessKeyID, key.SecretAccessKey)
		_, err = client.CreateBucket(ctx, &s3.CreateBucketInput{Bucket: aws.String(bucket)})
		require.NoError(t, err)
		for _, name := range []string{"keep.txt", "cleanup.txt"} {
			_, err = client.PutObject(ctx, &s3.PutObjectInput{Bucket: aws.String(bucket), Key: aws.String(name), Body: bytes.NewReader([]byte("synthetic tenant status fixture"))})
			require.NoError(t, err)
		}
		return key, client
	}
	targetKey, targetS3 := seed(target, targetBucket)
	_, controlS3 := seed(control, controlBucket)
	pending, err := targetS3.CreateMultipartUpload(ctx, &s3.CreateMultipartUploadInput{Bucket: aws.String(targetBucket), Key: aws.String("pending.txt")})
	require.NoError(t, err)
	// Presign once: denial must concern an old still-valid URL, not inability
	// to ask the console for a fresh one or expiration of the old signature.
	expiresNotBefore := time.Now().Add(10 * time.Minute)
	targetURL, err := s3.NewPresignClient(targetS3).PresignGetObject(ctx, &s3.GetObjectInput{Bucket: aws.String(targetBucket), Key: aws.String("keep.txt")}, s3.WithPresignExpires(10*time.Minute))
	require.NoError(t, err)
	controlURL, err := s3.NewPresignClient(controlS3).PresignGetObject(ctx, &s3.GetObjectInput{Bucket: aws.String(controlBucket), Key: aws.String("keep.txt")}, s3.WithPresignExpires(10*time.Minute))
	require.NoError(t, err)
	fetch := func(url string) (int, bool) {
		request, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			return 0, false
		}
		response, err := (&http.Client{Timeout: 10 * time.Second}).Do(request)
		if err != nil {
			return 0, false
		} // Never put a signed URL in test output.
		defer response.Body.Close()
		body, err := io.ReadAll(io.LimitReader(response.Body, 4096))
		return response.StatusCode, err == nil && bytes.Equal(body, []byte("synthetic tenant status fixture"))
	}
	status, matches := fetch(targetURL.URL)
	require.Equal(t, http.StatusOK, status)
	require.True(t, matches)
	status, matches = fetch(controlURL.URL)
	require.Equal(t, http.StatusOK, status)
	require.True(t, matches)

	require.NoError(t, net.console.UpdateTenantStatus(ctx, target, api.TenantStatusWriteLocked))
	writeLockedCommittedAt := time.Now()
	net.awaitRevocations(t, ctx, len(s3perm.CommandsFor(permissions...)), "did:key:"+targetKey.AccessKeyID)
	awaitS3Code(t, "AccessDenied", func() error {
		_, err := targetS3.PutObject(ctx, &s3.PutObjectInput{Bucket: aws.String(targetBucket), Key: aws.String("blocked.txt"), Body: bytes.NewReader([]byte("synthetic blocked write"))})
		return err
	})
	t.Logf("write-locked write denial observed %dms after management completion", time.Since(writeLockedCommittedAt).Milliseconds())
	// Warm the allowed cleanup chains and read/list action snapshot after
	// invalidation. Delete and abort together include every PutObject command;
	// the S3 operation set must remain narrower than the UCAN command union.
	_, err = targetS3.ListObjectsV2(ctx, &s3.ListObjectsV2Input{Bucket: aws.String(targetBucket)})
	require.NoError(t, err)
	_, err = targetS3.DeleteObject(ctx, &s3.DeleteObjectInput{Bucket: aws.String(targetBucket), Key: aws.String("cleanup.txt")})
	require.NoError(t, err)
	_, err = targetS3.AbortMultipartUpload(ctx, &s3.AbortMultipartUploadInput{Bucket: aws.String(targetBucket), Key: aws.String("pending.txt"), UploadId: pending.UploadId})
	require.NoError(t, err)
	status, matches = fetch(targetURL.URL)
	require.Equal(t, http.StatusOK, status, "write lock preserves old reads")
	require.True(t, matches)

	for name, mutate := range map[string]func() error{
		"put": func() error {
			_, err := targetS3.PutObject(ctx, &s3.PutObjectInput{Bucket: aws.String(targetBucket), Key: aws.String("blocked.txt"), Body: bytes.NewReader([]byte("blocked"))})
			return err
		},
		"copy": func() error {
			_, err := targetS3.CopyObject(ctx, &s3.CopyObjectInput{Bucket: aws.String(targetBucket), Key: aws.String("blocked-copy.txt"), CopySource: aws.String(targetBucket + "/keep.txt")})
			return err
		},
		"initiate multipart": func() error {
			_, err := targetS3.CreateMultipartUpload(ctx, &s3.CreateMultipartUploadInput{Bucket: aws.String(targetBucket), Key: aws.String("blocked-multipart.txt")})
			return err
		},
		"upload part": func() error {
			_, err := targetS3.UploadPart(ctx, &s3.UploadPartInput{Bucket: aws.String(targetBucket), Key: aws.String("pending.txt"), UploadId: pending.UploadId, PartNumber: aws.Int32(1), Body: bytes.NewReader([]byte("blocked"))})
			return err
		},
		"complete multipart": func() error {
			_, err := targetS3.CompleteMultipartUpload(ctx, &s3.CompleteMultipartUploadInput{Bucket: aws.String(targetBucket), Key: aws.String("pending.txt"), UploadId: pending.UploadId})
			return err
		},
		"delete object tags": func() error {
			_, err := targetS3.DeleteObjectTagging(ctx, &s3.DeleteObjectTaggingInput{Bucket: aws.String(targetBucket), Key: aws.String("keep.txt")})
			return err
		},
		"delete bucket cors": func() error {
			_, err := targetS3.DeleteBucketCors(ctx, &s3.DeleteBucketCorsInput{Bucket: aws.String(targetBucket)})
			return err
		},
		"delete bucket encryption": func() error {
			_, err := targetS3.DeleteBucketEncryption(ctx, &s3.DeleteBucketEncryptionInput{Bucket: aws.String(targetBucket)})
			return err
		},
		"delete bucket policy": func() error {
			_, err := targetS3.DeleteBucketPolicy(ctx, &s3.DeleteBucketPolicyInput{Bucket: aws.String(targetBucket)})
			return err
		},
		"delete bucket tags": func() error {
			_, err := targetS3.DeleteBucketTagging(ctx, &s3.DeleteBucketTaggingInput{Bucket: aws.String(targetBucket)})
			return err
		},
	} {
		t.Run(name, func(t *testing.T) { requireS3Code(t, mutate(), "AccessDenied") })
	}
	// Warm the other tenant once more so an over-broad invalidation or
	// restriction cannot pass merely by observing one denied target.
	status, matches = fetch(controlURL.URL)
	require.Equal(t, http.StatusOK, status)
	require.True(t, matches)

	require.NoError(t, net.console.UpdateTenantStatus(ctx, target, api.TenantStatusDisabled))
	disabledCommittedAt := time.Now()
	require.Eventually(t, func() bool {
		status, _ := fetch(targetURL.URL)
		return status == http.StatusForbidden && time.Now().Before(expiresNotBefore)
	}, time.Minute, time.Second,
		"the exact old URL must be refused after disabled invalidation")
	t.Logf("disabled old-URL denial observed %dms after management completion", time.Since(disabledCommittedAt).Milliseconds())
	status, matches = fetch(controlURL.URL)
	require.Equal(t, http.StatusOK, status)
	require.True(t, matches)
	require.NoError(t, net.console.UpdateTenantStatus(ctx, target, api.TenantStatusActive))
	require.Eventually(t, func() bool { status, matches := fetch(targetURL.URL); return status == http.StatusOK && matches }, time.Minute, time.Second,
		"restoration must issue fresh readable authority")
	_, err = targetS3.PutObject(ctx, &s3.PutObjectInput{Bucket: aws.String(targetBucket), Key: aws.String("restored.txt"), Body: bytes.NewReader([]byte("synthetic restored write"))})
	require.NoError(t, err)
}
