//go:build itest

package itest

import (
	"bytes"
	"errors"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/smithy-go"
	"github.com/fil-forge/hilt/pkg/s3perm"
	"github.com/stretchr/testify/require"
)

// testDeleteAccessKeyRevokes drives access-key deletion end to end: the
// console deletes a key over the REST API, hilt publishes a /ucan/revoke
// invocation to the real swarf for every delegation the key held, and swarf —
// which verifies the tenant's signature and that the tenant issued what it is
// revoking — records each one.
func testDeleteAccessKeyRevokes(t *testing.T, net *forgeNet) {
	ctx := t.Context()

	const tenantID = "tenant-keydel"
	_, err := net.console.ProvisionTenant(ctx, tenantID, forgeRegion)
	require.NoError(t, err)

	// The key's delegations are tenant-wide (powerline), and no bucket is
	// needed to revoke them: the tenant issued them, so no witness path is
	// involved.
	perms := []string{"s3:CreateBucket", "s3:PutObject"}
	ak, err := net.console.CreateAccessKey(ctx, tenantID, "key-1", perms, nil)
	require.NoError(t, err)

	require.NoError(t, net.console.DeleteAccessKey(ctx, tenantID, ak.AccessKeyID))

	// One delegation was issued per command mapped from the permissions, and
	// each is revoked. Swarf accepting them proves it agrees the tenant may
	// revoke directly.
	records := net.awaitRevocations(t, ctx, len(s3perm.CommandsFor(perms...)), "did:key:"+ak.AccessKeyID)

	for _, record := range records {
		// A direct revocation is recorded against the revoked delegation alone.
		require.Len(t, record.Path, 1)
		revokedDlg := record.Path[0]
		require.Equal(t, record.Revoke, revokedDlg.Link())
		// The tenant (a did:plc) issued the delegation, so the tenant revoked it.
		require.Equal(t, "plc", record.Cause.Issuer().Method())
		require.Equal(t, revokedDlg.Issuer(), record.Cause.Issuer())
	}

	_, err = net.console.GetAccessKey(ctx, tenantID, ak.AccessKeyID)
	require.Error(t, err, "the access key should be gone")
}

// testDeleteBucketRevokes drives bucket deletion end to end: a real S3 SDK
// DeleteBucket reaches hilt through the real ingot, and hilt publishes a
// /ucan/revoke to the real swarf for the bucket-scoped delegation it issued
// to an access key — but not for the bucket→tenant root, which it cannot
// revoke. Deleting while an object is still in the bucket must fail: hilt
// checks the space is empty against the real sprue.
func testDeleteBucketRevokes(t *testing.T, net *forgeNet) {
	ctx := t.Context()

	const tenantID, bucket = "tenant-bktdel", "bktdel-doomed"
	_, err := net.console.ProvisionTenant(ctx, tenantID, forgeRegion)
	require.NoError(t, err)

	// A tenant-wide admin key creates, fills, empties, and deletes the
	// bucket; its delegations are powerline (tenant subject), so the bucket
	// deletion revokes none of them.
	admin, err := net.console.CreateAccessKey(ctx, tenantID, "admin-key",
		[]string{"s3:CreateBucket", "s3:DeleteBucket", "s3:PutObject", "s3:DeleteObject"}, nil)
	require.NoError(t, err)
	adminS3 := net.s3Client(t, admin.AccessKeyID, admin.SecretAccessKey)
	_, err = adminS3.CreateBucket(ctx, &s3.CreateBucketInput{Bucket: aws.String(bucket)})
	require.NoError(t, err)

	// A reader key scoped to that bucket: this is the delegation the delete
	// revokes.
	readerPerms := []string{"s3:GetObject"}
	reader, err := net.console.CreateAccessKey(ctx, tenantID, "reader-key", readerPerms, []string{bucket})
	require.NoError(t, err)

	// With an object in the bucket the delete must be refused: hilt asks the
	// real sprue whether the space is empty.
	const blocker = "blocker.txt"
	_, err = adminS3.PutObject(ctx, &s3.PutObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(blocker),
		Body:   bytes.NewReader([]byte("not empty")),
	})
	require.NoError(t, err)

	_, err = adminS3.DeleteBucket(ctx, &s3.DeleteBucketInput{Bucket: aws.String(bucket)})
	var apiErr smithy.APIError
	require.ErrorAs(t, err, &apiErr, "deleting a non-empty bucket should fail")
	require.Equal(t, "BucketNotEmpty", apiErr.ErrorCode())

	_, err = adminS3.DeleteObject(ctx, &s3.DeleteObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(blocker),
	})
	require.NoError(t, err)

	// The blob release trails the object delete, so the bucket delete is
	// polled until sprue agrees the space is empty. Only BucketNotEmpty is
	// worth retrying — any other failure surfaces immediately.
	deadline := time.Now().Add(2 * time.Minute)
	for {
		_, err = adminS3.DeleteBucket(ctx, &s3.DeleteBucketInput{Bucket: aws.String(bucket)})
		if err == nil {
			break
		}
		var retryErr smithy.APIError
		if !errors.As(err, &retryErr) || retryErr.ErrorCode() != "BucketNotEmpty" || time.Now().After(deadline) {
			require.NoError(t, err, "the emptied bucket should delete")
		}
		time.Sleep(2 * time.Second)
	}

	// One revocation per command the reader's permissions mapped to — and
	// only those: the bucket→tenant root was signed by the bucket's discarded
	// key, so hilt cannot revoke it.
	records := net.awaitRevocations(t, ctx, len(s3perm.CommandsFor(readerPerms...)), "did:key:"+reader.AccessKeyID)
	for _, record := range records {
		require.Len(t, record.Path, 1)
		revokedDlg := record.Path[0]
		// Issued by the tenant (a did:plc), which is also who revoked it.
		require.Equal(t, "plc", record.Cause.Issuer().Method())
		require.Equal(t, revokedDlg.Issuer(), record.Cause.Issuer())
	}
}

// testDeleteBucketRevokesOnlyThatBucket covers an access key scoped to
// multiple buckets when one of them is deleted: only the deleted bucket's
// delegations are revoked, and the key keeps working against the surviving
// bucket.
func testDeleteBucketRevokesOnlyThatBucket(t *testing.T, net *forgeNet) {
	ctx := t.Context()

	const tenantID = "tenant-multibkt"
	const keptBucket, doomedBucket = "multibkt-kept", "multibkt-doomed"
	_, err := net.console.ProvisionTenant(ctx, tenantID, forgeRegion)
	require.NoError(t, err)

	admin, err := net.console.CreateAccessKey(ctx, tenantID,
		"admin-key", []string{"s3:CreateBucket", "s3:DeleteBucket"}, nil)
	require.NoError(t, err)
	adminS3 := net.s3Client(t, admin.AccessKeyID, admin.SecretAccessKey)
	for _, bucket := range []string{keptBucket, doomedBucket} {
		_, err = adminS3.CreateBucket(ctx, &s3.CreateBucketInput{Bucket: aws.String(bucket)})
		require.NoError(t, err)
	}

	// A writer key scoped to both buckets holds one delegation per
	// (bucket × command); deleting one bucket must revoke only that bucket's
	// half.
	writerPerms := []string{"s3:PutObject"}
	writer, err := net.console.CreateAccessKey(ctx, tenantID,
		"writer-key", writerPerms, []string{keptBucket, doomedBucket})
	require.NoError(t, err)

	_, err = adminS3.DeleteBucket(ctx, &s3.DeleteBucketInput{Bucket: aws.String(doomedBucket)})
	require.NoError(t, err)

	// Exactly one bucket's share of the writer's delegations lands on the
	// firehose: one revocation per command, all with the same subject.
	records := net.awaitRevocations(t, ctx, len(s3perm.CommandsFor(writerPerms...)), "did:key:"+writer.AccessKeyID)
	subjects := map[string]struct{}{}
	for _, record := range records {
		require.Len(t, record.Path, 1)
		subjects[record.Path[0].Subject().String()] = struct{}{}
	}
	require.Len(t, subjects, 1, "revocations should cover a single bucket")

	// The revoked subject is the deleted bucket: the key's record still
	// resolves the kept bucket by name and renders the deleted one as its raw
	// DID.
	got, err := net.console.GetAccessKey(ctx, tenantID, writer.AccessKeyID)
	require.NoError(t, err)
	require.Contains(t, got.Buckets, keptBucket)
	for subject := range subjects {
		require.Contains(t, got.Buckets, subject, "the revoked subject should be the deleted bucket's DID")
	}

	// The kept bucket's delegations survive: a real upload still authorizes
	// through the writer's remaining proof chain.
	writerS3 := net.s3Client(t, writer.AccessKeyID, writer.SecretAccessKey)
	_, err = writerS3.PutObject(ctx, &s3.PutObjectInput{
		Bucket: aws.String(keptBucket),
		Key:    aws.String("hello.txt"),
		Body:   bytes.NewReader([]byte("still works")),
	})
	require.NoError(t, err, "the writer key should still work for the surviving bucket")
}
