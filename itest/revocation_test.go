package itest

import (
	"bytes"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
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
	ak, err := net.Console.CreateAccessKey(ctx, tenantID, "key-1", perms, nil)
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

// TestDeleteBucketRevokes drives bucket deletion end to end: a real S3 SDK
// DeleteBucket reaches Hilt through the mock Ingot, and Hilt publishes a
// /ucan/revoke to the real Swarf for the bucket-scoped delegation it issued to an
// access key — but not for the bucket→tenant root, which it cannot revoke.
func TestDeleteBucketRevokes(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test boots a real Hilt server; skipped under -short")
	}
	ctx := t.Context()

	net := Start(t)
	require.NoError(t, net.Admin.AddProvider(ctx, net.IngotDID, Region))

	const tenantID, bucket = "tenant-1", "doomed-bucket"
	_, err := net.Console.ProvisionTenant(ctx, tenantID, Region)
	require.NoError(t, err)

	// An admin key creates and deletes the bucket; it holds no per-bucket
	// delegations of its own, since neither S3 permission maps to a Forge command.
	admin, err := net.Console.CreateAccessKey(ctx, tenantID,
		"admin-key", []string{"s3:CreateBucket", "s3:DeleteBucket"}, nil)
	require.NoError(t, err)
	adminS3 := net.S3Client(t, admin.AccessKeyID, admin.SecretAccessKey)
	_, err = adminS3.CreateBucket(ctx, &s3.CreateBucketInput{Bucket: aws.String(bucket)})
	require.NoError(t, err)

	// A reader key scoped to that bucket: this is the delegation the delete revokes.
	readerPerms := []string{"s3:GetObject"}
	reader, err := net.Console.CreateAccessKey(ctx, tenantID, "reader-key", readerPerms, []string{bucket})
	require.NoError(t, err)

	_, err = adminS3.DeleteBucket(ctx, &s3.DeleteBucketInput{Bucket: aws.String(bucket)})
	require.NoError(t, err)
	require.Positive(t, net.Sprue.blobListCount(), "Hilt should have checked the bucket was empty")

	// One revocation per command the reader's permissions mapped to — and only
	// those: the bucket→tenant root was signed by the bucket's discarded key, so
	// Hilt cannot revoke it.
	revoked := net.Swarf.awaitRevocations(t, ctx, len(s3perm.CommandsFor(readerPerms...)))
	readerDID := "did:key:" + reader.AccessKeyID
	for _, link := range revoked {
		record, err := net.Swarf.revocation(ctx, link)
		require.NoError(t, err)
		require.Len(t, record.Path, 1)
		revokedDlg := record.Path[0]
		require.Equal(t, readerDID, revokedDlg.Audience().String())
		// Issued by the tenant (a did:plc), which is also who revoked it.
		require.Equal(t, "plc", record.Cause.Issuer().Method())
		require.Equal(t, revokedDlg.Issuer(), record.Cause.Issuer())
	}
}

// TestDeleteBucketRevokesOnlyThatBucket covers an access key scoped to multiple
// buckets when one of them is deleted: only the deleted bucket's delegations are
// revoked, and the key keeps working against the surviving bucket.
func TestDeleteBucketRevokesOnlyThatBucket(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test boots a real Hilt server; skipped under -short")
	}
	ctx := t.Context()

	net := Start(t)
	require.NoError(t, net.Admin.AddProvider(ctx, net.IngotDID, Region))

	const tenantID = "tenant-1"
	const keptBucket, doomedBucket = "kept-bucket", "doomed-bucket"
	_, err := net.Console.ProvisionTenant(ctx, tenantID, Region)
	require.NoError(t, err)

	admin, err := net.Console.CreateAccessKey(ctx, tenantID,
		"admin-key", []string{"s3:CreateBucket", "s3:DeleteBucket"}, nil)
	require.NoError(t, err)
	adminS3 := net.S3Client(t, admin.AccessKeyID, admin.SecretAccessKey)
	for _, bucket := range []string{keptBucket, doomedBucket} {
		_, err = adminS3.CreateBucket(ctx, &s3.CreateBucketInput{Bucket: aws.String(bucket)})
		require.NoError(t, err)
	}

	// A writer key scoped to both buckets holds one delegation per
	// (bucket × command); deleting one bucket must revoke only that bucket's half.
	writerPerms := []string{"s3:PutObject"}
	writer, err := net.Console.CreateAccessKey(ctx, tenantID,
		"writer-key", writerPerms, []string{keptBucket, doomedBucket})
	require.NoError(t, err)

	_, err = adminS3.DeleteBucket(ctx, &s3.DeleteBucketInput{Bucket: aws.String(doomedBucket)})
	require.NoError(t, err)

	// Exactly one bucket's share of the writer's delegations lands on the
	// firehose: one revocation per command, all with the same subject.
	revoked := net.Swarf.awaitRevocations(t, ctx, len(s3perm.CommandsFor(writerPerms...)))
	writerDID := "did:key:" + writer.AccessKeyID
	subjects := map[string]struct{}{}
	for _, link := range revoked {
		record, err := net.Swarf.revocation(ctx, link)
		require.NoError(t, err)
		require.Len(t, record.Path, 1)
		revokedDlg := record.Path[0]
		require.Equal(t, writerDID, revokedDlg.Audience().String())
		subjects[revokedDlg.Subject().String()] = struct{}{}
	}
	require.Len(t, subjects, 1, "revocations should cover a single bucket")

	// The revoked subject is the deleted bucket: the key's record still resolves
	// the kept bucket by name and renders the deleted one as its raw DID.
	got, err := net.Console.GetAccessKey(ctx, tenantID, writer.AccessKeyID)
	require.NoError(t, err)
	require.Contains(t, got.Buckets, keptBucket)
	for subject := range subjects {
		require.Contains(t, got.Buckets, subject, "the revoked subject should be the deleted bucket's DID")
	}

	// The kept bucket's delegations survive: a real upload still authorizes
	// through the writer's remaining proof chain.
	writerS3 := net.S3Client(t, writer.AccessKeyID, writer.SecretAccessKey)
	_, err = writerS3.PutObject(ctx, &s3.PutObjectInput{
		Bucket: aws.String(keptBucket),
		Key:    aws.String("hello.txt"),
		Body:   bytes.NewReader([]byte("still works")),
	})
	require.NoError(t, err, "the writer key should still work for the surviving bucket")
}
