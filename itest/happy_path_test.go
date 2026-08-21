//go:build itest

package itest

import (
	"bytes"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/stretchr/testify/require"
)

// testHappyPath drives the network end to end: create a tenant and access
// key through the partner REST API, then use the real AWS S3 SDK against the
// real ingot gateway to create a bucket and round-trip an object. Every step
// succeeding is itself the proof the real services cooperated: hilt refuses
// to record a tenant whose sprue customer registration fails, CreateBucket
// requires a real space provisioned with sprue, and the object read comes
// back through ingot's storage tiers.
func testHappyPath(t *testing.T, net *forgeNet) {
	ctx := t.Context()

	const tenantID = "tenant-happy"
	_, err := net.console.ProvisionTenant(ctx, tenantID, forgeRegion)
	require.NoError(t, err)

	ak, err := net.console.CreateAccessKey(ctx, tenantID, "key-1",
		[]string{"s3:CreateBucket", "s3:PutObject", "s3:GetObject"}, nil)
	require.NoError(t, err)
	require.True(t, strings.HasPrefix(ak.SecretAccessKey, "u"), "secret should be a multibase base64url string")

	s3c := net.s3Client(t, ak.AccessKeyID, ak.SecretAccessKey)

	const bucket = "happy-bucket"
	_, err = s3c.CreateBucket(ctx, &s3.CreateBucketInput{Bucket: aws.String(bucket)})
	require.NoError(t, err)

	const objectKey = "hello.txt"
	payload := []byte("hello world")
	_, err = s3c.PutObject(ctx, &s3.PutObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(objectKey),
		Body:   bytes.NewReader(payload),
	})
	require.NoError(t, err)

	// The read may lag the write while ingot's catalog/retrieval tiers
	// settle, so poll rather than asserting the first response.
	require.Eventually(t, func() bool {
		out, err := s3c.GetObject(ctx, &s3.GetObjectInput{
			Bucket: aws.String(bucket),
			Key:    aws.String(objectKey),
		})
		if err != nil {
			return false
		}
		defer out.Body.Close()
		got, err := io.ReadAll(out.Body)
		return err == nil && bytes.Equal(got, payload)
	}, time.Minute, time.Second, "the object should round-trip through ingot")
}
