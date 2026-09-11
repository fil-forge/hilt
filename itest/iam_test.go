//go:build itest

package itest

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/smithy-go"
	"github.com/fil-forge/hilt/pkg/api"
	"github.com/fil-forge/hilt/pkg/bucketpolicy"
	"github.com/fil-forge/hilt/pkg/client/management"
	"github.com/stretchr/testify/require"
)

// The IAM scenarios drive the tenant access model end to end: a principal
// holds no delegation, so every action it may take on a bucket comes from the
// bucket's policy, and every change to a policy or a principal is published to
// the real swarf as a principal invalidation the gateway reads off the
// firehose. Each scenario provisions its own tenant and principal, so the
// stack-global firehose can be filtered by the principal's id.

// readActions are the policy actions a member needs to read a bucket, and
// writeActions add the object write. They are the two sets every scenario
// below grants.
var (
	readActions  = []string{"s3:GetObject", "s3:ListBucket"}
	writeActions = []string{"s3:GetObject", "s3:ListBucket", "s3:PutObject"}
)

// allPermissions is every S3 permission Hilt recognises. The fixture's service
// key holds them all so it can create buckets and seed objects for any
// scenario.
var allPermissions = []string{
	"s3:CreateBucket",
	"s3:DeleteBucket",
	"s3:ListAllMyBuckets",
	"s3:ListBucket",
	"s3:ListBucketVersions",
	"s3:GetObject",
	"s3:GetObjectVersion",
	"s3:GetObjectRetention",
	"s3:GetObjectLegalHold",
	"s3:PutObject",
	"s3:PutObjectRetention",
	"s3:PutObjectLegalHold",
	"s3:DeleteObject",
	"s3:DeleteObjectVersion",
	"s3:AbortMultipartUpload",
	"s3:ListMultipartUploadParts",
	"s3:ListBucketMultipartUploads",
	"s3:GetBucketVersioning",
	"s3:GetBucketObjectLockConfiguration",
}

// member is one scenario's fixture: a tenant with a service key that creates
// its buckets and seeds objects, and one principal with an access key bound to
// it. The principal's access is whatever the bucket policies say, so the
// fixture grants none.
type member struct {
	net       *forgeNet
	tenantID  string
	principal string
	service   *s3.Client
	key       api.CreatedAccessKey
	s3        *s3.Client
}

// newMember provisions the tenant, creates a service key that makes the named
// buckets, records the principal and creates a key bound to it.
func newMember(t *testing.T, net *forgeNet, tenantID, principal string, buckets ...string) member {
	t.Helper()
	ctx := t.Context()

	_, err := net.console.ProvisionTenant(ctx, tenantID, forgeRegion)
	require.NoError(t, err)
	cred, err := net.console.CreateAccessKey(ctx, tenantID, api.CreateAccessKeyRequest{
		Name:        "service",
		Permissions: allPermissions,
	})
	require.NoError(t, err)
	require.Empty(t, cred.Principal, "a key created without principalId is a service key")
	service := net.s3Client(t, cred.AccessKeyID, cred.SecretAccessKey)

	for _, bucket := range buckets {
		_, err = service.CreateBucket(ctx, &s3.CreateBucketInput{Bucket: aws.String(bucket)})
		require.NoError(t, err, "creating bucket %s", bucket)
	}

	_, err = net.console.CreatePrincipal(ctx, tenantID, principal)
	require.NoError(t, err)
	key, err := net.console.CreateAccessKey(ctx, tenantID, api.CreateAccessKeyRequest{
		Name:        principal + "-key",
		PrincipalID: principal,
	})
	require.NoError(t, err)
	require.Equal(t, principal, key.Principal)
	require.Empty(t, key.Permissions, "a principal-bound key carries none")
	require.Empty(t, key.Buckets, "a principal-bound key carries none")

	return member{
		net:       net,
		tenantID:  tenantID,
		principal: principal,
		service:   service,
		key:       key,
		s3:        net.s3Client(t, key.AccessKeyID, key.SecretAccessKey),
	}
}

// allow builds a one-statement document granting actions to principals.
func allow(actions []string, principals ...string) api.BucketPolicy {
	return api.BucketPolicy{Statements: []bucketpolicy.Statement{
		{Effect: bucketpolicy.Allow, Principals: principals, Actions: actions},
	}}
}

// requireS3Code asserts the request failed with the given S3 error code.
func requireS3Code(t *testing.T, err error, code string) {
	t.Helper()
	var apiErr smithy.APIError
	require.ErrorAs(t, err, &apiErr, "expected an S3 error, got %v", err)
	require.Equal(t, code, apiErr.ErrorCode())
}

// awaitObject polls a read until the object comes back with the expected
// bytes: a write settles through ingot's catalog and retrieval tiers before
// the first read can see it.
func awaitObject(t *testing.T, ctx context.Context, client *s3.Client, bucket, key string, want []byte) {
	t.Helper()
	require.Eventually(t, func() bool {
		out, err := client.GetObject(ctx, &s3.GetObjectInput{Bucket: aws.String(bucket), Key: aws.String(key)})
		if err != nil {
			return false
		}
		defer out.Body.Close()
		got, err := io.ReadAll(out.Body)
		return err == nil && bytes.Equal(got, want)
	}, time.Minute, time.Second, "%s/%s should be readable", bucket, key)
}

// awaitS3Code polls a request until it fails with the given S3 error code:
// after a policy change the gateway serves from its cache until the firehose
// event reaches it.
func awaitS3Code(t *testing.T, code string, request func() error) {
	t.Helper()
	var last error
	require.Eventually(t, func() bool {
		last = request()
		if last == nil {
			return false
		}
		var apiErr smithy.APIError
		return errors.As(last, &apiErr) && apiErr.ErrorCode() == code
	}, time.Minute, time.Second, "the request should be refused with %s, last error: %v", code, last)
}

// testPrincipalKeyCreateRejectsBadRequests covers the two ways a
// principal-bound key creation is refused: a principal-bound key that also asks
// for permissions, and one naming a principal the tenant does not have. Both
// are 422, and neither leaves a key behind.
func testPrincipalKeyCreateRejectsBadRequests(t *testing.T, net *forgeNet) {
	ctx := t.Context()

	const tenantID, principal = "tenant-iam-422", "member-422"
	_, err := net.console.ProvisionTenant(ctx, tenantID, forgeRegion)
	require.NoError(t, err)
	_, err = net.console.CreatePrincipal(ctx, tenantID, principal)
	require.NoError(t, err)

	// A principal-bound key's access comes from the bucket policies alone.
	_, err = net.console.CreateAccessKey(ctx, tenantID, api.CreateAccessKeyRequest{
		Name:        "scoped",
		PrincipalID: principal,
		Permissions: []string{"s3:GetObject"},
	})
	var apiErr *management.APIError
	require.ErrorAs(t, err, &apiErr)
	require.Equal(t, http.StatusUnprocessableEntity, apiErr.StatusCode)

	_, err = net.console.CreateAccessKey(ctx, tenantID, api.CreateAccessKeyRequest{
		Name:        "unknown",
		PrincipalID: "no-such-member",
	})
	require.ErrorAs(t, err, &apiErr)
	require.Equal(t, http.StatusUnprocessableEntity, apiErr.StatusCode)

	keys, err := net.console.ListPrincipalAccessKeys(ctx, tenantID, principal)
	require.NoError(t, err)
	require.Empty(t, keys, "a refused create leaves no key behind")
}

// testPrincipalPolicyScopesToOneBucket covers the grant: a principal named in
// one bucket's policy reads and writes that bucket with its own key, and the
// tenant's other bucket does not exist as far as that key is concerned — hilt
// answers UnknownBucket, which ingot renders as NoSuchBucket.
func testPrincipalPolicyScopesToOneBucket(t *testing.T, net *forgeNet) {
	ctx := t.Context()

	const tenantID, principal = "tenant-iam-scope", "member-scope"
	const granted, ungranted = "iamscope-granted", "iamscope-other"
	m := newMember(t, net, tenantID, principal, granted, ungranted)

	_, err := net.console.CreateBucketPolicy(ctx, tenantID, granted, allow(writeActions, principal))
	require.NoError(t, err)

	payload := []byte("written by the member")
	_, err = m.s3.PutObject(ctx, &s3.PutObjectInput{
		Bucket: aws.String(granted),
		Key:    aws.String("member.txt"),
		Body:   bytes.NewReader(payload),
	})
	require.NoError(t, err, "the policy grants s3:PutObject on this bucket")
	awaitObject(t, ctx, m.s3, granted, "member.txt", payload)

	_, err = m.s3.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(ungranted),
		Key:    aws.String("member.txt"),
	})
	requireS3Code(t, err, "NoSuchBucket")

	// The console's view of the member matches: one bucket, the granted set.
	access, err := net.console.GetPrincipalAccess(ctx, tenantID, principal)
	require.NoError(t, err)
	require.Len(t, access, 1)
	require.Equal(t, granted, access[0].Name)
	require.ElementsMatch(t, writeActions, access[0].Actions)
}

// testDenyBeatsAllow covers precedence: a Deny statement withholds an action
// an Allow statement in the same document grants, and leaves the rest of the
// grant standing.
func testDenyBeatsAllow(t *testing.T, net *forgeNet) {
	ctx := t.Context()

	const tenantID, principal, bucket = "tenant-iam-deny", "member-deny", "iamdeny-bucket"
	m := newMember(t, net, tenantID, principal, bucket)

	payload := []byte("seeded by the tenant")
	_, err := m.service.PutObject(ctx, &s3.PutObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String("seeded.txt"),
		Body:   bytes.NewReader(payload),
	})
	require.NoError(t, err)

	doc := api.BucketPolicy{Statements: []bucketpolicy.Statement{
		{Effect: bucketpolicy.Allow, Principals: []string{principal}, Actions: writeActions},
		{Effect: bucketpolicy.Deny, Principals: []string{principal}, Actions: []string{"s3:PutObject"}},
	}}
	_, err = net.console.CreateBucketPolicy(ctx, tenantID, bucket, doc)
	require.NoError(t, err)

	_, err = m.s3.PutObject(ctx, &s3.PutObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String("refused.txt"),
		Body:   bytes.NewReader([]byte("should not be stored")),
	})
	requireS3Code(t, err, "AccessDenied")

	// The Allow the Deny does not name still holds.
	awaitObject(t, ctx, m.s3, bucket, "seeded.txt", payload)
}

// testNarrowingInvalidatesPrincipal covers a policy narrowed to drop a member:
// hilt publishes a principal event to the real swarf inside the write, the
// firehose carries it, and the member's next request is refused.
func testNarrowingInvalidatesPrincipal(t *testing.T, net *forgeNet) {
	ctx := t.Context()

	const tenantID, principal, bucket = "tenant-iam-narrow", "member-narrow", "iamnarrow-bucket"
	const keeper = "member-narrow-keeper"
	m := newMember(t, net, tenantID, principal, bucket)
	_, err := net.console.CreatePrincipal(ctx, tenantID, keeper)
	require.NoError(t, err)

	etag, err := net.console.CreateBucketPolicy(ctx, tenantID, bucket, allow(writeActions, principal, keeper))
	require.NoError(t, err)

	payload := []byte("readable while the policy names the member")
	_, err = m.s3.PutObject(ctx, &s3.PutObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String("narrow.txt"),
		Body:   bytes.NewReader(payload),
	})
	require.NoError(t, err)
	awaitObject(t, ctx, m.s3, bucket, "narrow.txt", payload)

	// Narrow the policy to the other principal alone. The create published an
	// event for the member too; the narrowing's is the one not yet on the
	// firehose at this point.
	before := net.principalEventCauses(t, ctx, principal)
	_, err = net.console.ReplaceBucketPolicy(ctx, tenantID, bucket, allow(writeActions, keeper), etag)
	require.NoError(t, err)

	events := net.awaitPrincipalEvents(t, ctx, before, 1, principal)
	require.Equal(t, "plc", events[0].Tenant.Method(), "the event names the tenant did:plc")
	require.True(t, events[0].Cause.Defined(), "the event carries the invocation that caused it")

	// With no statement naming the member the bucket is unknown to its key.
	awaitS3Code(t, "NoSuchBucket", func() error {
		_, err := m.s3.GetObject(ctx, &s3.GetObjectInput{
			Bucket: aws.String(bucket),
			Key:    aws.String("narrow.txt"),
		})
		return err
	})

	policies, err := net.console.ListPrincipalPolicies(ctx, tenantID, principal)
	require.NoError(t, err)
	require.Empty(t, policies, "the narrowed policy no longer names the member")
}

// testDeletePrincipalRemovesKeysAndPolicies covers removing a member: the
// principal's keys go with it, so its requests no longer resolve at hilt, and
// every policy naming it is rewritten without it.
func testDeletePrincipalRemovesKeysAndPolicies(t *testing.T, net *forgeNet) {
	ctx := t.Context()

	const tenantID, principal, bucket = "tenant-iam-rmuser", "member-rmuser", "iamrmuser-bucket"
	const keeper = "member-rmuser-keeper"
	m := newMember(t, net, tenantID, principal, bucket)
	_, err := net.console.CreatePrincipal(ctx, tenantID, keeper)
	require.NoError(t, err)

	_, err = net.console.CreateBucketPolicy(ctx, tenantID, bucket, allow(readActions, principal, keeper))
	require.NoError(t, err)

	keys, err := net.console.ListPrincipalAccessKeys(ctx, tenantID, principal)
	require.NoError(t, err)
	require.Len(t, keys, 1)

	require.NoError(t, net.console.DeletePrincipal(ctx, tenantID, principal))

	// The key is gone from hilt, so the gateway cannot resolve it at all.
	awaitS3Code(t, "InvalidAccessKeyId", func() error {
		_, err := m.s3.GetObject(ctx, &s3.GetObjectInput{
			Bucket: aws.String(bucket),
			Key:    aws.String("whatever.txt"),
		})
		return err
	})

	// The principal is gone from the console too: its policy listing is a 404,
	// not an empty list.
	_, err = net.console.ListPrincipalPolicies(ctx, tenantID, principal)
	var apiErr *management.APIError
	require.ErrorAs(t, err, &apiErr)
	require.Equal(t, http.StatusNotFound, apiErr.StatusCode)

	// The policy survives for the principal it still names, stripped of the
	// removed one.
	kept, _, err := net.console.GetBucketPolicy(ctx, tenantID, bucket)
	require.NoError(t, err)
	require.Len(t, kept.Statements, 1)
	require.Equal(t, []string{keeper}, kept.Statements[0].Principals)
}

// testPresignedGetFollowsPolicy covers the presigned URL: a GET signed with a
// principal's key is served while the policy allows it, and refused once the
// policy is gone. The URL carries the same signature the SDK sends inline, so
// it is authorized the same way.
func testPresignedGetFollowsPolicy(t *testing.T, net *forgeNet) {
	ctx := t.Context()

	const tenantID, principal, bucket = "tenant-iam-presign", "member-presign", "iampresign-bucket"
	const objectKey = "presigned.txt"
	m := newMember(t, net, tenantID, principal, bucket)

	payload := []byte("served over a presigned url")
	_, err := m.service.PutObject(ctx, &s3.PutObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(objectKey),
		Body:   bytes.NewReader(payload),
	})
	require.NoError(t, err)

	etag, err := net.console.CreateBucketPolicy(ctx, tenantID, bucket, allow(readActions, principal))
	require.NoError(t, err)

	presign := s3.NewPresignClient(m.s3)
	// get signs a fresh URL and fetches it. It returns errors rather than
	// failing the test: it runs inside require.Eventually's condition, which
	// testify executes on another goroutine, where FailNow would stall the
	// wait instead of failing it.
	get := func() (int, []byte, error) {
		signed, err := presign.PresignGetObject(ctx, &s3.GetObjectInput{
			Bucket: aws.String(bucket),
			Key:    aws.String(objectKey),
		}, s3.WithPresignExpires(5*time.Minute))
		if err != nil {
			return 0, nil, fmt.Errorf("presigning: %w", err)
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, signed.URL, nil)
		if err != nil {
			return 0, nil, err
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return 0, nil, fmt.Errorf("fetching presigned url: %w", err)
		}
		defer resp.Body.Close()
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return resp.StatusCode, nil, fmt.Errorf("reading presigned response: %w", err)
		}
		return resp.StatusCode, body, nil
	}

	var lastStatus int
	var lastBody []byte
	var lastErr error
	require.Eventually(t, func() bool {
		lastStatus, lastBody, lastErr = get()
		return lastErr == nil && lastStatus == http.StatusOK && bytes.Equal(lastBody, payload)
	}, time.Minute, time.Second, "the presigned url should serve the object while the policy allows it")
	require.NoError(t, lastErr)

	before := net.principalEventCauses(t, ctx, principal)
	require.NoError(t, net.console.DeleteBucketPolicy(ctx, tenantID, bucket, etag))
	net.awaitPrincipalEvents(t, ctx, before, 1, principal)

	require.Eventually(t, func() bool {
		lastStatus, lastBody, lastErr = get()
		return lastErr == nil && lastStatus == http.StatusNotFound && bytes.Contains(lastBody, []byte("NoSuchBucket"))
	}, time.Minute, time.Second, "the presigned url should be refused once the policy is gone")
	require.NoError(t, lastErr)
	require.Equal(t, http.StatusNotFound, lastStatus, "last body: %s", lastBody)
}
