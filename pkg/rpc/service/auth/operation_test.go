package auth

import (
	"testing"

	s3 "github.com/fil-forge/libforge/commands/s3"
	"github.com/stretchr/testify/require"
)

// TestClassifyRequest covers the method/path/query rules, including the multipart
// operations whose query parameters shadow a plain-object classification.
func TestClassifyRequest(t *testing.T) {
	tests := []struct {
		name       string
		method     string
		url        string
		headers    map[string]string
		want       Operation
		wantBucket string
		wantKey    string
		wantSrc    string // "bucket/key" named by x-amz-copy-source, for the copy operations
	}{
		// Plain object and bucket operations.
		{name: "list buckets", method: "GET", url: "https://s3.example.com/", want: OpListBuckets},
		{name: "list objects", method: "GET", url: "https://s3.example.com/bkt", want: OpListBucket, wantBucket: "bkt"},
		{name: "get object", method: "GET", url: "https://s3.example.com/bkt/k", want: OpGetObject, wantBucket: "bkt", wantKey: "k"},
		{name: "head object", method: "HEAD", url: "https://s3.example.com/bkt/k", want: OpGetObject, wantBucket: "bkt", wantKey: "k"},
		{name: "put object", method: "PUT", url: "https://s3.example.com/bkt/k", want: OpPutObject, wantBucket: "bkt", wantKey: "k"},
		{name: "create bucket", method: "PUT", url: "https://s3.example.com/bkt", want: OpCreateBucket, wantBucket: "bkt"},
		{name: "delete object", method: "DELETE", url: "https://s3.example.com/bkt/k", want: OpDeleteObject, wantBucket: "bkt", wantKey: "k"},
		{name: "delete bucket", method: "DELETE", url: "https://s3.example.com/bkt", want: OpDeleteBucket, wantBucket: "bkt"},

		// Bucket-configuration reads. Both classified as ListBucket before the
		// subresource parameter was taken into account.
		{name: "get bucket versioning", method: "GET", url: "https://s3.example.com/bkt?versioning", want: OpGetBucketVersioning, wantBucket: "bkt"},
		{name: "get bucket versioning with value", method: "GET", url: "https://s3.example.com/bkt?versioning=", want: OpGetBucketVersioning, wantBucket: "bkt"},
		{name: "head bucket versioning", method: "HEAD", url: "https://s3.example.com/bkt?versioning", want: OpGetBucketVersioning, wantBucket: "bkt"},
		{name: "get bucket object lock configuration", method: "GET", url: "https://s3.example.com/bkt?object-lock", want: OpGetBucketObjectLockConfiguration, wantBucket: "bkt"},
		// The subresource only applies to a bucket: on an object key it is an
		// unknown parameter and the request stays a GetObject.
		{name: "versioning on an object is a get object", method: "GET", url: "https://s3.example.com/bkt/k?versioning", want: OpGetObject, wantBucket: "bkt", wantKey: "k"},
		{name: "object-lock on an object is a get object", method: "GET", url: "https://s3.example.com/bkt/k?object-lock", want: OpGetObject, wantBucket: "bkt", wantKey: "k"},
		// The parameter names are case-sensitive, and a PUT of the subresource is
		// not a supported configuration write: it classifies as CreateBucket.
		{name: "versioning wrong case is a list", method: "GET", url: "https://s3.example.com/bkt?Versioning", want: OpListBucket, wantBucket: "bkt"},
		{name: "put bucket versioning is a create bucket", method: "PUT", url: "https://s3.example.com/bkt?versioning", want: OpCreateBucket, wantBucket: "bkt"},

		// Multipart operations. Each of these classified as its plain-object
		// counterpart before the query string was taken into account.
		{name: "list multipart uploads", method: "GET", url: "https://s3.example.com/bkt?uploads", want: OpListBucketMultipartUploads, wantBucket: "bkt"},
		{name: "list parts", method: "GET", url: "https://s3.example.com/bkt/k?uploadId=abc", want: OpListMultipartUploadParts, wantBucket: "bkt", wantKey: "k"},
		{name: "create multipart upload", method: "POST", url: "https://s3.example.com/bkt/k?uploads", want: OpCreateMultipartUpload, wantBucket: "bkt", wantKey: "k"},
		{name: "upload part", method: "PUT", url: "https://s3.example.com/bkt/k?partNumber=1&uploadId=abc", want: OpUploadPart, wantBucket: "bkt", wantKey: "k"},
		{name: "complete multipart upload", method: "POST", url: "https://s3.example.com/bkt/k?uploadId=abc", want: OpCompleteMultipartUpload, wantBucket: "bkt", wantKey: "k"},
		{name: "abort multipart upload", method: "DELETE", url: "https://s3.example.com/bkt/k?uploadId=abc", want: OpAbortMultipartUpload, wantBucket: "bkt", wantKey: "k"},

		// Copies: a PUT of an object or a part naming a parseable x-amz-copy-source.
		// The header name is case-insensitive; the value may carry a leading slash,
		// URL-encoding and a versionId suffix, all of which the source parse strips.
		{name: "copy object", method: "PUT", url: "https://s3.example.com/bkt/k", headers: map[string]string{"x-amz-copy-source": "src/obj"}, want: OpCopyObject, wantBucket: "bkt", wantKey: "k", wantSrc: "src/obj"},
		{name: "copy object, header name case", method: "PUT", url: "https://s3.example.com/bkt/k", headers: map[string]string{"X-Amz-Copy-Source": "/src/a%20b/c?versionId=v1"}, want: OpCopyObject, wantBucket: "bkt", wantKey: "k", wantSrc: "src/a b/c"},
		{name: "upload part copy", method: "PUT", url: "https://s3.example.com/bkt/k?partNumber=2&uploadId=abc", headers: map[string]string{"x-amz-copy-source": "src/obj"}, want: OpUploadPartCopy, wantBucket: "bkt", wantKey: "k", wantSrc: "src/obj"},
		{name: "copy within a bucket", method: "PUT", url: "https://s3.example.com/bkt/k", headers: map[string]string{"x-amz-copy-source": "bkt/other"}, want: OpCopyObject, wantBucket: "bkt", wantKey: "k", wantSrc: "bkt/other"},

		// Only the values the gateway's backend parser rejects are not a copy: no
		// separator, or bad percent-encoding. An empty bucket or key is a copy of
		// that (impossible) bucket or key, exactly as the gateway parses it.
		{name: "copy source without a separator is a put", method: "PUT", url: "https://s3.example.com/bkt/k", headers: map[string]string{"x-amz-copy-source": "srconly"}, want: OpPutObject, wantBucket: "bkt", wantKey: "k"},
		{name: "copy source with bad encoding is a put", method: "PUT", url: "https://s3.example.com/bkt/k", headers: map[string]string{"x-amz-copy-source": "src/%ZZ"}, want: OpPutObject, wantBucket: "bkt", wantKey: "k"},
		{name: "empty copy source is a put", method: "PUT", url: "https://s3.example.com/bkt/k", headers: map[string]string{"x-amz-copy-source": ""}, want: OpPutObject, wantBucket: "bkt", wantKey: "k"},
		{name: "copy source with an empty key is a copy", method: "PUT", url: "https://s3.example.com/bkt/k", headers: map[string]string{"x-amz-copy-source": "src/"}, want: OpCopyObject, wantBucket: "bkt", wantKey: "k", wantSrc: "src/"},
		{name: "copy source with an empty bucket is a copy", method: "PUT", url: "https://s3.example.com/bkt/k", headers: map[string]string{"x-amz-copy-source": "//k"}, want: OpCopyObject, wantBucket: "bkt", wantKey: "k", wantSrc: "/k"},
		// Only PUT copies; the header on any other shape is ignored.
		{name: "copy source on a complete is a complete", method: "POST", url: "https://s3.example.com/bkt/k?uploadId=abc", headers: map[string]string{"x-amz-copy-source": "src/obj"}, want: OpCompleteMultipartUpload, wantBucket: "bkt", wantKey: "k"},
		{name: "copy source on a get is a get", method: "GET", url: "https://s3.example.com/bkt/k", headers: map[string]string{"x-amz-copy-source": "src/obj"}, want: OpGetObject, wantBucket: "bkt", wantKey: "k"},

		// Each multipart write shape is reachable only via the method S3 defines for
		// it. A mismatched shape is not a multipart request and falls back to
		// PutObject, which requires the same permission.
		{name: "part upload shape on POST is not an upload part", method: "POST", url: "https://s3.example.com/bkt/k?partNumber=1&uploadId=abc", want: OpPutObject, wantBucket: "bkt", wantKey: "k"},
		{name: "initiate shape on PUT is not an initiate", method: "PUT", url: "https://s3.example.com/bkt/k?uploads", want: OpPutObject, wantBucket: "bkt", wantKey: "k"},
		{name: "complete shape on PUT is not a complete", method: "PUT", url: "https://s3.example.com/bkt/k?uploadId=abc", want: OpPutObject, wantBucket: "bkt", wantKey: "k"},
		{name: "part upload without partNumber is not an upload part", method: "PUT", url: "https://s3.example.com/bkt/k?uploadId=abc&partNo=1", want: OpPutObject, wantBucket: "bkt", wantKey: "k"},

		// Unrelated query parameters do not change the classification, and the
		// multipart parameter names are case-sensitive.
		{name: "list objects with prefix", method: "GET", url: "https://s3.example.com/bkt?prefix=a/", want: OpListBucket, wantBucket: "bkt"},
		{name: "get object with version", method: "GET", url: "https://s3.example.com/bkt/k?versionId=v", want: OpGetObject, wantBucket: "bkt", wantKey: "k"},
		{name: "uploadid wrong case is not multipart", method: "DELETE", url: "https://s3.example.com/bkt/k?uploadid=abc", want: OpDeleteObject, wantBucket: "bkt", wantKey: "k"},

		// Nested keys keep their full remainder as the key.
		{name: "nested key", method: "POST", url: "https://s3.example.com/bkt/a/b/c?uploads", want: OpCreateMultipartUpload, wantBucket: "bkt", wantKey: "a/b/c"},

		// Lowercase methods classify the same.
		{name: "lowercase method", method: "delete", url: "https://s3.example.com/bkt/k?uploadId=abc", want: OpAbortMultipartUpload, wantBucket: "bkt", wantKey: "k"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, err := classifyRequest(s3.Request{Method: tt.method, URL: tt.url, Headers: tt.headers})
			require.NoError(t, err)
			require.Equal(t, tt.want, c.op)
			require.Equal(t, tt.wantBucket, c.bucket)
			require.Equal(t, tt.wantKey, c.key)
			src := ""
			if c.op.CopiesSource() {
				src = c.srcBucket + "/" + c.srcKey
			}
			require.Equal(t, tt.wantSrc, src)
		})
	}

	t.Run("rejects unsupported method and path combinations", func(t *testing.T) {
		for _, req := range []s3.Request{
			{Method: "PUT", URL: "https://s3.example.com/"},
			{Method: "POST", URL: "https://s3.example.com/"},
			{Method: "DELETE", URL: "https://s3.example.com/"},
			{Method: "PATCH", URL: "https://s3.example.com/bkt/k"},
		} {
			_, err := classifyRequest(req)
			require.Error(t, err, "%s %s", req.Method, req.URL)
		}
	})
}

// TestRequirementsFor covers the gateway's local view of what a request needs:
// one bucket/permission pair for an ordinary operation, a second for the copy
// source, none for operations that address no existing bucket.
func TestRequirementsFor(t *testing.T) {
	copyHdr := map[string]string{"x-amz-copy-source": "src/obj"}

	op, reqs, err := RequirementsFor(s3.Request{Method: "PUT", URL: "https://s3.example.com/bkt/k", Headers: copyHdr})
	require.NoError(t, err)
	require.Equal(t, OpCopyObject, op)
	require.Equal(t, []Requirement{{Bucket: "bkt", Permission: "s3:PutObject"}, {Bucket: "src", Permission: SourcePermission}}, reqs)

	op, reqs, err = RequirementsFor(s3.Request{Method: "PUT", URL: "https://s3.example.com/bkt/k?partNumber=1&uploadId=abc", Headers: copyHdr})
	require.NoError(t, err)
	require.Equal(t, OpUploadPartCopy, op)
	require.Equal(t, []Requirement{{Bucket: "bkt", Permission: "s3:PutObject"}, {Bucket: "src", Permission: SourcePermission}}, reqs)

	op, reqs, err = RequirementsFor(s3.Request{Method: "GET", URL: "https://s3.example.com/bkt/k"})
	require.NoError(t, err)
	require.Equal(t, OpGetObject, op)
	require.Equal(t, []Requirement{{Bucket: "bkt", Permission: "s3:GetObject"}}, reqs)

	for _, req := range []s3.Request{
		{Method: "GET", URL: "https://s3.example.com/"},
		{Method: "PUT", URL: "https://s3.example.com/bkt"},
	} {
		_, reqs, err := RequirementsFor(req)
		require.NoError(t, err)
		require.Empty(t, reqs, "%s %s", req.Method, req.URL)
	}

	_, _, err = RequirementsFor(s3.Request{Method: "PATCH", URL: "https://s3.example.com/bkt/k"})
	require.Error(t, err)
}

// TestOperationPermission asserts every operation requires a permission, so a new
// operation cannot be added without an operationPermission entry — an operation
// with no permission would pass the access key's permission check unconditionally.
func TestOperationPermission(t *testing.T) {
	ops := []Operation{
		OpListBuckets, OpListBucket, OpGetObject, OpPutObject, OpCopyObject, OpCreateBucket,
		OpDeleteObject, OpDeleteBucket,
		OpGetBucketVersioning, OpGetBucketObjectLockConfiguration,
		OpCreateMultipartUpload, OpUploadPart, OpUploadPartCopy, OpCompleteMultipartUpload,
		OpAbortMultipartUpload, OpListMultipartUploadParts, OpListBucketMultipartUploads,
	}
	require.Len(t, operationPermission, len(ops), "every operation constant must be listed here")
	for _, op := range ops {
		require.NotEmpty(t, op.Permission(), "operation %s has no required permission", op)
	}

	// The bucket-configuration reads act on a bucket that must exist, so the
	// authorizer resolves and scope-checks it as it does for a listing.
	require.True(t, OpGetBucketVersioning.addressesExistingBucket())
	require.True(t, OpGetBucketObjectLockConfiguration.addressesExistingBucket())

	// The multipart write operations share s3:PutObject, so a key that can already
	// put an object can perform them without being re-issued.
	require.Equal(t, "s3:PutObject", OpCreateMultipartUpload.Permission())
	require.Equal(t, "s3:PutObject", OpUploadPart.Permission())
	// The copies write their destination like a put; the source's read
	// permission is a separate requirement.
	require.Equal(t, "s3:PutObject", OpCopyObject.Permission())
	require.Equal(t, "s3:PutObject", OpUploadPartCopy.Permission())
	require.Equal(t, "s3:GetObject", SourcePermission)
	require.True(t, OpCopyObject.CopiesSource())
	require.True(t, OpUploadPartCopy.CopiesSource())
	require.False(t, OpPutObject.CopiesSource())
	require.Equal(t, "s3:PutObject", OpCompleteMultipartUpload.Permission())
	require.Equal(t, "s3:AbortMultipartUpload", OpAbortMultipartUpload.Permission())
	require.Equal(t, "s3:ListMultipartUploadParts", OpListMultipartUploadParts.Permission())
	require.Equal(t, "s3:ListBucketMultipartUploads", OpListBucketMultipartUploads.Permission())

	// The bucket-configuration reads have their own permissions, so a policy can
	// grant a listing without them and the other way round.
	require.Equal(t, "s3:GetBucketVersioning", OpGetBucketVersioning.Permission())
	require.Equal(t, "s3:GetBucketObjectLockConfiguration", OpGetBucketObjectLockConfiguration.Permission())

	require.Empty(t, Operation("Unknown").Permission())
}
