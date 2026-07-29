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
		want       Operation
		wantBucket string
		wantKey    string
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

		// Multipart operations. Each of these classified as its plain-object
		// counterpart before the query string was taken into account.
		{name: "list multipart uploads", method: "GET", url: "https://s3.example.com/bkt?uploads", want: OpListBucketMultipartUploads, wantBucket: "bkt"},
		{name: "list parts", method: "GET", url: "https://s3.example.com/bkt/k?uploadId=abc", want: OpListMultipartUploadParts, wantBucket: "bkt", wantKey: "k"},
		{name: "create multipart upload", method: "POST", url: "https://s3.example.com/bkt/k?uploads", want: OpCreateMultipartUpload, wantBucket: "bkt", wantKey: "k"},
		{name: "upload part", method: "PUT", url: "https://s3.example.com/bkt/k?partNumber=1&uploadId=abc", want: OpUploadPart, wantBucket: "bkt", wantKey: "k"},
		{name: "complete multipart upload", method: "POST", url: "https://s3.example.com/bkt/k?uploadId=abc", want: OpCompleteMultipartUpload, wantBucket: "bkt", wantKey: "k"},
		{name: "abort multipart upload", method: "DELETE", url: "https://s3.example.com/bkt/k?uploadId=abc", want: OpAbortMultipartUpload, wantBucket: "bkt", wantKey: "k"},

		// A part copy is an upload part: the copy source is not classified.
		{name: "upload part copy", method: "PUT", url: "https://s3.example.com/bkt/k?partNumber=2&uploadId=abc", want: OpUploadPart, wantBucket: "bkt", wantKey: "k"},

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
			op, bucket, key, err := classifyRequest(s3.Request{Method: tt.method, URL: tt.url})
			require.NoError(t, err)
			require.Equal(t, tt.want, op)
			require.Equal(t, tt.wantBucket, bucket)
			require.Equal(t, tt.wantKey, key)
		})
	}

	t.Run("rejects unsupported method and path combinations", func(t *testing.T) {
		for _, req := range []s3.Request{
			{Method: "PUT", URL: "https://s3.example.com/"},
			{Method: "POST", URL: "https://s3.example.com/"},
			{Method: "DELETE", URL: "https://s3.example.com/"},
			{Method: "PATCH", URL: "https://s3.example.com/bkt/k"},
		} {
			_, _, _, err := classifyRequest(req)
			require.Error(t, err, "%s %s", req.Method, req.URL)
		}
	})
}

// TestOperationPermission asserts every operation requires a permission, so a new
// operation cannot be added without an operationPermission entry — an operation
// with no permission would pass the access key's permission check unconditionally.
func TestOperationPermission(t *testing.T) {
	ops := []Operation{
		OpListBuckets, OpListBucket, OpGetObject, OpPutObject, OpCreateBucket,
		OpDeleteObject, OpDeleteBucket,
		OpCreateMultipartUpload, OpUploadPart, OpCompleteMultipartUpload,
		OpAbortMultipartUpload, OpListMultipartUploadParts, OpListBucketMultipartUploads,
	}
	require.Len(t, operationPermission, len(ops), "every operation constant must be listed here")
	for _, op := range ops {
		require.NotEmpty(t, op.Permission(), "operation %s has no required permission", op)
	}

	// The multipart write operations share s3:PutObject, so a key that can already
	// put an object can perform them without being re-issued.
	require.Equal(t, "s3:PutObject", OpCreateMultipartUpload.Permission())
	require.Equal(t, "s3:PutObject", OpUploadPart.Permission())
	require.Equal(t, "s3:PutObject", OpCompleteMultipartUpload.Permission())
	require.Equal(t, "s3:AbortMultipartUpload", OpAbortMultipartUpload.Permission())
	require.Equal(t, "s3:ListMultipartUploadParts", OpListMultipartUploadParts.Permission())
	require.Equal(t, "s3:ListBucketMultipartUploads", OpListBucketMultipartUploads.Permission())

	require.Empty(t, Operation("Unknown").Permission())
}
