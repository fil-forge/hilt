package auth

import (
	"slices"
	"testing"
	"time"

	"github.com/fil-forge/hilt/pkg/sigv4"
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
		// wantSrcVersion is the versionId the copy source names, if any.
		wantSrcVersion string
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
		{name: "get bucket policy", method: "GET", url: "https://s3.example.com/bkt?policy", want: OpGetBucketPolicy, wantBucket: "bkt"},
		{name: "put bucket policy", method: "PUT", url: "https://s3.example.com/bkt?policy=", want: OpPutBucketPolicy, wantBucket: "bkt"},
		{name: "delete bucket policy", method: "DELETE", url: "https://s3.example.com/bkt?policy", want: OpDeleteBucketPolicy, wantBucket: "bkt"},
		{name: "a policy query on an object is the object operation", method: "GET", url: "https://s3.example.com/bkt/k?policy", want: OpGetObject, wantBucket: "bkt", wantKey: "k"},
		{name: "a policy query on a HEAD is the bucket operation", method: "HEAD", url: "https://s3.example.com/bkt?policy", want: OpListBucket, wantBucket: "bkt"},

		// Multipart operations. Each of these classified as its plain-object
		// counterpart before the query string was taken into account.
		{name: "list multipart uploads", method: "GET", url: "https://s3.example.com/bkt?uploads", want: OpListBucketMultipartUploads, wantBucket: "bkt"},
		{name: "list parts", method: "GET", url: "https://s3.example.com/bkt/k?uploadId=abc", want: OpListMultipartUploadParts, wantBucket: "bkt", wantKey: "k"},
		{name: "create multipart upload", method: "POST", url: "https://s3.example.com/bkt/k?uploads", want: OpCreateMultipartUpload, wantBucket: "bkt", wantKey: "k"},
		{name: "upload part", method: "PUT", url: "https://s3.example.com/bkt/k?partNumber=1&uploadId=abc", want: OpUploadPart, wantBucket: "bkt", wantKey: "k"},
		{name: "complete multipart upload", method: "POST", url: "https://s3.example.com/bkt/k?uploadId=abc", want: OpCompleteMultipartUpload, wantBucket: "bkt", wantKey: "k"},
		{name: "abort multipart upload", method: "DELETE", url: "https://s3.example.com/bkt/k?uploadId=abc", want: OpAbortMultipartUpload, wantBucket: "bkt", wantKey: "k"},

		// Copies: a PUT of an object or a part naming a parseable x-amz-copy-source.
		// The header name is case-insensitive; the value may carry a leading slash
		// and URL-encoding, which the source parse strips, and a versionId suffix,
		// which names the source version; an empty one names none.
		{name: "copy object", method: "PUT", url: "https://s3.example.com/bkt/k", headers: map[string]string{"x-amz-copy-source": "src/obj"}, want: OpCopyObject, wantBucket: "bkt", wantKey: "k", wantSrc: "src/obj"},
		{name: "copy object, header name case", method: "PUT", url: "https://s3.example.com/bkt/k", headers: map[string]string{"X-Amz-Copy-Source": "/src/a%20b/c?versionId=v1"}, want: OpCopyObject, wantBucket: "bkt", wantKey: "k", wantSrc: "src/a b/c", wantSrcVersion: "v1"},
		{name: "copy of a version", method: "PUT", url: "https://s3.example.com/bkt/k", headers: map[string]string{"x-amz-copy-source": "src/obj?versionId=v1"}, want: OpCopyObject, wantBucket: "bkt", wantKey: "k", wantSrc: "src/obj", wantSrcVersion: "v1"},
		{name: "copy with an empty versionId names no version", method: "PUT", url: "https://s3.example.com/bkt/k", headers: map[string]string{"x-amz-copy-source": "src/obj?versionId="}, want: OpCopyObject, wantBucket: "bkt", wantKey: "k", wantSrc: "src/obj"},
		{name: "upload part copy of a version", method: "PUT", url: "https://s3.example.com/bkt/k?partNumber=2&uploadId=abc", headers: map[string]string{"x-amz-copy-source": "src/obj?versionId=v1"}, want: OpUploadPartCopy, wantBucket: "bkt", wantKey: "k", wantSrc: "src/obj", wantSrcVersion: "v1"},
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

		// A multipart subresource on a method the gateway does not route it on
		// is what the gateway makes of it: a part number on a POST is ignored,
		// so the shape is a complete, and `uploads` on a PUT is a plain put.
		{name: "part upload shape on POST is a complete", method: "POST", url: "https://s3.example.com/bkt/k?partNumber=1&uploadId=abc", want: OpCompleteMultipartUpload, wantBucket: "bkt", wantKey: "k"},
		{name: "initiate shape on PUT is not an initiate", method: "PUT", url: "https://s3.example.com/bkt/k?uploads", want: OpPutObject, wantBucket: "bkt", wantKey: "k"},

		// Unrelated query parameters do not change the classification, and the
		// multipart parameter names are case-sensitive.
		{name: "list objects with prefix", method: "GET", url: "https://s3.example.com/bkt?prefix=a/", want: OpListBucket, wantBucket: "bkt"},
		{name: "uploadid wrong case is not multipart", method: "DELETE", url: "https://s3.example.com/bkt/k?uploadid=abc", want: OpDeleteObject, wantBucket: "bkt", wantKey: "k"},

		// Object-lock and version-scoped shapes, named by the query parameters
		// the gateway routes on. Each has its own permission, so an access key
		// granted plain reads, writes or deletes does not get these too.
		{name: "list object versions", method: "GET", url: "https://s3.example.com/bkt?versions", want: OpListBucketVersions, wantBucket: "bkt"},
		// The bucket encryption configuration, distinguished by `encryption` on
		// the methods S3 defines for it.
		{name: "get bucket encryption", method: "GET", url: "https://s3.example.com/bkt?encryption", want: OpGetBucketEncryption, wantBucket: "bkt"},
		{name: "put bucket encryption", method: "PUT", url: "https://s3.example.com/bkt?encryption=", want: OpPutBucketEncryption, wantBucket: "bkt"},
		{name: "delete bucket encryption", method: "DELETE", url: "https://s3.example.com/bkt?encryption", want: OpDeleteBucketEncryption, wantBucket: "bkt"},
		{name: "an encryption query on a HEAD is the bucket operation", method: "HEAD", url: "https://s3.example.com/bkt?encryption", want: OpListBucket, wantBucket: "bkt"},
		{name: "an encryption query on an object is the object operation", method: "GET", url: "https://s3.example.com/bkt/k?encryption", want: OpGetObject, wantBucket: "bkt", wantKey: "k"},
		// Other query parameters, known to some operation or not, neither select
		// an operation nor conflict with one, and a subresource may carry a value.
		{name: "an unknown parameter is ignored", method: "GET", url: "https://s3.example.com/bkt?encryption&foo", want: OpGetBucketEncryption, wantBucket: "bkt"},
		{name: "an unknown parameter first is ignored", method: "GET", url: "https://s3.example.com/bkt?foo=bar&encryption", want: OpGetBucketEncryption, wantBucket: "bkt"},
		{name: "another operation's parameter is ignored", method: "GET", url: "https://s3.example.com/bkt?encryption&max-keys=1", want: OpGetBucketEncryption, wantBucket: "bkt"},
		{name: "a subresource with a value still selects", method: "GET", url: "https://s3.example.com/bkt?encryption=true", want: OpGetBucketEncryption, wantBucket: "bkt"},
		{name: "subresource names are case-sensitive", method: "GET", url: "https://s3.example.com/bkt?Encryption", want: OpListBucket, wantBucket: "bkt"},
		// DeleteObjects names its keys in the body and needs the delete
		// permission on the bucket, as each single delete does.
		{name: "delete objects", method: "POST", url: "https://s3.example.com/bkt?delete", want: OpDeleteObjects, wantBucket: "bkt"},
		// The bucket configuration, object tagging and attribute operations,
		// each under its own permission.
		{name: "get bucket location", method: "GET", url: "https://s3.example.com/bkt?location", want: OpGetBucketLocation, wantBucket: "bkt"},
		{name: "get bucket acl", method: "GET", url: "https://s3.example.com/bkt?acl", want: OpGetBucketAcl, wantBucket: "bkt"},
		{name: "get bucket cors", method: "GET", url: "https://s3.example.com/bkt?cors", want: OpGetBucketCors, wantBucket: "bkt"},
		{name: "get bucket policy status", method: "GET", url: "https://s3.example.com/bkt?policyStatus", want: OpGetBucketPolicyStatus, wantBucket: "bkt"},
		{name: "get bucket tagging", method: "GET", url: "https://s3.example.com/bkt?tagging", want: OpGetBucketTagging, wantBucket: "bkt"},
		{name: "put bucket tagging", method: "PUT", url: "https://s3.example.com/bkt?tagging", want: OpPutBucketTagging, wantBucket: "bkt"},
		{name: "delete bucket tagging", method: "DELETE", url: "https://s3.example.com/bkt?tagging", want: OpDeleteBucketTagging, wantBucket: "bkt"},
		{name: "get bucket versioning", method: "GET", url: "https://s3.example.com/bkt?versioning", want: OpGetBucketVersioning, wantBucket: "bkt"},
		{name: "put bucket versioning", method: "PUT", url: "https://s3.example.com/bkt?versioning", want: OpPutBucketVersioning, wantBucket: "bkt"},
		{name: "get object lock configuration", method: "GET", url: "https://s3.example.com/bkt?object-lock", want: OpGetObjectLockConfiguration, wantBucket: "bkt"},
		{name: "put object lock configuration", method: "PUT", url: "https://s3.example.com/bkt?object-lock", want: OpPutObjectLockConfiguration, wantBucket: "bkt"},
		{name: "get object tagging", method: "GET", url: "https://s3.example.com/bkt/k?tagging", want: OpGetObjectTagging, wantBucket: "bkt", wantKey: "k"},
		{name: "get object tagging of a version", method: "GET", url: "https://s3.example.com/bkt/k?tagging&versionId=v", want: OpGetObjectTagging, wantBucket: "bkt", wantKey: "k"},
		{name: "put object tagging", method: "PUT", url: "https://s3.example.com/bkt/k?tagging", want: OpPutObjectTagging, wantBucket: "bkt", wantKey: "k"},
		{name: "put object tagging is not a copy", method: "PUT", url: "https://s3.example.com/bkt/k?tagging", headers: map[string]string{"x-amz-copy-source": "src/obj"}, want: OpPutObjectTagging, wantBucket: "bkt", wantKey: "k"},
		{name: "delete object tagging", method: "DELETE", url: "https://s3.example.com/bkt/k?tagging", want: OpDeleteObjectTagging, wantBucket: "bkt", wantKey: "k"},
		{name: "get object attributes", method: "GET", url: "https://s3.example.com/bkt/k?attributes", want: OpGetObjectAttributes, wantBucket: "bkt", wantKey: "k"},
		// A subresource the router does not route on for the method or path is
		// the plain operation there, as it is in the router.
		{name: "uploads on a bucket PUT is a bucket create", method: "PUT", url: "https://s3.example.com/bkt?uploads", want: OpCreateBucket, wantBucket: "bkt"},
		{name: "delete on a bucket DELETE is a bucket delete", method: "DELETE", url: "https://s3.example.com/bkt?delete", want: OpDeleteBucket, wantBucket: "bkt"},
		{name: "a head ignores its subresource", method: "HEAD", url: "https://s3.example.com/bkt/k?retention", want: OpGetObject, wantBucket: "bkt", wantKey: "k"},
		{name: "a head names a version", method: "HEAD", url: "https://s3.example.com/bkt/k?versionId=v", want: OpGetObjectVersion, wantBucket: "bkt", wantKey: "k"},
		{name: "get object version", method: "GET", url: "https://s3.example.com/bkt/k?versionId=v", want: OpGetObjectVersion, wantBucket: "bkt", wantKey: "k"},
		{name: "get object retention", method: "GET", url: "https://s3.example.com/bkt/k?retention", want: OpGetObjectRetention, wantBucket: "bkt", wantKey: "k"},
		{name: "get object legal hold", method: "GET", url: "https://s3.example.com/bkt/k?legal-hold", want: OpGetObjectLegalHold, wantBucket: "bkt", wantKey: "k"},
		{name: "put object retention", method: "PUT", url: "https://s3.example.com/bkt/k?retention", want: OpPutObjectRetention, wantBucket: "bkt", wantKey: "k"},
		{name: "put object legal hold", method: "PUT", url: "https://s3.example.com/bkt/k?legal-hold", want: OpPutObjectLegalHold, wantBucket: "bkt", wantKey: "k"},
		{name: "delete object version", method: "DELETE", url: "https://s3.example.com/bkt/k?versionId=v", want: OpDeleteObjectVersion, wantBucket: "bkt", wantKey: "k"},

		// A lock parameter decides the operation on its own: there is no
		// version-scoped variant of the lock permissions to fall to.
		{name: "retention on a named version is a retention write", method: "PUT", url: "https://s3.example.com/bkt/k?retention&versionId=v", want: OpPutObjectRetention, wantBucket: "bkt", wantKey: "k"},
		{name: "legal hold on a named version is a legal hold read", method: "GET", url: "https://s3.example.com/bkt/k?legal-hold&versionId=v", want: OpGetObjectLegalHold, wantBucket: "bkt", wantKey: "k"},

		// A lock parameter on a method the gateway does not route it on is not
		// a lock operation: the gateway performs the plain-object operation. A
		// PUT carrying one is a lock write rather than a copy.
		{name: "retention on DELETE is not a retention write", method: "DELETE", url: "https://s3.example.com/bkt/k?retention", want: OpDeleteObject, wantBucket: "bkt", wantKey: "k"},
		{name: "copy source on a retention write is a retention write", method: "PUT", url: "https://s3.example.com/bkt/k?retention", headers: map[string]string{"x-amz-copy-source": "src/obj"}, want: OpPutObjectRetention, wantBucket: "bkt", wantKey: "k"},

		// The parameter names are case-sensitive, as the multipart ones are,
		// and an empty versionId names no version.
		{name: "versionid wrong case is a plain get", method: "GET", url: "https://s3.example.com/bkt/k?versionid=v", want: OpGetObject, wantBucket: "bkt", wantKey: "k"},
		{name: "empty versionId is a plain delete", method: "DELETE", url: "https://s3.example.com/bkt/k?versionId=", want: OpDeleteObject, wantBucket: "bkt", wantKey: "k"},

		// An abort names its upload, so it is an abort before it is a version
		// delete.
		{name: "abort with a version id is an abort", method: "DELETE", url: "https://s3.example.com/bkt/k?uploadId=abc&versionId=v", want: OpAbortMultipartUpload, wantBucket: "bkt", wantKey: "k"},

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
			require.Equal(t, tt.wantSrcVersion, c.srcVersionID)
		})
	}

	t.Run("refuses a query naming two subresources, whatever their order", func(t *testing.T) {
		for _, tc := range []struct{ method, url, want string }{
			{"GET", "https://s3.example.com/bkt?uploads&encryption", "encryption, uploads"},
			{"GET", "https://s3.example.com/bkt?encryption&uploads", "encryption, uploads"},
			{"GET", "https://s3.example.com/bkt?versions&encryption", "encryption, versions"},
			{"GET", "https://s3.example.com/bkt?policy&encryption", "encryption, policy"},
			{"HEAD", "https://s3.example.com/bkt?uploads&encryption", "encryption, uploads"},
			{"PUT", "https://s3.example.com/bkt?policy&encryption", "encryption, policy"},
			{"DELETE", "https://s3.example.com/bkt?encryption&policy", "encryption, policy"},
			{"GET", "https://s3.example.com/bkt/k?retention&legal-hold", "legal-hold, retention"},
			{"GET", "https://s3.example.com/bkt/k?uploadId=abc&uploads", "uploadId, uploads"},
		} {
			_, err := classifyRequest(s3.Request{Method: tc.method, URL: tc.url})
			require.ErrorIs(t, err, ErrConflictingQuery, "%s %s", tc.method, tc.url)
			require.ErrorContains(t, err, tc.want, "%s %s", tc.method, tc.url)
		}
	})

	t.Run("refuses a subresource the gateway does not serve", func(t *testing.T) {
		for _, tc := range []struct{ method, url, name string }{
			{"GET", "https://s3.example.com/bkt?lifecycle", "lifecycle"},
			{"PUT", "https://s3.example.com/bkt?website", "website"},
			{"DELETE", "https://s3.example.com/bkt?replication", "replication"},
			{"GET", "https://s3.example.com/bkt?ownershipControls&foo=bar", "ownershipControls"},
			{"POST", "https://s3.example.com/bkt/k?restore", "restore"},
			{"POST", "https://s3.example.com/bkt/k?select&select-type=2", "select"},
			{"GET", "https://s3.example.com/bkt/k?torrent", "torrent"},
		} {
			_, err := classifyRequest(s3.Request{Method: tc.method, URL: tc.url})
			require.ErrorIs(t, err, ErrUnsupportedOperation, "%s %s", tc.method, tc.url)
			require.ErrorContains(t, err, tc.name, "%s %s", tc.method, tc.url)
		}
		// Two subresources conflict whether supported or not.
		_, err := classifyRequest(s3.Request{Method: "GET", URL: "https://s3.example.com/bkt?lifecycle&versioning"})
		require.ErrorIs(t, err, ErrConflictingQuery)
		require.ErrorContains(t, err, "lifecycle, versioning")
	})

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

	// A supported subresource on a method whose route the gateway has but
	// Hilt does not authorize is refused, rather than classified as the plain
	// bucket or object operation it would otherwise look like. So is a POST
	// naming no route, and either half of a part upload alone on a PUT, which
	// the gateway answers with an error.
	t.Run("refuses a route Hilt does not authorize", func(t *testing.T) {
		for _, req := range []s3.Request{
			{Method: "PUT", URL: "https://s3.example.com/bkt?cors"},
			{Method: "DELETE", URL: "https://s3.example.com/bkt?cors"},
			{Method: "PUT", URL: "https://s3.example.com/bkt?acl"},
			{Method: "GET", URL: "https://s3.example.com/bkt/k?acl"},
			{Method: "PUT", URL: "https://s3.example.com/bkt/k?acl"},
			{Method: "GET", URL: "https://s3.example.com/bkt/k?uploads"},
			{Method: "GET", URL: "https://s3.example.com/bkt/k?versions"},
			{Method: "PUT", URL: "https://s3.example.com/bkt/k?uploadId=abc"},
			{Method: "PUT", URL: "https://s3.example.com/bkt/k?uploadId=abc&partNo=1"},
			{Method: "POST", URL: "https://s3.example.com/bkt"},
			{Method: "POST", URL: "https://s3.example.com/bkt?encryption"},
			{Method: "POST", URL: "https://s3.example.com/bkt/k"},
			{Method: "POST", URL: "https://s3.example.com/bkt/k?retention"},
		} {
			_, err := classifyRequest(req)
			require.ErrorIs(t, err, ErrUnsupportedOperation, "%s %s", req.Method, req.URL)
		}
	})
}

// TestRequirementsFor covers the gateway's local view of what a request
// needs: one bucket/permission pair for an ordinary operation, a second for
// the copy source, a companion permission or a header that adds one, none
// for operations that address no existing bucket, and a refusal when a
// header a decision was taken from is not signed.
func TestRequirementsFor(t *testing.T) {
	// presigned signs the request with every header it carries covered.
	presigned := func(method, url string, headers map[string]string, unsigned ...string) s3.Request {
		t.Helper()
		var signed []string
		for name := range headers {
			if !slices.Contains(unsigned, name) {
				signed = append(signed, name)
			}
		}
		req, err := sigv4.Presign(sigv4.Request{Method: method, URL: url, Headers: headers}, "AKIATEST", "secret", "us-east-1", sigv4.SchemeV4, time.Now(), time.Hour, sigv4.WithSignedHeaders(signed...))
		require.NoError(t, err)
		return s3.Request{Method: req.Method, URL: req.URL, Headers: headers}
	}
	requirements := func(method, url string, headers map[string]string) Requirements {
		t.Helper()
		r, err := RequirementsFor(presigned(method, url, headers))
		require.NoError(t, err)
		return r
	}
	copyHdr := map[string]string{"x-amz-copy-source": "src/obj"}

	r := requirements("PUT", "https://s3.example.com/bkt/k", copyHdr)
	require.Equal(t, OpCopyObject, r.Operation)
	require.Equal(t, []Requirement{{Bucket: "bkt", Permission: "s3:PutObject"}, {Bucket: "src", Permission: SourcePermission}}, r.Buckets)

	r = requirements("PUT", "https://s3.example.com/bkt/k?partNumber=1&uploadId=abc", copyHdr)
	require.Equal(t, OpUploadPartCopy, r.Operation)
	require.Equal(t, []Requirement{{Bucket: "bkt", Permission: "s3:PutObject"}, {Bucket: "src", Permission: SourcePermission}}, r.Buckets)

	// A source naming a version needs the version read there instead.
	versionHdr := map[string]string{"x-amz-copy-source": "src/obj?versionId=v1"}
	r = requirements("PUT", "https://s3.example.com/bkt/k", versionHdr)
	require.Equal(t, OpCopyObject, r.Operation)
	require.Equal(t, []Requirement{{Bucket: "bkt", Permission: "s3:PutObject"}, {Bucket: "src", Permission: SourceVersionPermission}}, r.Buckets)

	r = requirements("PUT", "https://s3.example.com/bkt/k?partNumber=1&uploadId=abc", versionHdr)
	require.Equal(t, OpUploadPartCopy, r.Operation)
	require.Equal(t, []Requirement{{Bucket: "bkt", Permission: "s3:PutObject"}, {Bucket: "src", Permission: SourceVersionPermission}}, r.Buckets)

	r = requirements("GET", "https://s3.example.com/bkt/k", nil)
	require.Equal(t, OpGetObject, r.Operation)
	require.Equal(t, []Requirement{{Bucket: "bkt", Permission: "s3:GetObject"}}, r.Buckets)

	// Reading an object's attributes needs the object read too, on the same
	// bucket, as S3 requires.
	r = requirements("GET", "https://s3.example.com/bkt/k?attributes", nil)
	require.Equal(t, OpGetObjectAttributes, r.Operation)
	require.Equal(t, []Requirement{{Bucket: "bkt", Permission: "s3:GetObjectAttributes"}, {Bucket: "bkt", Permission: "s3:GetObject"}}, r.Buckets)

	// A header that adds a permission puts it on the addressed bucket, after
	// the operation's own and before the copy source's.
	r = requirements("PUT", "https://s3.example.com/bkt/k", map[string]string{"x-amz-object-lock-mode": "GOVERNANCE"})
	require.Equal(t, OpPutObject, r.Operation)
	require.Equal(t, []Requirement{{Bucket: "bkt", Permission: "s3:PutObject"}, {Bucket: "bkt", Permission: "s3:PutObjectRetention"}}, r.Buckets)

	r = requirements("PUT", "https://s3.example.com/bkt/k", map[string]string{"x-amz-copy-source": "src/obj", "x-amz-tagging-directive": "REPLACE"})
	require.Equal(t, OpCopyObject, r.Operation)
	require.Equal(t, []Requirement{{Bucket: "bkt", Permission: "s3:PutObject"}, {Bucket: "bkt", Permission: "s3:PutObjectTagging"}, {Bucket: "src", Permission: SourcePermission}}, r.Buckets)

	// CreateBucket addresses no existing bucket, so it yields no pair for
	// the gateway to check locally, with or without the Object Lock flag.
	r = requirements("PUT", "https://s3.example.com/bkt", map[string]string{"x-amz-bucket-object-lock-enabled": "true"})
	require.Equal(t, OpCreateBucket, r.Operation)
	require.Empty(t, r.Buckets)

	for _, req := range []s3.Request{
		presigned("GET", "https://s3.example.com/", nil),
		presigned("PUT", "https://s3.example.com/bkt", nil),
	} {
		r, err := RequirementsFor(req)
		require.NoError(t, err)
		require.Empty(t, r.Buckets, "%s %s", req.Method, req.URL)
	}

	// A header a decision was taken from that the signature does not cover
	// is refused by name, as Authorize refuses it; the rest of the request
	// is not decided on. A request deciding on no header needs no signature
	// at all to be read.
	for _, tt := range []struct {
		name    string
		method  string
		url     string
		headers map[string]string
		leave   string
	}{
		{"copy source", "PUT", "https://s3.example.com/bkt/k", map[string]string{"x-amz-copy-source": "src/obj"}, "x-amz-copy-source"},
		{"lock mode", "PUT", "https://s3.example.com/bkt/k", map[string]string{"x-amz-object-lock-mode": "GOVERNANCE", "x-amz-tagging": "k=v"}, "x-amz-object-lock-mode"},
		{"replacement tags", "PUT", "https://s3.example.com/bkt/k", map[string]string{"x-amz-copy-source": "src/obj", "x-amz-tagging-directive": "REPLACE", "x-amz-tagging": "k=v"}, "x-amz-tagging"},
		{"object lock flag", "PUT", "https://s3.example.com/bkt", map[string]string{"x-amz-bucket-object-lock-enabled": "true"}, "x-amz-bucket-object-lock-enabled"},
	} {
		t.Run(tt.name+" unsigned", func(t *testing.T) {
			_, err := RequirementsFor(presigned(tt.method, tt.url, tt.headers, tt.leave))
			require.ErrorIs(t, err, ErrUnsignedHeader)
			require.ErrorContains(t, err, tt.leave)
		})
	}
	_, err := RequirementsFor(s3.Request{Method: "PUT", URL: "https://s3.example.com/bkt/k", Headers: copyHdr})
	require.Error(t, err, "an unsigned request names a copy source it cannot be trusted on")
	require.NotErrorIs(t, err, ErrUnsignedHeader)
	r, err = RequirementsFor(s3.Request{Method: "GET", URL: "https://s3.example.com/bkt/k"})
	require.NoError(t, err)
	require.Equal(t, OpGetObject, r.Operation)

	_, err = RequirementsFor(s3.Request{Method: "PATCH", URL: "https://s3.example.com/bkt/k"})
	require.Error(t, err)

	// The gateway sees the refusal of two subresources by its name, so it can
	// answer it without consulting hilt, and before any signature is read.
	_, err = RequirementsFor(s3.Request{Method: "GET", URL: "https://s3.example.com/bkt?uploads&encryption"})
	require.ErrorIs(t, err, ErrConflictingQuery)
}

// TestReadHeaders covers the permissions a request's headers add to its
// operation, and the headers recorded as decided from: the lock and tagging
// headers on the three writes that create a version, the Object Lock flag
// on CreateBucket, and nothing anywhere else.
func TestReadHeaders(t *testing.T) {
	for _, tt := range []struct {
		name        string
		method, url string
		headers     map[string]string
		wantPerms   []string
		wantHeaders []string
	}{
		{name: "put with a lock mode", method: "PUT", url: "https://s3.example.com/bkt/k",
			headers:   map[string]string{"x-amz-object-lock-mode": "GOVERNANCE"},
			wantPerms: []string{"s3:PutObjectRetention"}, wantHeaders: []string{"x-amz-object-lock-mode"}},
		{name: "put with a retain-until date alone", method: "PUT", url: "https://s3.example.com/bkt/k",
			headers:   map[string]string{"x-amz-object-lock-retain-until-date": "2030-01-01T00:00:00Z"},
			wantPerms: []string{"s3:PutObjectRetention"}, wantHeaders: []string{"x-amz-object-lock-retain-until-date"}},
		{name: "put with a legal hold", method: "PUT", url: "https://s3.example.com/bkt/k",
			headers:   map[string]string{"x-amz-object-lock-legal-hold": "ON"},
			wantPerms: []string{"s3:PutObjectLegalHold"}, wantHeaders: []string{"x-amz-object-lock-legal-hold"}},
		{name: "put with tags", method: "PUT", url: "https://s3.example.com/bkt/k",
			headers:   map[string]string{"x-amz-tagging": "k=v"},
			wantPerms: []string{"s3:PutObjectTagging"}, wantHeaders: []string{"x-amz-tagging"}},
		{name: "put with every header, names each once", method: "PUT", url: "https://s3.example.com/bkt/k",
			headers: map[string]string{
				"X-Amz-Object-Lock-Mode": "COMPLIANCE", "x-amz-object-lock-retain-until-date": "2030-01-01T00:00:00Z",
				"x-amz-object-lock-legal-hold": "OFF", "x-amz-tagging": "k=v",
			},
			wantPerms:   []string{"s3:PutObjectRetention", "s3:PutObjectLegalHold", "s3:PutObjectTagging"},
			wantHeaders: []string{"x-amz-object-lock-mode", "x-amz-object-lock-retain-until-date", "x-amz-object-lock-legal-hold", "x-amz-tagging"}},
		{name: "an empty header value is absent", method: "PUT", url: "https://s3.example.com/bkt/k",
			headers: map[string]string{"x-amz-object-lock-mode": "", "x-amz-tagging": ""}},
		{name: "create multipart upload with a lock and tags", method: "POST", url: "https://s3.example.com/bkt/k?uploads",
			headers:     map[string]string{"x-amz-object-lock-legal-hold": "ON", "x-amz-tagging": "k=v"},
			wantPerms:   []string{"s3:PutObjectLegalHold", "s3:PutObjectTagging"},
			wantHeaders: []string{"x-amz-object-lock-legal-hold", "x-amz-tagging"}},
		{name: "copy with a lock mode", method: "PUT", url: "https://s3.example.com/bkt/k",
			headers:     map[string]string{"x-amz-copy-source": "src/obj", "x-amz-object-lock-mode": "GOVERNANCE"},
			wantPerms:   []string{"s3:PutObjectRetention"},
			wantHeaders: []string{"x-amz-copy-source", "x-amz-object-lock-mode"}},
		{name: "copy replacing the tags", method: "PUT", url: "https://s3.example.com/bkt/k",
			headers:     map[string]string{"x-amz-copy-source": "src/obj", "x-amz-tagging-directive": "REPLACE", "x-amz-tagging": "k=v"},
			wantPerms:   []string{"s3:PutObjectTagging"},
			wantHeaders: []string{"x-amz-copy-source", "x-amz-tagging-directive", "x-amz-tagging"}},
		{name: "copy replacing the tags with none", method: "PUT", url: "https://s3.example.com/bkt/k",
			headers:     map[string]string{"x-amz-copy-source": "src/obj", "x-amz-tagging-directive": "REPLACE"},
			wantPerms:   []string{"s3:PutObjectTagging"},
			wantHeaders: []string{"x-amz-copy-source", "x-amz-tagging-directive"}},
		{name: "copy carrying the tags, which the gateway ignores", method: "PUT", url: "https://s3.example.com/bkt/k",
			headers:     map[string]string{"x-amz-copy-source": "src/obj", "x-amz-tagging-directive": "COPY", "x-amz-tagging": "k=v"},
			wantHeaders: []string{"x-amz-copy-source"}},
		{name: "copy with tags and no directive", method: "PUT", url: "https://s3.example.com/bkt/k",
			headers:     map[string]string{"x-amz-copy-source": "src/obj", "x-amz-tagging": "k=v"},
			wantHeaders: []string{"x-amz-copy-source"}},
		{name: "the directive is compared exactly", method: "PUT", url: "https://s3.example.com/bkt/k",
			headers:     map[string]string{"x-amz-copy-source": "src/obj", "x-amz-tagging-directive": "replace"},
			wantHeaders: []string{"x-amz-copy-source"}},
		{name: "upload part ignores the lock headers", method: "PUT", url: "https://s3.example.com/bkt/k?partNumber=1&uploadId=abc",
			headers: map[string]string{"x-amz-object-lock-mode": "GOVERNANCE", "x-amz-tagging": "k=v"}},
		{name: "upload part copy ignores them too", method: "PUT", url: "https://s3.example.com/bkt/k?partNumber=1&uploadId=abc",
			headers:     map[string]string{"x-amz-copy-source": "src/obj", "x-amz-object-lock-mode": "GOVERNANCE", "x-amz-tagging-directive": "REPLACE"},
			wantHeaders: []string{"x-amz-copy-source"}},
		{name: "complete multipart upload ignores them", method: "POST", url: "https://s3.example.com/bkt/k?uploadId=abc",
			headers: map[string]string{"x-amz-object-lock-mode": "GOVERNANCE", "x-amz-tagging": "k=v"}},
		{name: "a read ignores them", method: "GET", url: "https://s3.example.com/bkt/k",
			headers: map[string]string{"x-amz-object-lock-mode": "GOVERNANCE", "x-amz-tagging": "k=v"}},
		{name: "create bucket with object lock enabled", method: "PUT", url: "https://s3.example.com/bkt",
			headers:     map[string]string{"x-amz-bucket-object-lock-enabled": "true"},
			wantPerms:   []string{"s3:PutBucketVersioning", "s3:PutBucketObjectLockConfiguration"},
			wantHeaders: []string{"x-amz-bucket-object-lock-enabled"}},
		{name: "the flag is read case-insensitively", method: "PUT", url: "https://s3.example.com/bkt",
			headers:     map[string]string{"X-Amz-Bucket-Object-Lock-Enabled": "TRUE"},
			wantPerms:   []string{"s3:PutBucketVersioning", "s3:PutBucketObjectLockConfiguration"},
			wantHeaders: []string{"x-amz-bucket-object-lock-enabled"}},
		{name: "create bucket with object lock disabled", method: "PUT", url: "https://s3.example.com/bkt",
			headers: map[string]string{"x-amz-bucket-object-lock-enabled": "false"}},
		{name: "put object ignores the bucket flag", method: "PUT", url: "https://s3.example.com/bkt/k",
			headers: map[string]string{"x-amz-bucket-object-lock-enabled": "true"}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			c, err := classifyRequest(s3.Request{Method: tt.method, URL: tt.url, Headers: tt.headers})
			require.NoError(t, err)
			require.Equal(t, tt.wantPerms, c.headerPermissions)
			require.Equal(t, tt.wantHeaders, c.headers)
			require.Equal(t, append(c.op.Permissions(), tt.wantPerms...), c.permissions())
		})
	}
}

// TestOperationPermission asserts every operation requires a permission, so a new
// operation cannot be added without an operationPermission entry — an operation
// with no permission would pass the access key's permission check unconditionally.
func TestOperationPermission(t *testing.T) {
	ops := []Operation{
		OpListBuckets, OpListBucket, OpGetObject, OpPutObject, OpCopyObject, OpCreateBucket,
		OpDeleteObject, OpDeleteBucket,
		OpGetObjectVersion, OpGetObjectRetention, OpGetObjectLegalHold,
		OpPutObjectRetention, OpPutObjectLegalHold, OpDeleteObjectVersion, OpDeleteObjects, OpListBucketVersions,
		OpGetBucketPolicy, OpPutBucketPolicy, OpDeleteBucketPolicy,
		OpGetBucketEncryption, OpPutBucketEncryption, OpDeleteBucketEncryption,
		OpCreateMultipartUpload, OpUploadPart, OpUploadPartCopy, OpCompleteMultipartUpload,
		OpAbortMultipartUpload, OpListMultipartUploadParts, OpListBucketMultipartUploads,
		OpGetBucketLocation, OpGetBucketAcl, OpGetBucketCors, OpGetBucketPolicyStatus,
		OpGetBucketTagging, OpPutBucketTagging, OpDeleteBucketTagging,
		OpGetBucketVersioning, OpPutBucketVersioning,
		OpGetObjectLockConfiguration, OpPutObjectLockConfiguration,
		OpGetObjectTagging, OpPutObjectTagging, OpDeleteObjectTagging, OpGetObjectAttributes,
	}
	require.Len(t, operationPermission, len(ops), "every operation constant must be listed here")
	for _, op := range ops {
		require.NotEmpty(t, op.Permission(), "operation %s has no required permission", op)
	}

	// The multipart write operations share s3:PutObject, so a key that can already
	// put an object can perform them without being re-issued.
	require.Equal(t, "s3:PutObject", OpCreateMultipartUpload.Permission())
	require.Equal(t, "s3:PutObject", OpUploadPart.Permission())
	// The copies write their destination like a put; the source's read
	// permission is a separate requirement.
	require.Equal(t, "s3:PutObject", OpCopyObject.Permission())
	require.Equal(t, "s3:PutObject", OpUploadPartCopy.Permission())
	require.Equal(t, "s3:GetObject", SourcePermission)
	require.Equal(t, "s3:GetObjectVersion", SourceVersionPermission)
	require.True(t, OpCopyObject.CopiesSource())
	require.True(t, OpUploadPartCopy.CopiesSource())
	require.False(t, OpPutObject.CopiesSource())
	require.Equal(t, "s3:PutObject", OpCompleteMultipartUpload.Permission())
	require.Equal(t, "s3:AbortMultipartUpload", OpAbortMultipartUpload.Permission())
	require.Equal(t, "s3:ListMultipartUploadParts", OpListMultipartUploadParts.Permission())
	require.Equal(t, "s3:ListBucketMultipartUploads", OpListBucketMultipartUploads.Permission())

	// Removing the bucket's tags needs the permission that writes them.
	require.Equal(t, "s3:PutBucketTagging", OpDeleteBucketTagging.Permission())

	// Reading an object's attributes needs the object read as well; every
	// other operation needs only its own permission on its bucket, and a
	// companion is always something a key can hold.
	require.Equal(t, []string{"s3:GetObjectAttributes", "s3:GetObject"}, OpGetObjectAttributes.Permissions())
	for _, op := range ops {
		perms := op.Permissions()
		require.Equal(t, op.Permission(), perms[0], "operation %s", op)
		if op != OpGetObjectAttributes {
			require.Len(t, perms, 1, "operation %s", op)
		}
	}
	for op, companion := range companionPermission {
		require.Contains(t, ops, op, "companion for an unlisted operation %s", op)
		require.NotEqual(t, op.Permission(), companion, "operation %s names its own permission as its companion", op)
	}

	require.Empty(t, Operation("Unknown").Permission())
}

// TestRoutesAddressExistingBuckets asserts every operation a subresource
// routes to is checked against the bucket it addresses. CreateBucket skips
// that check because its bucket does not exist yet, so an operation that
// classified as it would be authorized on any bucket in the tenant.
func TestRoutesAddressExistingBuckets(t *testing.T) {
	for _, routes := range []map[string]map[string]Operation{bucketRoutes, objectRoutes} {
		for method, bySubresource := range routes {
			for name, op := range bySubresource {
				require.True(t, subresources[name], "%s ?%s routes on a subresource marked unsupported", method, name)
				if op == "" {
					continue
				}
				require.NotEmpty(t, op.Permission(), "%s ?%s", method, name)
				require.True(t, op.addressesExistingBucket(), "%s ?%s classifies as %s", method, name, op)
			}
		}
	}
}
