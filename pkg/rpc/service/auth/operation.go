package auth

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"

	s3 "github.com/fil-forge/libforge/commands/s3"
)

// Operation is the S3 operation a request performs, derived from its HTTP method,
// path and, for the copy operations, the x-amz-copy-source header.
// [Authorizer.Authorize] classifies it, checks the access key is permitted to
// perform it, and returns it on [AuthorizedRequest.Operation] so a handler can
// confirm the request matches the operation it serves.
type Operation string

const (
	OpListBuckets  Operation = "ListBuckets"  // GET, no bucket in path
	OpListBucket   Operation = "ListBucket"   // GET, bucket, no key (list objects)
	OpGetObject    Operation = "GetObject"    // GET, bucket + key
	OpPutObject    Operation = "PutObject"    // PUT/POST, bucket + key
	OpCopyObject   Operation = "CopyObject"   // PUT, bucket + key, x-amz-copy-source
	OpCreateBucket Operation = "CreateBucket" // PUT/POST, bucket, no key
	OpDeleteObject Operation = "DeleteObject" // DELETE, bucket + key
	OpDeleteBucket Operation = "DeleteBucket" // DELETE, bucket, no key

	// Multipart upload operations, distinguished from their plain-object
	// counterparts by the query parameters on the signed URL.
	OpCreateMultipartUpload      Operation = "CreateMultipartUpload"      // POST, bucket + key, ?uploads
	OpUploadPart                 Operation = "UploadPart"                 // PUT, bucket + key, ?uploadId&partNumber
	OpUploadPartCopy             Operation = "UploadPartCopy"             // UploadPart with x-amz-copy-source
	OpCompleteMultipartUpload    Operation = "CompleteMultipartUpload"    // POST, bucket + key, ?uploadId
	OpAbortMultipartUpload       Operation = "AbortMultipartUpload"       // DELETE, bucket + key, ?uploadId
	OpListMultipartUploadParts   Operation = "ListMultipartUploadParts"   // GET, bucket + key, ?uploadId
	OpListBucketMultipartUploads Operation = "ListBucketMultipartUploads" // GET, bucket, no key, ?uploads
)

// operationPermission maps each operation to the S3 permission an access key
// must hold to perform it. The multipart permissions follow the S3 API
// requirements: initiating, uploading a part and completing an upload all
// require s3:PutObject, while stopping and listing have their own permissions.
var operationPermission = map[Operation]string{
	OpListBuckets:  "s3:ListAllMyBuckets",
	OpListBucket:   "s3:ListBucket",
	OpGetObject:    "s3:GetObject",
	OpPutObject:    "s3:PutObject",
	OpCopyObject:   "s3:PutObject",
	OpCreateBucket: "s3:CreateBucket",
	OpDeleteObject: "s3:DeleteObject",
	OpDeleteBucket: "s3:DeleteBucket",

	OpCreateMultipartUpload:      "s3:PutObject",
	OpUploadPart:                 "s3:PutObject",
	OpUploadPartCopy:             "s3:PutObject",
	OpCompleteMultipartUpload:    "s3:PutObject",
	OpAbortMultipartUpload:       "s3:AbortMultipartUpload",
	OpListMultipartUploadParts:   "s3:ListMultipartUploadParts",
	OpListBucketMultipartUploads: "s3:ListBucketMultipartUploads",
}

// Permission returns the S3 permission an access key must hold to perform the
// operation on the bucket it addresses. Callers that map permissions to Forge
// commands (see the `/s3/request/authorize` handler) use it to avoid re-deriving
// the permission. For the copy operations this is the destination's permission;
// the source's is [SourcePermission].
func (o Operation) Permission() string { return operationPermission[o] }

// SourcePermission is the S3 permission an access key must additionally hold,
// on the copy source's bucket, to perform CopyObject or UploadPartCopy: S3
// requires read access to the object being copied.
const SourcePermission = "s3:GetObject"

// CopiesSource reports whether the operation reads a copy source named by the
// x-amz-copy-source header, and so needs [SourcePermission] on that bucket.
func (o Operation) CopiesSource() bool {
	return o == OpCopyObject || o == OpUploadPartCopy
}

func (o Operation) String() string { return string(o) }

// addressesExistingBucket reports whether the operation acts on a bucket that must
// already exist, so it can be resolved and scope-checked. ListBuckets addresses no
// bucket; CreateBucket's bucket does not exist yet. Every multipart operation acts
// on an existing bucket — an upload cannot be initiated into one that does not.
func (o Operation) addressesExistingBucket() bool {
	switch o {
	case OpListBucket, OpGetObject, OpPutObject, OpCopyObject, OpDeleteObject, OpDeleteBucket,
		OpCreateMultipartUpload, OpUploadPart, OpUploadPartCopy, OpCompleteMultipartUpload,
		OpAbortMultipartUpload, OpListMultipartUploadParts, OpListBucketMultipartUploads:
		return true
	default:
		return false
	}
}

// OperationFor classifies the S3 operation addressed by a request. See
// [classifyRequest] for the method/path rules.
func OperationFor(req s3.Request) (Operation, error) {
	c, err := classifyRequest(req)
	return c.op, err
}

// Requirement is one bucket an access key must be permitted to act on, with the
// S3 permission it needs there, for a request to be authorized.
type Requirement struct {
	Bucket     string
	Permission string
}

// RequirementsFor classifies a request and returns every bucket/permission pair
// it needs: the addressed bucket with the operation's permission, plus, for the
// copy operations, the copy source's bucket with [SourcePermission]. Operations
// that address no existing bucket (ListBuckets, CreateBucket) yield none. It is
// the local mirror of the checks [Authorizer.Authorize] performs, for a gateway
// authorizing over cached delegations; such a caller must also confirm the
// x-amz-copy-source header is covered by the signature (see
// [sigv4.SignedRequest.HeaderSigned]), as Authorize does.
func RequirementsFor(req s3.Request) (Operation, []Requirement, error) {
	c, err := classifyRequest(req)
	if err != nil {
		return "", nil, err
	}
	if !c.op.addressesExistingBucket() {
		return c.op, nil, nil
	}
	reqs := []Requirement{{Bucket: c.bucket, Permission: c.op.Permission()}}
	if c.op.CopiesSource() {
		reqs = append(reqs, Requirement{Bucket: c.srcBucket, Permission: SourcePermission})
	}
	return c.op, reqs, nil
}

// copySourceHeader names the copy source of a CopyObject / UploadPartCopy
// request: "bucket/key", optionally with a leading slash, URL-encoded, with an
// optional "?versionId=" suffix.
const copySourceHeader = "x-amz-copy-source"

// classification is what classifyRequest derives from a request: the operation,
// the bucket and key it addresses, and for the copy operations the bucket and
// key named by x-amz-copy-source.
type classification struct {
	op          Operation
	bucket, key string
	// srcBucket and srcKey are set only when op.CopiesSource().
	srcBucket, srcKey string
}

// classifyRequest determines the S3 operation and the addressed bucket/object key
// from a request's HTTP method, path-style URL (https://<host>/<bucket>/<key...>) and
// query parameters. Both the path and the query string are part of the SigV4-signed
// canonical request (see sigv4.canonicalQueryString), so once the signature is
// verified the classification is bound to what the caller signed. It returns an
// error for method/path combinations that map to no supported operation.
//
// Multipart uploads are distinguished only by their query parameters — S3 spells
// them `uploads`, `uploadId` and `partNumber`, and the names are case-sensitive.
// Those branches are checked before the plain-object fallbacks they shadow, and
// each is reachable only via the method S3 defines for it: a part is uploaded with
// PUT, while an upload is initiated and completed with POST. A shape whose method
// does not match is not a multipart request and falls back to its plain-object
// classification, which requires the same permission.
//
// A PUT of an object or a part that carries a parseable x-amz-copy-source header
// is a copy (OpCopyObject / OpUploadPartCopy) and also names the source bucket
// and key. Headers are signed only when listed in the signature's SignedHeaders,
// so unlike the path this binding is not implied by signature verification:
// [Authorizer.Authorize] confirms the header was signed before trusting it. A
// copy-source value the gateway's own parser would reject (no bucket/key
// separator, bad percent-encoding) is not classified as a copy: the gateway
// fails such a request on its own validation before it reads anything, and
// classifying it here would only change which error the caller sees. The parse
// mirrors the gateway's (versitygw backend.ParseCopySource) so hilt never
// accepts a source the gateway would parse differently.
func classifyRequest(req s3.Request) (classification, error) {
	u, err := url.Parse(req.URL)
	if err != nil {
		return classification{}, fmt.Errorf("parsing request URL: %w", err)
	}
	var c classification
	c.bucket, c.key, _ = strings.Cut(strings.TrimPrefix(u.EscapedPath(), "/"), "/")

	query := u.Query()
	uploads := query.Has("uploads") // valueless flag: `?uploads`
	uploadID := query.Get("uploadId")

	// A plain-object or part PUT with a parseable copy source is a copy.
	copy := func(plain, copied Operation) Operation {
		if method := strings.ToUpper(req.Method); method != http.MethodPut {
			return plain
		}
		src, ok := headerValue(req.Headers, copySourceHeader)
		if !ok {
			return plain
		}
		srcBucket, srcKey, ok := parseCopySource(src)
		if !ok {
			return plain
		}
		c.srcBucket, c.srcKey = srcBucket, srcKey
		return copied
	}

	classify := func(op Operation) (classification, error) {
		c.op = op
		return c, nil
	}

	method := strings.ToUpper(req.Method)
	switch method {
	case http.MethodGet, http.MethodHead:
		switch {
		case c.bucket == "":
			return classify(OpListBuckets)
		case c.key == "" && uploads:
			return classify(OpListBucketMultipartUploads)
		case c.key == "":
			return classify(OpListBucket)
		case uploadID != "":
			return classify(OpListMultipartUploadParts)
		default:
			return classify(OpGetObject)
		}
	case http.MethodPut, http.MethodPost:
		if c.bucket == "" {
			return classification{}, fmt.Errorf("%s request has no bucket in its path", req.Method)
		}
		switch {
		case c.key == "":
			return classify(OpCreateBucket)
		case method == http.MethodPost && uploads:
			return classify(OpCreateMultipartUpload)
		case method == http.MethodPut && uploadID != "" && query.Has("partNumber"):
			return classify(copy(OpUploadPart, OpUploadPartCopy))
		case method == http.MethodPost && uploadID != "" && !query.Has("partNumber"):
			return classify(OpCompleteMultipartUpload)
		default:
			return classify(copy(OpPutObject, OpCopyObject))
		}
	case http.MethodDelete:
		if c.bucket == "" {
			return classification{}, fmt.Errorf("%s request has no bucket in its path", req.Method)
		}
		switch {
		case c.key == "":
			return classify(OpDeleteBucket)
		case uploadID != "":
			return classify(OpAbortMultipartUpload)
		default:
			return classify(OpDeleteObject)
		}
	default:
		return classification{}, fmt.Errorf("unsupported S3 method %q", req.Method)
	}
}

// headerValue returns the value of the named header from a request's header
// map, matched case-insensitively (HTTP header names are; the gateway forwards
// them as sent). An empty value counts as absent.
func headerValue(headers map[string]string, name string) (string, bool) {
	for k, v := range headers {
		if strings.EqualFold(k, name) && v != "" {
			return v, true
		}
	}
	return "", false
}

// parseCopySource splits an x-amz-copy-source value into its bucket and key,
// mirroring the gateway's parser: an optional leading slash, URL-decoding of the
// whole value, an optional "?versionId=<id>" suffix, then bucket/key at the first
// slash. ok is false for anything the gateway would reject.
func parseCopySource(v string) (bucket, key string, ok bool) {
	v = strings.TrimPrefix(v, "/")
	decoded, err := url.QueryUnescape(v)
	if err != nil {
		return "", "", false
	}
	decoded, _, _ = strings.Cut(decoded, "?versionId=")
	bucket, key, ok = strings.Cut(decoded, "/")
	if !ok || bucket == "" || key == "" {
		return "", "", false
	}
	return bucket, key, true
}
