package auth

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"

	s3 "github.com/fil-forge/libforge/commands/s3"
)

// Operation is the S3 operation a request performs, derived from its HTTP method
// and path. [Authorizer.Authorize] classifies it, checks the access key is
// permitted to perform it, and returns it on [AuthorizedRequest.Operation] so a
// handler can confirm the request matches the operation it serves.
type Operation string

const (
	OpListBuckets  Operation = "ListBuckets"  // GET, no bucket in path
	OpListBucket   Operation = "ListBucket"   // GET, bucket, no key (list objects)
	OpGetObject    Operation = "GetObject"    // GET, bucket + key
	OpPutObject    Operation = "PutObject"    // PUT/POST, bucket + key
	OpCreateBucket Operation = "CreateBucket" // PUT/POST, bucket, no key
	OpDeleteObject Operation = "DeleteObject" // DELETE, bucket + key
	OpDeleteBucket Operation = "DeleteBucket" // DELETE, bucket, no key

	// Multipart upload operations, distinguished from their plain-object
	// counterparts by the query parameters on the signed URL.
	OpCreateMultipartUpload      Operation = "CreateMultipartUpload"      // POST, bucket + key, ?uploads
	OpUploadPart                 Operation = "UploadPart"                 // PUT, bucket + key, ?uploadId&partNumber
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
	OpCreateBucket: "s3:CreateBucket",
	OpDeleteObject: "s3:DeleteObject",
	OpDeleteBucket: "s3:DeleteBucket",

	OpCreateMultipartUpload:      "s3:PutObject",
	OpUploadPart:                 "s3:PutObject",
	OpCompleteMultipartUpload:    "s3:PutObject",
	OpAbortMultipartUpload:       "s3:AbortMultipartUpload",
	OpListMultipartUploadParts:   "s3:ListMultipartUploadParts",
	OpListBucketMultipartUploads: "s3:ListBucketMultipartUploads",
}

// Permission returns the S3 permission an access key must hold to perform the
// operation. Callers that map permissions to Forge commands (see the
// `/s3/request/authorize` handler) use it to avoid re-deriving the permission.
func (o Operation) Permission() string { return operationPermission[o] }

func (o Operation) String() string { return string(o) }

// addressesExistingBucket reports whether the operation acts on a bucket that must
// already exist, so it can be resolved and scope-checked. ListBuckets addresses no
// bucket; CreateBucket's bucket does not exist yet. Every multipart operation acts
// on an existing bucket — an upload cannot be initiated into one that does not.
func (o Operation) addressesExistingBucket() bool {
	switch o {
	case OpListBucket, OpGetObject, OpPutObject, OpDeleteObject, OpDeleteBucket,
		OpCreateMultipartUpload, OpUploadPart, OpCompleteMultipartUpload,
		OpAbortMultipartUpload, OpListMultipartUploadParts, OpListBucketMultipartUploads:
		return true
	default:
		return false
	}
}

// OperationFor classifies the S3 operation addressed by a request. See
// [classifyRequest] for the method/path rules.
func OperationFor(req s3.Request) (Operation, error) {
	op, _, _, err := classifyRequest(req)
	return op, err
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
// UploadPartCopy is not distinguished from UploadPart: S3 requires s3:PutObject on
// the target and s3:GetObject on the source object, but the source arrives in the
// x-amz-copy-source header, which is not guaranteed to be signed. Only s3:PutObject
// is required, matching how a plain CopyObject also classifies as OpPutObject.
func classifyRequest(req s3.Request) (op Operation, bucket, key string, err error) {
	u, err := url.Parse(req.URL)
	if err != nil {
		return "", "", "", fmt.Errorf("parsing request URL: %w", err)
	}
	bucket, key, _ = strings.Cut(strings.TrimPrefix(u.EscapedPath(), "/"), "/")

	query := u.Query()
	uploads := query.Has("uploads") // valueless flag: `?uploads`
	uploadID := query.Get("uploadId")

	method := strings.ToUpper(req.Method)
	switch method {
	case http.MethodGet, http.MethodHead:
		switch {
		case bucket == "":
			return OpListBuckets, bucket, key, nil
		case key == "" && uploads:
			return OpListBucketMultipartUploads, bucket, key, nil
		case key == "":
			return OpListBucket, bucket, key, nil
		case uploadID != "":
			return OpListMultipartUploadParts, bucket, key, nil
		default:
			return OpGetObject, bucket, key, nil
		}
	case http.MethodPut, http.MethodPost:
		if bucket == "" {
			return "", "", "", fmt.Errorf("%s request has no bucket in its path", req.Method)
		}
		switch {
		case key == "":
			return OpCreateBucket, bucket, key, nil
		case method == http.MethodPost && uploads:
			return OpCreateMultipartUpload, bucket, key, nil
		case method == http.MethodPut && uploadID != "" && query.Has("partNumber"):
			return OpUploadPart, bucket, key, nil
		case method == http.MethodPost && uploadID != "" && !query.Has("partNumber"):
			return OpCompleteMultipartUpload, bucket, key, nil
		default:
			return OpPutObject, bucket, key, nil
		}
	case http.MethodDelete:
		if bucket == "" {
			return "", "", "", fmt.Errorf("%s request has no bucket in its path", req.Method)
		}
		switch {
		case key == "":
			return OpDeleteBucket, bucket, key, nil
		case uploadID != "":
			return OpAbortMultipartUpload, bucket, key, nil
		default:
			return OpDeleteObject, bucket, key, nil
		}
	default:
		return "", "", "", fmt.Errorf("unsupported S3 method %q", req.Method)
	}
}
