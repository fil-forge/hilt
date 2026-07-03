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
)

// operationPermission maps each operation to the S3 permission an access key
// must hold to perform it.
var operationPermission = map[Operation]string{
	OpListBuckets:  "s3:ListAllMyBuckets",
	OpListBucket:   "s3:ListBucket",
	OpGetObject:    "s3:GetObject",
	OpPutObject:    "s3:PutObject",
	OpCreateBucket: "s3:CreateBucket",
	OpDeleteObject: "s3:DeleteObject",
	OpDeleteBucket: "s3:DeleteBucket",
}

// Permission returns the S3 permission an access key must hold to perform the
// operation. Callers that map permissions to Forge commands (see the
// `/s3/request/authorize` handler) use it to avoid re-deriving the permission.
func (o Operation) Permission() string { return operationPermission[o] }

func (o Operation) String() string { return string(o) }

// addressesExistingBucket reports whether the operation acts on a bucket that must
// already exist, so it can be resolved and scope-checked. ListBuckets addresses no
// bucket; CreateBucket's bucket does not exist yet.
func (o Operation) addressesExistingBucket() bool {
	switch o {
	case OpListBucket, OpGetObject, OpPutObject, OpDeleteObject, OpDeleteBucket:
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
// from a request's HTTP method and path-style URL (https://<host>/<bucket>/<key...>).
// The path is part of the SigV4-signed canonical request, so once the signature is
// verified the classification is bound to what the caller signed. It returns an
// error for method/path combinations that map to no supported operation.
func classifyRequest(req s3.Request) (op Operation, bucket, key string, err error) {
	u, err := url.Parse(req.URL)
	if err != nil {
		return "", "", "", fmt.Errorf("parsing request URL: %w", err)
	}
	bucket, key, _ = strings.Cut(strings.TrimPrefix(u.EscapedPath(), "/"), "/")

	switch strings.ToUpper(req.Method) {
	case http.MethodGet, http.MethodHead:
		switch {
		case bucket == "":
			return OpListBuckets, bucket, key, nil
		case key == "":
			return OpListBucket, bucket, key, nil
		default:
			return OpGetObject, bucket, key, nil
		}
	case http.MethodPut, http.MethodPost:
		if bucket == "" {
			return "", "", "", fmt.Errorf("%s request has no bucket in its path", req.Method)
		}
		if key == "" {
			return OpCreateBucket, bucket, key, nil
		}
		return OpPutObject, bucket, key, nil
	case http.MethodDelete:
		if bucket == "" {
			return "", "", "", fmt.Errorf("%s request has no bucket in its path", req.Method)
		}
		if key == "" {
			return OpDeleteBucket, bucket, key, nil
		}
		return OpDeleteObject, bucket, key, nil
	default:
		return "", "", "", fmt.Errorf("unsupported S3 method %q", req.Method)
	}
}
