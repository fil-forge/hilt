package auth

import (
	"fmt"
	"net/http"
	"net/url"
	"slices"
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

	// Object-lock and version-scoped operations, distinguished from their
	// plain-object counterparts by the query parameters on the signed URL.
	// S3 gives each its own permission, so an access key granted plain reads,
	// writes or deletes does not thereby get to read version history, delete a
	// named version, or place a retention period or legal hold.
	OpGetObjectVersion    Operation = "GetObjectVersion"    // GET, bucket + key, ?versionId
	OpGetObjectRetention  Operation = "GetObjectRetention"  // GET, bucket + key, ?retention
	OpGetObjectLegalHold  Operation = "GetObjectLegalHold"  // GET, bucket + key, ?legal-hold
	OpPutObjectRetention  Operation = "PutObjectRetention"  // PUT, bucket + key, ?retention
	OpPutObjectLegalHold  Operation = "PutObjectLegalHold"  // PUT, bucket + key, ?legal-hold
	OpDeleteObjectVersion Operation = "DeleteObjectVersion" // DELETE, bucket + key, ?versionId
	OpDeleteObjects       Operation = "DeleteObjects"       // POST, bucket, no key, ?delete
	OpListBucketVersions  Operation = "ListBucketVersions"  // GET, bucket, no key, ?versions

	// Bucket policy operations, distinguished from the plain bucket operations
	// by the ?policy query parameter.
	OpGetBucketPolicy    Operation = "GetBucketPolicy"    // GET, bucket, no key, ?policy
	OpPutBucketPolicy    Operation = "PutBucketPolicy"    // PUT, bucket, no key, ?policy
	OpDeleteBucketPolicy Operation = "DeleteBucketPolicy" // DELETE, bucket, no key, ?policy

	// Bucket encryption configuration operations, distinguished from the plain
	// bucket operations by the `encryption` query parameter. Removing the
	// configuration needs the same permission as writing it, as it does in S3.
	OpGetBucketEncryption    Operation = "GetBucketEncryption"    // GET, bucket, no key, ?encryption
	OpPutBucketEncryption    Operation = "PutBucketEncryption"    // PUT, bucket, no key, ?encryption
	OpDeleteBucketEncryption Operation = "DeleteBucketEncryption" // DELETE, bucket, no key, ?encryption

	// Multipart upload operations, distinguished from their plain-object
	// counterparts by the query parameters on the signed URL.
	OpCreateMultipartUpload      Operation = "CreateMultipartUpload"      // POST, bucket + key, ?uploads
	OpUploadPart                 Operation = "UploadPart"                 // PUT, bucket + key, ?uploadId&partNumber
	OpUploadPartCopy             Operation = "UploadPartCopy"             // UploadPart with x-amz-copy-source
	OpCompleteMultipartUpload    Operation = "CompleteMultipartUpload"    // POST, bucket + key, ?uploadId
	OpAbortMultipartUpload       Operation = "AbortMultipartUpload"       // DELETE, bucket + key, ?uploadId
	OpListMultipartUploadParts   Operation = "ListMultipartUploadParts"   // GET, bucket + key, ?uploadId
	OpListBucketMultipartUploads Operation = "ListBucketMultipartUploads" // GET, bucket, no key, ?uploads

	// Bucket configuration operations, each distinguished from the plain
	// bucket operations by its subresource. Removing the bucket's tags needs
	// the same permission as writing them, as it does in S3.
	OpGetBucketLocation          Operation = "GetBucketLocation"          // GET, bucket, no key, ?location
	OpGetBucketAcl               Operation = "GetBucketAcl"               // GET, bucket, no key, ?acl
	OpGetBucketCors              Operation = "GetBucketCors"              // GET, bucket, no key, ?cors
	OpGetBucketPolicyStatus      Operation = "GetBucketPolicyStatus"      // GET, bucket, no key, ?policyStatus
	OpGetBucketTagging           Operation = "GetBucketTagging"           // GET, bucket, no key, ?tagging
	OpPutBucketTagging           Operation = "PutBucketTagging"           // PUT, bucket, no key, ?tagging
	OpDeleteBucketTagging        Operation = "DeleteBucketTagging"        // DELETE, bucket, no key, ?tagging
	OpGetBucketVersioning        Operation = "GetBucketVersioning"        // GET, bucket, no key, ?versioning
	OpPutBucketVersioning        Operation = "PutBucketVersioning"        // PUT, bucket, no key, ?versioning
	OpGetObjectLockConfiguration Operation = "GetObjectLockConfiguration" // GET, bucket, no key, ?object-lock
	OpPutObjectLockConfiguration Operation = "PutObjectLockConfiguration" // PUT, bucket, no key, ?object-lock

	// Object tagging and attributes, distinguished from the plain object
	// operations by their subresources.
	OpGetObjectTagging    Operation = "GetObjectTagging"    // GET, bucket + key, ?tagging
	OpPutObjectTagging    Operation = "PutObjectTagging"    // PUT, bucket + key, ?tagging
	OpDeleteObjectTagging Operation = "DeleteObjectTagging" // DELETE, bucket + key, ?tagging
	OpGetObjectAttributes Operation = "GetObjectAttributes" // GET, bucket + key, ?attributes
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

	OpGetObjectVersion:    "s3:GetObjectVersion",
	OpGetObjectRetention:  "s3:GetObjectRetention",
	OpGetObjectLegalHold:  "s3:GetObjectLegalHold",
	OpPutObjectRetention:  "s3:PutObjectRetention",
	OpPutObjectLegalHold:  "s3:PutObjectLegalHold",
	OpDeleteObjectVersion: "s3:DeleteObjectVersion",
	OpDeleteObjects:       "s3:DeleteObject",
	OpListBucketVersions:  "s3:ListBucketVersions",

	OpGetBucketPolicy:        "s3:GetBucketPolicy",
	OpPutBucketPolicy:        "s3:PutBucketPolicy",
	OpDeleteBucketPolicy:     "s3:DeleteBucketPolicy",
	OpGetBucketEncryption:    "s3:GetEncryptionConfiguration",
	OpPutBucketEncryption:    "s3:PutEncryptionConfiguration",
	OpDeleteBucketEncryption: "s3:PutEncryptionConfiguration",

	OpCreateMultipartUpload:      "s3:PutObject",
	OpUploadPart:                 "s3:PutObject",
	OpUploadPartCopy:             "s3:PutObject",
	OpCompleteMultipartUpload:    "s3:PutObject",
	OpAbortMultipartUpload:       "s3:AbortMultipartUpload",
	OpListMultipartUploadParts:   "s3:ListMultipartUploadParts",
	OpListBucketMultipartUploads: "s3:ListBucketMultipartUploads",

	OpGetBucketLocation:          "s3:GetBucketLocation",
	OpGetBucketAcl:               "s3:GetBucketAcl",
	OpGetBucketCors:              "s3:GetBucketCORS",
	OpGetBucketPolicyStatus:      "s3:GetBucketPolicyStatus",
	OpGetBucketTagging:           "s3:GetBucketTagging",
	OpPutBucketTagging:           "s3:PutBucketTagging",
	OpDeleteBucketTagging:        "s3:PutBucketTagging",
	OpGetBucketVersioning:        "s3:GetBucketVersioning",
	OpPutBucketVersioning:        "s3:PutBucketVersioning",
	OpGetObjectLockConfiguration: "s3:GetBucketObjectLockConfiguration",
	OpPutObjectLockConfiguration: "s3:PutBucketObjectLockConfiguration",

	OpGetObjectTagging:    "s3:GetObjectTagging",
	OpPutObjectTagging:    "s3:PutObjectTagging",
	OpDeleteObjectTagging: "s3:DeleteObjectTagging",
	OpGetObjectAttributes: "s3:GetObjectAttributes",
}

// Permission returns the S3 permission that names the operation: the one an
// access key must hold to perform it on the bucket it addresses, and the one
// whose Forge commands the `/s3/request/authorize` handler re-delegates. An
// operation with a companion permission ([Permissions]) needs that too. For
// the copy operations this is the destination's permission; the source's is
// [SourcePermission].
func (o Operation) Permission() string { return operationPermission[o] }

// companionPermission is a second S3 permission an access key must hold on
// the addressed bucket beside the operation's own, as S3 requires. Reading an
// object's attributes needs read access to the object, so GetObjectAttributes
// needs s3:GetObject as well as s3:GetObjectAttributes. Only the operation's
// own permission is re-delegated, so it must grant every command its
// companion does, which s3perm's TestOperationPermissionCoversCompanion pins.
var companionPermission = map[Operation]string{
	OpGetObjectAttributes: "s3:GetObject",
}

// Permissions returns every S3 permission an access key must hold on the
// bucket the operation addresses: [Permission], then the companion for an
// operation that has one. The copy source's permission is separate.
func (o Operation) Permissions() []string {
	perms := []string{operationPermission[o]}
	if companion, ok := companionPermission[o]; ok {
		perms = append(perms, companion)
	}
	return perms
}

// SourcePermission and SourceVersionPermission are the S3 permissions an
// access key must additionally hold, on the copy source's bucket, to perform
// CopyObject or UploadPartCopy: S3 requires read access to the object being
// copied, and to the version when x-amz-copy-source names one. Which applies
// is [classification.sourcePermission].
const (
	SourcePermission        = "s3:GetObject"
	SourceVersionPermission = "s3:GetObjectVersion"
)

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
		OpGetObjectVersion, OpGetObjectRetention, OpGetObjectLegalHold,
		OpPutObjectRetention, OpPutObjectLegalHold, OpDeleteObjectVersion, OpDeleteObjects, OpListBucketVersions,
		OpGetBucketPolicy, OpPutBucketPolicy, OpDeleteBucketPolicy,
		OpGetBucketEncryption, OpPutBucketEncryption, OpDeleteBucketEncryption,
		OpGetBucketLocation, OpGetBucketAcl, OpGetBucketCors, OpGetBucketPolicyStatus,
		OpGetBucketTagging, OpPutBucketTagging, OpDeleteBucketTagging,
		OpGetBucketVersioning, OpPutBucketVersioning,
		OpGetObjectLockConfiguration, OpPutObjectLockConfiguration,
		OpGetObjectTagging, OpPutObjectTagging, OpDeleteObjectTagging, OpGetObjectAttributes,
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
// it needs: the addressed bucket with each of the operation's permissions,
// plus, for the copy operations, the copy source's bucket with
// [SourcePermission] or [SourceVersionPermission]. Operations
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
	var reqs []Requirement
	for _, perm := range c.op.Permissions() {
		reqs = append(reqs, Requirement{Bucket: c.bucket, Permission: perm})
	}
	if c.op.CopiesSource() {
		reqs = append(reqs, Requirement{Bucket: c.srcBucket, Permission: c.sourcePermission()})
	}
	return c.op, reqs, nil
}

// copySourceHeader names the copy source of a CopyObject / UploadPartCopy
// request: "bucket/key", optionally with a leading slash, URL-encoded, with an
// optional "?versionId=" suffix.
const copySourceHeader = "x-amz-copy-source"

// classification is what classifyRequest derives from a request: the operation,
// the bucket and key it addresses, and for the copy operations the bucket,
// key and version named by x-amz-copy-source.
type classification struct {
	op          Operation
	bucket, key string
	// srcBucket, srcKey and srcVersionID are set only when op.CopiesSource();
	// srcVersionID is empty when the source names no version.
	srcBucket, srcKey, srcVersionID string
}

// sourcePermission is the S3 permission the copy's source needs: the version
// read when the source names a version, the object read otherwise, as S3
// decides it.
func (c classification) sourcePermission() string {
	if c.srcVersionID != "" {
		return SourceVersionPermission
	}
	return SourcePermission
}

// subresources is every query parameter S3 treats as a subresource: one that
// selects the operation a request performs, rather than parameterising it.
// The value says whether the gateway serves an operation for it over Ingot.
// A request naming two is refused as [ErrConflictingQuery], as S3 refuses
// it, and one naming an unsupported subresource is refused as
// [ErrUnsupportedOperation] before any permission is consulted, so the
// gateway's own refusal is never preceded by an authorization. Which
// operation a supported subresource selects depends on the method and on
// whether the path names a key; see [bucketRoutes] and [objectRoutes].
var subresources = map[string]bool{
	"accelerate":            false,
	"acl":                   true, // GetBucketAcl only
	"analytics":             false,
	"attributes":            true,
	"cors":                  true, // GetBucketCors only
	"delete":                true,
	"encryption":            true,
	"intelligent-tiering":   false,
	"inventory":             false,
	"legal-hold":            true,
	"lifecycle":             false,
	"location":              true,
	"logging":               false,
	"metadataConfiguration": false,
	"metadataTable":         false,
	"metrics":               false,
	"notification":          false,
	"object-lock":           true,
	"ownershipControls":     false,
	"policy":                true,
	"policyStatus":          true,
	"publicAccessBlock":     false,
	"renameObject":          false,
	"replication":           false,
	"requestPayment":        false,
	"restore":               false,
	"retention":             true,
	"select":                false,
	"session":               false,
	"tagging":               true,
	"torrent":               false,
	"uploadId":              true,
	"uploads":               true,
	"versioning":            true,
	"versions":              true,
	"website":               false,
}

// bucketRoutes are the operations the gateway's router selects by subresource
// for a request that addresses a bucket and no key, by method. An empty
// operation is a route the gateway has (one it serves, or answers with an
// error) that Hilt does not authorize, and is refused. A supported
// subresource with no entry for the method selects nothing in the router
// either, which performs the plain bucket operation: `PUT /b?uploads`
// creates the bucket.
var bucketRoutes = map[string]map[string]Operation{
	http.MethodGet: {
		"location":     OpGetBucketLocation,
		"tagging":      OpGetBucketTagging,
		"versioning":   OpGetBucketVersioning,
		"policy":       OpGetBucketPolicy,
		"cors":         OpGetBucketCors,
		"object-lock":  OpGetObjectLockConfiguration,
		"acl":          OpGetBucketAcl,
		"uploads":      OpListBucketMultipartUploads,
		"versions":     OpListBucketVersions,
		"policyStatus": OpGetBucketPolicyStatus,
		"encryption":   OpGetBucketEncryption,
	},
	http.MethodPut: {
		"tagging":     OpPutBucketTagging,
		"versioning":  OpPutBucketVersioning,
		"object-lock": OpPutObjectLockConfiguration,
		"cors":        "",
		"policy":      OpPutBucketPolicy,
		"acl":         "",
		"encryption":  OpPutBucketEncryption,
	},
	http.MethodDelete: {
		"tagging":    OpDeleteBucketTagging,
		"policy":     OpDeleteBucketPolicy,
		"cors":       "",
		"encryption": OpDeleteBucketEncryption,
	},
	http.MethodPost: {
		"delete": OpDeleteObjects,
	},
}

// objectRoutes are bucketRoutes' counterpart for a request that addresses an
// object. A PUT naming uploadId is a part upload only with a partNumber;
// classifyRequest checks for it, and the gateway answers either alone with
// an error.
var objectRoutes = map[string]map[string]Operation{
	http.MethodGet: {
		"uploads":    "",
		"versions":   "",
		"tagging":    OpGetObjectTagging,
		"retention":  OpGetObjectRetention,
		"legal-hold": OpGetObjectLegalHold,
		"acl":        "",
		"attributes": OpGetObjectAttributes,
		"uploadId":   OpListMultipartUploadParts,
	},
	http.MethodPut: {
		"tagging":    OpPutObjectTagging,
		"retention":  OpPutObjectRetention,
		"legal-hold": OpPutObjectLegalHold,
		"acl":        "",
		"uploadId":   OpUploadPart,
	},
	http.MethodPost: {
		"uploadId": OpCompleteMultipartUpload,
		"uploads":  OpCreateMultipartUpload,
	},
	http.MethodDelete: {
		"tagging":  OpDeleteObjectTagging,
		"uploadId": OpAbortMultipartUpload,
	},
}

// classifyRequest determines the S3 operation and the addressed bucket/object key
// from a request's HTTP method, path-style URL (https://<host>/<bucket>/<key...>) and
// query parameters. Both the path and the query string are part of the SigV4-signed
// canonical request (see sigv4.canonicalQueryString), so once the signature is
// verified the classification is bound to what the caller signed. It returns an
// error for any request it cannot classify as the operation the gateway would
// perform.
//
// The classification mirrors the gateway's router, which picks the operation
// from the method, whether the path names a key, and the subresource the
// query names, if any ([bucketRoutes], [objectRoutes]). A request naming more
// than one subresource (see [subresources]) addresses no single operation and
// is refused with [ErrConflictingQuery], as S3 refuses it (400
// InvalidArgument, "Conflicting query string parameters"), whatever order the
// parameters come in. One naming a subresource the gateway does not serve, or
// a route Hilt does not authorize, is refused with [ErrUnsupportedOperation].
// So is a POST naming no route: on a bucket it is a browser form upload,
// authenticated by a signed policy in the body that Hilt does not verify, and
// on an object the gateway has no such route.
//
// Any other query parameter, known to some operation or not, with a value or
// without, neither selects an operation nor conflicts with one:
// `?encryption&max-keys=1` and `?encryption&foo` are both
// GetBucketEncryption, as they are on S3. A subresource may carry a value
// (`?encryption=true` is still GetBucketEncryption) and its name is
// case-sensitive (`?Encryption` is the plain bucket operation).
//
// A HEAD is HeadBucket or HeadObject whatever subresource it names, as it is
// in the router, and needs s3:ListBucket or s3:GetObject; a versionId makes
// the object read version-scoped. With no subresource, a versionId likewise
// makes a GET or a DELETE of an object version-scoped, each under its own
// permission. A subresource decides the operation on its own, ahead of
// versionId: hilt's permission vocabulary has no version-scoped variant of
// the lock or tagging actions, so `?retention&versionId=` is a retention
// write.
//
// DeleteObjects (`POST /bucket?delete`) deletes the keys its body names and
// needs s3:DeleteObject on the bucket, as each single delete does; the
// gateway checks s3:DeleteObjectVersion for each entry that names a version.
//
// A PUT of an object or a part that carries a parseable x-amz-copy-source header
// is a copy (OpCopyObject / OpUploadPartCopy) and also names the source bucket
// and key. Headers are signed only when listed in the signature's SignedHeaders,
// so unlike the path this binding is not implied by signature verification:
// [Authorizer.Authorize] confirms the header was signed before trusting it.
//
// The value is parsed exactly as the gateway's backend parses it (versitygw
// backend.ParseCopySource): the only values that are not a copy are ones with
// bad percent-encoding or no bucket/key separator, which that parser rejects
// too, so hilt never treats as a plain write a request the gateway would treat
// as a copy. An empty bucket or key parses as a copy of that bucket and key,
// as it does there: authorization then fails on a bucket that cannot exist, or
// the gateway's own validation of the value rejects the request. Which error
// the caller sees for a malformed value is the gateway's call; it validates
// the header before consulting hilt.
func classifyRequest(req s3.Request) (classification, error) {
	u, err := url.Parse(req.URL)
	if err != nil {
		return classification{}, fmt.Errorf("parsing request URL: %w", err)
	}
	var c classification
	c.bucket, c.key, _ = strings.Cut(strings.TrimPrefix(u.EscapedPath(), "/"), "/")

	query := u.Query()
	versionID := query.Get("versionId")

	// Each subresource selects an operation on its own; two at once address
	// none, and one the gateway does not serve addresses nothing to authorize.
	var named []string
	for name := range subresources {
		if query.Has(name) {
			named = append(named, name)
		}
	}
	if len(named) > 1 {
		slices.Sort(named)
		return classification{}, fmt.Errorf("%w: %s", ErrConflictingQuery, strings.Join(named, ", "))
	}
	if len(named) == 1 && !subresources[named[0]] {
		return classification{}, fmt.Errorf("%w: subresource %q", ErrUnsupportedOperation, named[0])
	}

	// A plain-object or part PUT with a parseable copy source is a copy.
	copy := func(plain, copied Operation) Operation {
		src, ok := HeaderValue(req.Headers, copySourceHeader)
		if !ok {
			return plain
		}
		srcBucket, srcKey, srcVersionID, ok := parseCopySource(src)
		if !ok {
			return plain
		}
		c.srcBucket, c.srcKey, c.srcVersionID = srcBucket, srcKey, srcVersionID
		return copied
	}

	classify := func(op Operation) (classification, error) {
		c.op = op
		return c, nil
	}

	method := strings.ToUpper(req.Method)
	switch method {
	case http.MethodGet, http.MethodHead, http.MethodPut, http.MethodPost, http.MethodDelete:
	default:
		return classification{}, fmt.Errorf("unsupported S3 method %q", req.Method)
	}

	if c.bucket == "" {
		if method == http.MethodGet || method == http.MethodHead {
			return classify(OpListBuckets)
		}
		return classification{}, fmt.Errorf("%s request has no bucket in its path", req.Method)
	}

	if method == http.MethodHead {
		switch {
		case c.key == "":
			return classify(OpListBucket)
		case versionID != "":
			return classify(OpGetObjectVersion)
		default:
			return classify(OpGetObject)
		}
	}

	routes := bucketRoutes[method]
	if c.key != "" {
		routes = objectRoutes[method]
	}
	if len(named) == 1 {
		if op, ok := routes[named[0]]; ok {
			switch {
			case op == "":
				return classification{}, fmt.Errorf("%w: %s ?%s", ErrUnsupportedOperation, req.Method, named[0])
			case op == OpUploadPart && !query.Has("partNumber"):
				return classification{}, fmt.Errorf("%w: %s ?uploadId without partNumber", ErrUnsupportedOperation, req.Method)
			case op == OpUploadPart:
				return classify(copy(OpUploadPart, OpUploadPartCopy))
			default:
				return classify(op)
			}
		}
	}

	switch method {
	case http.MethodGet:
		switch {
		case c.key == "":
			return classify(OpListBucket)
		case versionID != "":
			return classify(OpGetObjectVersion)
		default:
			return classify(OpGetObject)
		}
	case http.MethodPut:
		if c.key == "" {
			return classify(OpCreateBucket)
		}
		return classify(copy(OpPutObject, OpCopyObject))
	case http.MethodDelete:
		switch {
		case c.key == "":
			return classify(OpDeleteBucket)
		case versionID != "":
			return classify(OpDeleteObjectVersion)
		default:
			return classify(OpDeleteObject)
		}
	default:
		return classification{}, fmt.Errorf("%w: %s names no route", ErrUnsupportedOperation, req.Method)
	}
}

// HeaderValue returns the value of the named header from a request's header
// map, matched case-insensitively (HTTP header names are; the gateway forwards
// them as sent). An empty value counts as absent. Names differing only in case
// would make the lookup ambiguous, and could diverge from the value the
// signature covered; sigv4.Parse rejects such a request before classification
// (in Authorize, and in the gateway's fast path).
func HeaderValue(headers map[string]string, name string) (string, bool) {
	for k, v := range headers {
		if strings.EqualFold(k, name) && v != "" {
			return v, true
		}
	}
	return "", false
}

// parseCopySource splits an x-amz-copy-source value into its bucket, key and
// version exactly as the gateway's backend parser does: an optional leading
// slash, URL-decoding of the whole value, an optional "?versionId=<id>"
// suffix, then bucket/key at the first slash. ok is false only for bad
// percent-encoding or a missing separator; an empty bucket or key is returned
// as such, and an absent or empty versionId names no version.
func parseCopySource(v string) (bucket, key, versionID string, ok bool) {
	v = strings.TrimPrefix(v, "/")
	decoded, err := url.QueryUnescape(v)
	if err != nil {
		return "", "", "", false
	}
	decoded, versionID, _ = strings.Cut(decoded, "?versionId=")
	bucket, key, ok = strings.Cut(decoded, "/")
	if !ok {
		return "", "", "", false
	}
	return bucket, key, versionID, true
}
