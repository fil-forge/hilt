// Package s3perm maps S3 permission strings (e.g. "s3:GetObject") to the Forge
// network commands that must be delegated for them. It is shared by the Tenant
// REST API (which delegates commands to an access key at creation) and the UCAN
// RPC API (which re-delegates them to the invocation issuer).
package s3perm

import (
	"slices"

	"github.com/fil-forge/libforge/commands/blob"
	"github.com/fil-forge/libforge/commands/content"
	"github.com/fil-forge/libforge/commands/index"
	"github.com/fil-forge/libforge/commands/upload"
	"github.com/fil-forge/ucantone/ucan"
)

// Forge command sets, sourced from the libforge bound command types so the
// command identifiers stay in sync with their definitions.
var (
	cmdsRetrieve = []ucan.Command{content.Retrieve.Command}
	// An add may not complete: /blob/abort abandons a blob that was allocated and
	// uploaded but never accepted, so it belongs to the write path.
	// An add may also supersede: a put (or multipart complete) to a key that
	// already exists must release the replaced body's blobs with /blob/remove.
	// Without the grant those releases go out proofless and are rejected, and
	// the superseded blobs' registrations leak in the space — invisible to the
	// S3 client (removal is best-effort), but the space can never be emptied
	// and keeps the tenant's bytes registered with no way to release them.
	cmdsAdd    = []ucan.Command{blob.Add.Command, index.Add.Command, upload.Add.Command, content.Retrieve.Command, blob.Abort.Command, blob.Remove.Command}
	cmdsRemove = []ucan.Command{blob.Remove.Command, upload.Remove.Command}
	// Stopping a multipart upload discards the parts uploaded so far: those still
	// parked are abandoned with /blob/abort, those already accepted released with
	// /blob/remove.
	cmdsAbort = []ucan.Command{blob.Abort.Command, blob.Remove.Command}
)

// permissionCommands maps each supported S3 permission to the Forge commands
// that must be delegated for it. Permissions with no Forge equivalent
// (bucket-level actions) map to nil — they are valid and stored on the access
// key, but issue no delegation and are enforced directly by Ingot/Hilt (see the
// RFC).
var permissionCommands = map[string][]ucan.Command{
	"s3:GetObject":           cmdsRetrieve,
	"s3:GetObjectVersion":    cmdsRetrieve,
	"s3:GetObjectRetention":  cmdsRetrieve,
	"s3:GetObjectLegalHold":  cmdsRetrieve,
	"s3:ListBucket":          cmdsRetrieve,
	"s3:ListBucketVersions":  cmdsRetrieve,
	"s3:PutObject":           cmdsAdd,
	"s3:PutObjectRetention":  cmdsAdd,
	"s3:PutObjectLegalHold":  cmdsAdd,
	"s3:DeleteObject":        cmdsRemove,
	"s3:DeleteObjectVersion": cmdsRemove,
	"s3:CreateBucket":        nil,
	"s3:ListAllMyBuckets":    nil,
	"s3:DeleteBucket":        nil,

	// Bucket-configuration reads. Ingot answers them from its registry, so they
	// issue no delegation; they exist so a policy can grant or withhold them.
	"s3:GetBucketVersioning":              nil,
	"s3:GetBucketObjectLockConfiguration": nil,

	// Multipart uploads. Initiating an upload, uploading a part and completing an
	// upload all require s3:PutObject, so they need no permission of their own.
	"s3:AbortMultipartUpload":       cmdsAbort,
	"s3:ListMultipartUploadParts":   cmdsRetrieve,
	"s3:ListBucketMultipartUploads": cmdsRetrieve,
}

// bucketLevel are the permissions excluded from bucket policies: a key holding
// CreateBucket or DeleteBucket acts outside the policy that granted it, and
// every principal holds ListAllMyBuckets.
var bucketLevel = map[string]bool{
	"s3:CreateBucket":     true,
	"s3:DeleteBucket":     true,
	"s3:ListAllMyBuckets": true,
}

// Valid reports whether p is a recognized S3 permission.
func Valid(p string) bool {
	_, ok := permissionCommands[p]
	return ok
}

// PolicyAction reports whether p may appear in a bucket policy statement: a
// recognized permission other than s3:CreateBucket, s3:DeleteBucket and
// s3:ListAllMyBuckets.
func PolicyAction(p string) bool {
	return Valid(p) && !bucketLevel[p]
}

// All returns every recognized S3 permission in sorted order. It is the
// permission set of a tenant-wide service credential.
func All() []string {
	all := make([]string, 0, len(permissionCommands))
	for p := range permissionCommands {
		all = append(all, p)
	}
	slices.Sort(all)
	return all
}

// CommandsFor returns the deduplicated set of Forge commands to delegate for the
// given S3 permissions, preserving first-seen order.
func CommandsFor(permissions ...string) []ucan.Command {
	seen := map[string]bool{}
	var cmds []ucan.Command
	for _, p := range permissions {
		for _, c := range permissionCommands[p] {
			if k := c.String(); !seen[k] {
				seen[k] = true
				cmds = append(cmds, c)
			}
		}
	}
	return cmds
}
