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
	// Every operation that changes the catalog owes a ship: the blocks it
	// writes are sealed into a CAR and sent with /blob/add, and its index
	// published with /index/add. That the ship happens later, off the request,
	// does not make it someone else's: an operation is authorized for what it
	// causes, not only for what it does before it returns. cmdsCatalogWrite is
	// that floor, and every catalog-changing set below is built on it.
	//
	// /content/retrieve rides along because the write reads first, and a
	// manifest or state block the gateway no longer holds locally comes back
	// over the network.
	cmdsCatalogWrite = []ucan.Command{blob.Add.Command, index.Add.Command, content.Retrieve.Command}
	// An add may not complete: /blob/abort abandons a blob that was allocated and
	// uploaded but never accepted, so it belongs to the write path.
	// An add may also supersede: a put (or multipart complete) to a key that
	// already exists must release the replaced body's blobs with /blob/remove.
	// Without the grant those releases go out proofless and are rejected, and
	// the superseded blobs' registrations leak in the space — invisible to the
	// S3 client (removal is best-effort), but the space can never be emptied
	// and keeps the tenant's bytes registered with no way to release them.
	// Supersession retires the replaced version itself the same way, with
	// /upload/remove: the space counts one content entry per object version, so
	// without the grant an overwrite registers the new version and fails to
	// retract the old, and the tenant's object count climbs with every
	// overwrite instead of holding steady.
	cmdsAdd = append([]ucan.Command{upload.Add.Command, upload.Remove.Command, blob.Abort.Command, blob.Remove.Command},
		cmdsCatalogWrite...)
	// The two deletes differ, so they get their own sets.
	//
	// A delete with no version id may write a delete marker, and a delete
	// marker is a version like any other, counted the way AWS counts it — so
	// registering it is an add, odd as that reads on a delete. Without the
	// grant the gateway queues a change it can never send, and the object
	// count drifts for every delete against a versioned bucket.
	cmdsDeleteObject = append([]ucan.Command{blob.Remove.Command, upload.Add.Command, upload.Remove.Command},
		cmdsCatalogWrite...)
	// Deleting one named version only ever removes. It mints no version, so it
	// has nothing to register and no business holding the grant to.
	cmdsDeleteObjectVersion = append([]ucan.Command{blob.Remove.Command, upload.Remove.Command},
		cmdsCatalogWrite...)
	// Setting retention or a legal hold rewrites one version's lock state and
	// nothing else: no bytes stored, no version minted or retired, no blob
	// released. The catalog write is the whole of it.
	cmdsLockState = cmdsCatalogWrite
	// Stopping a multipart upload discards the parts uploaded so far: those still
	// parked are abandoned with /blob/abort, those already accepted released with
	// /blob/remove. Without the grant Ingot can release them only with authority
	// left over from some earlier write. No /upload/remove: an abandoned upload
	// never committed a version, so it has no content entry to retract.
	cmdsAbort = []ucan.Command{blob.Abort.Command, blob.Remove.Command}
	// Deleting a bucket unwinds every blob its space still holds — in-flight
	// multipart parts, deleted objects' bodies whose deferred release has not
	// run, and shipped catalog segments — so it needs what an abort needs, and
	// a bucket that saw no write has no captured authority to fall back on.
	//
	// It also needs /upload/remove. Emptying a bucket queues a retraction per
	// object version, and the gateway applies whatever is still queued before
	// asking to delete the space, because nothing else ever will: this delete
	// checks that the space holds no blobs and never touches its content
	// entries, and the upload service keeps a space's entries and counters
	// after the space is gone. Those retractions normally travel on authority
	// the original write left behind; this grant is what lets them go out when
	// that authority has expired.
	cmdsDeleteBucket = []ucan.Command{blob.Abort.Command, blob.Remove.Command, upload.Remove.Command}
)

// permissionCommands maps each supported S3 permission to the Forge commands
// that must be delegated for it. Permissions with no Forge equivalent map to
// nil — they are valid and stored on the access key, but issue no delegation
// and are enforced directly by Ingot/Hilt (see the RFC). Of the bucket-level
// actions only s3:DeleteBucket needs commands, since it releases the space's
// blobs.
//
// Several permissions name a narrower shape of another: s3:PutObjectRetention
// and s3:PutObjectLegalHold against s3:PutObject, s3:DeleteObjectVersion
// against s3:DeleteObject, the version-scoped reads against s3:GetObject and
// s3:ListBucket. auth.classifyRequest gives each shape its own operation, but
// a request that misses the narrower branch falls back to the broader one — a
// lock parameter on a method the gateway does not route it on, a versionId
// naming no version. So each broad set has to grant what its narrower
// counterparts do, which TestClassifiedPermissionsCoverTheirShapes pins.
var permissionCommands = map[string][]ucan.Command{
	"s3:GetObject":           cmdsRetrieve,
	"s3:GetObjectVersion":    cmdsRetrieve,
	"s3:GetObjectRetention":  cmdsRetrieve,
	"s3:GetObjectLegalHold":  cmdsRetrieve,
	"s3:ListBucket":          cmdsRetrieve,
	"s3:ListBucketVersions":  cmdsRetrieve,
	"s3:PutObject":           cmdsAdd,
	"s3:PutObjectRetention":  cmdsLockState,
	"s3:PutObjectLegalHold":  cmdsLockState,
	"s3:DeleteObject":        cmdsDeleteObject,
	"s3:DeleteObjectVersion": cmdsDeleteObjectVersion,
	"s3:CreateBucket":        nil,
	"s3:ListAllMyBuckets":    nil,
	"s3:DeleteBucket":        cmdsDeleteBucket,

	// Multipart uploads. Initiating an upload, uploading a part and completing an
	// upload all require s3:PutObject, so they need no permission of their own.
	"s3:AbortMultipartUpload":       cmdsAbort,
	"s3:ListMultipartUploadParts":   cmdsRetrieve,
	"s3:ListBucketMultipartUploads": cmdsRetrieve,
}

// Valid reports whether p is a recognized S3 permission.
func Valid(p string) bool {
	_, ok := permissionCommands[p]
	return ok
}

// Mutates reports whether a delegation of cmd lets its holder change tenant
// data. Only the read command set is enumerated, so any other command
// (including one added later) counts as mutating: a write lock revokes these
// grants, and failing closed is the safe default there. /content/retrieve is
// also delegated for s3:PutObject, but it only reads, so a write-locked tenant
// keeps it.
func Mutates(cmd ucan.Command) bool {
	return !slices.ContainsFunc(cmdsRetrieve, func(c ucan.Command) bool { return c.String() == cmd.String() })
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
