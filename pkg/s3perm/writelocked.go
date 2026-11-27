package s3perm

// writeLockedKeeps says, for every S3 permission the service knows, whether a
// write-locked tenant keeps it. A write-locked tenant is read-only: it reads
// and lists what it has stored and may delete it, and it stores nothing new
// and changes no setting.
//
// Kept are the reads and listings, of objects and of bucket configuration,
// and the deletions that release storage: an object, a named version, a
// bucket, and the parts of a multipart upload that is stopped. Bypassing
// governance retention is kept too, since it is only ever asked for to delete
// a version under governance retention, and a key needs the permission for
// it whatever the tenant's status.
//
// Not kept are the uploads (s3:PutObject, which also covers CopyObject and
// initiating, uploading to and completing a multipart upload), bucket
// creation, and every change to configuration or to what protects an object,
// whichever HTTP method carries it: bucket policy, encryption, CORS, tags,
// versioning and Object Lock configuration, and an object's retention, legal
// hold and tags.
//
// Every permission in permissionCommands has an entry, which
// TestWriteLockedRuleCoversEveryPermission pins, so a new permission is
// decided when it is added.
var writeLockedKeeps = map[string]bool{
	"s3:GetObject":           true,
	"s3:GetObjectVersion":    true,
	"s3:GetObjectRetention":  true,
	"s3:GetObjectLegalHold":  true,
	"s3:GetObjectTagging":    true,
	"s3:GetObjectAttributes": true,

	"s3:ListBucket":                 true,
	"s3:ListBucketVersions":         true,
	"s3:ListAllMyBuckets":           true,
	"s3:ListMultipartUploadParts":   true,
	"s3:ListBucketMultipartUploads": true,

	"s3:GetBucketPolicy":                  true,
	"s3:GetBucketPolicyStatus":            true,
	"s3:GetEncryptionConfiguration":       true,
	"s3:GetBucketLocation":                true,
	"s3:GetBucketAcl":                     true,
	"s3:GetBucketCORS":                    true,
	"s3:GetBucketTagging":                 true,
	"s3:GetBucketVersioning":              true,
	"s3:GetBucketObjectLockConfiguration": true,

	"s3:BypassGovernanceRetention": true,
	"s3:DeleteObject":              true,
	"s3:DeleteObjectVersion":       true,
	"s3:DeleteBucket":              true,
	"s3:AbortMultipartUpload":      true,

	"s3:PutObject":    false,
	"s3:CreateBucket": false,

	"s3:PutBucketPolicy":                  false,
	"s3:DeleteBucketPolicy":               false,
	"s3:PutEncryptionConfiguration":       false,
	"s3:PutBucketCORS":                    false,
	"s3:PutBucketTagging":                 false,
	"s3:PutBucketVersioning":              false,
	"s3:PutBucketObjectLockConfiguration": false,

	"s3:PutObjectRetention":  false,
	"s3:PutObjectLegalHold":  false,
	"s3:PutObjectTagging":    false,
	"s3:DeleteObjectTagging": false,
}

// KeptWhenWriteLocked reports whether a write-locked tenant keeps the S3
// permission: the reads, the listings and the deletions that release storage
// (see writeLockedKeeps). A permission the service does not know is not kept.
//
// It is the one rule for write-locking. Authorization refuses a request that
// needs a permission it does not keep and reports only the kept permissions
// to the gateway, and the grants a write-locked tenant's keys hold are
// issued for the kept permissions alone.
//
// The Forge commands of the kept permissions overlap with those of an
// upload: a delete changes the catalog, so s3:DeleteObject carries
// /blob/add and /index/add as s3:PutObject does. A key's grants therefore do
// not by themselves stop an upload, and a gateway deciding a request from
// what it has cached must decide it on the S3 permissions it was given.
func KeptWhenWriteLocked(permission string) bool {
	return writeLockedKeeps[permission]
}
