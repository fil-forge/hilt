package s3perm

// AllowedWhenWriteLocked reports whether a recognized permission only reads
// existing state or performs object/bucket/upload cleanup. Configuration and
// security changes are denied even when their HTTP method is DELETE. Unknown
// permissions fail closed, so a future operation needs an explicit decision.
func AllowedWhenWriteLocked(action string) bool {
	switch action {
	case "s3:GetObject", "s3:GetObjectVersion", "s3:GetObjectRetention", "s3:GetObjectLegalHold",
		"s3:ListBucket", "s3:ListBucketVersions", "s3:ListAllMyBuckets",
		"s3:GetBucketPolicy", "s3:GetBucketPolicyStatus", "s3:GetEncryptionConfiguration",
		"s3:GetBucketLocation", "s3:GetBucketAcl", "s3:GetBucketCORS", "s3:GetBucketTagging",
		"s3:GetBucketVersioning", "s3:GetBucketObjectLockConfiguration",
		"s3:GetObjectTagging", "s3:GetObjectAttributes",
		"s3:ListMultipartUploadParts", "s3:ListBucketMultipartUploads",
		"s3:DeleteObject", "s3:DeleteObjectVersion", "s3:DeleteBucket", "s3:AbortMultipartUpload":
		return true
	default:
		return false
	}
}
