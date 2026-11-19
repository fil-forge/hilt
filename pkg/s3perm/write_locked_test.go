package s3perm_test

import (
	"testing"

	"github.com/fil-forge/hilt/pkg/s3perm"
	"github.com/stretchr/testify/require"
)

func TestAllowedWhenWriteLocked(t *testing.T) {
	for _, action := range []string{
		"s3:GetObject", "s3:GetObjectVersion", "s3:GetObjectRetention", "s3:GetObjectLegalHold",
		"s3:ListBucket", "s3:ListBucketVersions", "s3:ListAllMyBuckets", "s3:GetBucketPolicy",
		"s3:GetBucketPolicyStatus", "s3:GetEncryptionConfiguration", "s3:GetBucketLocation", "s3:GetBucketAcl",
		"s3:GetBucketCORS", "s3:GetBucketTagging", "s3:GetBucketVersioning", "s3:GetBucketObjectLockConfiguration",
		"s3:GetObjectTagging", "s3:GetObjectAttributes", "s3:ListMultipartUploadParts", "s3:ListBucketMultipartUploads",
		"s3:DeleteObject", "s3:DeleteObjectVersion", "s3:DeleteBucket", "s3:AbortMultipartUpload",
	} {
		t.Run(action, func(t *testing.T) { require.True(t, s3perm.AllowedWhenWriteLocked(action)) })
	}
	for _, action := range []string{
		"s3:PutObject", "s3:CreateBucket", "s3:PutObjectRetention", "s3:PutObjectLegalHold",
		"s3:PutBucketPolicy", "s3:DeleteBucketPolicy", "s3:PutEncryptionConfiguration", "s3:PutBucketCORS",
		"s3:PutBucketTagging", "s3:PutBucketVersioning", "s3:PutBucketObjectLockConfiguration",
		"s3:BypassGovernanceRetention", "s3:PutObjectTagging", "s3:DeleteObjectTagging",
		"s3:GetUnknownFutureSetting", "s3:DeleteUnknownFutureSetting", "s3:*", "", "unknown",
	} {
		t.Run(action, func(t *testing.T) { require.False(t, s3perm.AllowedWhenWriteLocked(action)) })
	}
}
