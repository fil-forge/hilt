package s3perm_test

import (
	"slices"
	"testing"

	s3bkt "github.com/fil-forge/libforge/commands/s3/bucket"

	"github.com/fil-forge/hilt/pkg/s3perm"
	"github.com/fil-forge/libforge/commands/blob"
	"github.com/fil-forge/libforge/commands/content"
	"github.com/fil-forge/libforge/commands/index"
	"github.com/stretchr/testify/require"
)

// writeLockedKept and writeLockedLost are every S3 permission the service
// knows, by whether a write-locked tenant keeps it.
var (
	writeLockedKept = []string{
		"s3:GetObject", "s3:GetObjectVersion", "s3:GetObjectRetention", "s3:GetObjectLegalHold",
		"s3:GetObjectTagging", "s3:GetObjectAttributes",
		"s3:ListBucket", "s3:ListBucketVersions", "s3:ListAllMyBuckets",
		"s3:ListMultipartUploadParts", "s3:ListBucketMultipartUploads",
		"s3:GetBucketPolicy", "s3:GetBucketPolicyStatus", "s3:GetEncryptionConfiguration",
		"s3:GetBucketLocation", "s3:GetBucketAcl", "s3:GetBucketCORS", "s3:GetBucketTagging",
		"s3:GetBucketVersioning", "s3:GetBucketObjectLockConfiguration",
		"s3:DeleteObject", "s3:DeleteObjectVersion", "s3:DeleteBucket", "s3:AbortMultipartUpload",
		"s3:BypassGovernanceRetention",
	}
	writeLockedLost = []string{
		"s3:PutObject", "s3:CreateBucket",
		"s3:PutBucketPolicy", "s3:DeleteBucketPolicy", "s3:PutEncryptionConfiguration",
		"s3:PutBucketCORS", "s3:PutBucketTagging", "s3:PutBucketVersioning",
		"s3:PutBucketObjectLockConfiguration",
		"s3:PutObjectRetention", "s3:PutObjectLegalHold",
		"s3:PutObjectTagging", "s3:DeleteObjectTagging",
	}
)

func TestKeptWhenWriteLocked(t *testing.T) {
	for _, p := range writeLockedKept {
		t.Run(p+" is kept", func(t *testing.T) {
			require.True(t, s3perm.Valid(p))
			require.True(t, s3perm.KeptWhenWriteLocked(p))
		})
	}
	for _, p := range writeLockedLost {
		t.Run(p+" is not kept", func(t *testing.T) {
			require.True(t, s3perm.Valid(p))
			require.False(t, s3perm.KeptWhenWriteLocked(p))
		})
	}
	for _, p := range []string{
		"", "unknown", "s3:*", "*", "s3:getobject", "GetObject",
		"s3:GetUnknownFutureSetting", "s3:DeleteUnknownFutureSetting", "s3:ListUnknownFutureThings",
	} {
		t.Run("unknown "+p+" is not kept", func(t *testing.T) {
			require.False(t, s3perm.Valid(p))
			require.False(t, s3perm.KeptWhenWriteLocked(p))
		})
	}

	t.Run("the table is every policy action and no permission twice", func(t *testing.T) {
		all := append(slices.Clone(writeLockedKept), writeLockedLost...)
		slices.Sort(all)
		require.Equal(t, all, slices.Compact(slices.Clone(all)))
		for _, p := range s3bkt.PolicyActions() {
			require.Contains(t, all, p)
		}
	})
}

// The grants a write-locked key holds do not by themselves stop an upload:
// a delete changes the catalog and releases blobs, so the kept permissions
// carry every Forge command s3:PutObject does. What stops the upload is the
// S3 permission set, which is why the gateway is given the reduced one.
func TestWriteLockedGrantsCoverAnUploadsCommands(t *testing.T) {
	names := func(perms ...string) []string {
		var out []string
		for _, c := range s3perm.CommandsFor(perms...) {
			out = append(out, c.String())
		}
		slices.Sort(out)
		return out
	}
	upload := names("s3:PutObject")
	require.Equal(t, names("s3:DeleteObject", "s3:AbortMultipartUpload"), upload,
		"a key that may delete objects and stop multipart uploads holds every command of an upload")
	require.Equal(t, names(writeLockedKept...), upload, "the kept permissions hold no command an upload lacks")

	// s3:DeleteObject alone lacks only /blob/abort.
	del := names("s3:DeleteObject")
	for _, cmd := range []string{blob.Add.Command.String(), index.Add.Command.String(), content.Retrieve.Command.String(), blob.Remove.Command.String()} {
		require.Contains(t, del, cmd)
	}
	require.NotContains(t, del, blob.Abort.Command.String())
	// The reads alone hold /content/retrieve and nothing an upload writes with.
	require.Equal(t, []string{content.Retrieve.Command.String()}, names("s3:GetObject", "s3:ListBucket"))
}
