package s3perm_test

import (
	"testing"

	"github.com/fil-forge/hilt/pkg/rpc/service/auth"
	"github.com/fil-forge/hilt/pkg/s3perm"
	s3 "github.com/fil-forge/libforge/commands/s3"
	"github.com/fil-forge/ucantone/ucan/command"
	"github.com/stretchr/testify/require"
)

func TestValid(t *testing.T) {
	for _, p := range []string{
		"s3:GetObject", "s3:PutObject", "s3:DeleteObject",
		"s3:CreateBucket", "s3:ListAllMyBuckets", "s3:DeleteBucket",
		"s3:AbortMultipartUpload", "s3:ListMultipartUploadParts", "s3:ListBucketMultipartUploads",
	} {
		require.True(t, s3perm.Valid(p), p)
	}

	for _, p := range []string{"", "s3:Frobnicate", "s3:getobject", "GetObject"} {
		require.False(t, s3perm.Valid(p), p)
	}
}

func TestCommandsFor(t *testing.T) {
	strs := func(perms ...string) []string {
		var out []string
		for _, c := range s3perm.CommandsFor(perms...) {
			out = append(out, c.String())
		}
		return out
	}

	t.Run("maps multipart permissions", func(t *testing.T) {
		// Stopping an upload abandons parts still parked and releases those already
		// accepted.
		require.ElementsMatch(t, []string{"/blob/abort", "/blob/remove"}, strs("s3:AbortMultipartUpload"))
		require.Equal(t, []string{"/content/retrieve"}, strs("s3:ListMultipartUploadParts"))
		require.Equal(t, []string{"/content/retrieve"}, strs("s3:ListBucketMultipartUploads"))
	})

	t.Run("the write path can abandon an incomplete upload", func(t *testing.T) {
		require.Contains(t, strs("s3:PutObject"), "/blob/abort")
	})

	t.Run("the write path can release a superseded body", func(t *testing.T) {
		// Overwriting an existing key (put or multipart complete) releases the
		// replaced body's blobs with /blob/remove.
		require.Contains(t, strs("s3:PutObject"), "/blob/remove")
	})

	t.Run("the write path can retire a superseded version", func(t *testing.T) {
		// The same overwrite retires the replaced version's content entry with
		// /upload/remove, so the space's object count holds instead of climbing
		// with every overwrite.
		require.Contains(t, strs("s3:PutObject"), "/upload/remove")
	})

	t.Run("bucket-level permissions map to no commands", func(t *testing.T) {
		require.Empty(t, strs("s3:CreateBucket", "s3:ListAllMyBuckets"))
	})

	t.Run("deleting a bucket unwinds the blobs its space holds", func(t *testing.T) {
		// Parked parts are abandoned, everything else the space still
		// registers is released.
		require.ElementsMatch(t, []string{"/blob/abort", "/blob/remove"}, strs("s3:DeleteBucket"))
	})

	t.Run("deduplicates across permissions, preserving first-seen order", func(t *testing.T) {
		require.Equal(t, []string{
			"/content/retrieve", "/blob/add", "/index/add", "/upload/add", "/upload/remove", "/blob/abort", "/blob/remove",
		}, strs("s3:GetObject", "s3:PutObject"))
	})

	t.Run("ignores unknown permissions", func(t *testing.T) {
		require.Empty(t, strs("s3:Frobnicate"))
		require.Equal(t, []string{"/content/retrieve"}, strs("s3:Frobnicate", "s3:GetObject"))
	})
}

// TestOperationPermissionsAreValid keeps the two hardcoded permission lists in
// lockstep: every permission an operation requires must be one this package can map
// to Forge commands, otherwise an authorized request would be re-delegated nothing.
func TestOperationPermissionsAreValid(t *testing.T) {
	reqs := []struct {
		method string
		url    string
	}{
		{"GET", "https://s3.example.com/"},
		{"GET", "https://s3.example.com/bkt"},
		{"GET", "https://s3.example.com/bkt/k"},
		{"PUT", "https://s3.example.com/bkt"},
		{"PUT", "https://s3.example.com/bkt/k"},
		{"DELETE", "https://s3.example.com/bkt"},
		{"DELETE", "https://s3.example.com/bkt/k"},
		{"POST", "https://s3.example.com/bkt/k?uploads"},
		{"PUT", "https://s3.example.com/bkt/k?partNumber=1&uploadId=abc"},
		{"POST", "https://s3.example.com/bkt/k?uploadId=abc"},
		{"DELETE", "https://s3.example.com/bkt/k?uploadId=abc"},
		{"GET", "https://s3.example.com/bkt/k?uploadId=abc"},
		{"GET", "https://s3.example.com/bkt?uploads"},
	}
	for _, r := range reqs {
		op, err := auth.OperationFor(s3.Request{Method: r.method, URL: r.url})
		require.NoError(t, err, "%s %s", r.method, r.url)
		require.True(t, s3perm.Valid(op.Permission()),
			"operation %s requires %q, which s3perm does not recognize", op, op.Permission())
	}

	// The copies: their destination permission and the source's.
	copyHdr := map[string]string{"x-amz-copy-source": "src/k"}
	for _, r := range reqs[4:5] {
		op, err := auth.OperationFor(s3.Request{Method: r.method, URL: r.url, Headers: copyHdr})
		require.NoError(t, err)
		require.Equal(t, auth.OpCopyObject, op)
		require.True(t, s3perm.Valid(op.Permission()))
	}
	op, err := auth.OperationFor(s3.Request{Method: "PUT", URL: "https://s3.example.com/bkt/k?partNumber=1&uploadId=abc", Headers: copyHdr})
	require.NoError(t, err)
	require.Equal(t, auth.OpUploadPartCopy, op)
	require.True(t, s3perm.Valid(op.Permission()))
	require.True(t, s3perm.Valid(auth.SourcePermission))
}

// TestMutates checks that a write lock, which revokes the grants for mutating
// commands, leaves every read permission fully usable and cuts every write
// permission off.
func TestMutates(t *testing.T) {
	reads := []string{
		"s3:GetObject", "s3:GetObjectVersion", "s3:GetObjectRetention", "s3:GetObjectLegalHold",
		"s3:ListBucket", "s3:ListBucketVersions", "s3:ListMultipartUploadParts", "s3:ListBucketMultipartUploads",
	}
	for _, p := range reads {
		for _, cmd := range s3perm.CommandsFor(p) {
			require.False(t, s3perm.Mutates(cmd), "%s needs %s, which a write lock must keep", p, cmd)
		}
	}

	writes := []string{
		"s3:PutObject", "s3:PutObjectRetention", "s3:PutObjectLegalHold",
		"s3:DeleteObject", "s3:DeleteObjectVersion", "s3:DeleteBucket", "s3:AbortMultipartUpload",
	}
	for _, p := range writes {
		var revoked bool
		for _, cmd := range s3perm.CommandsFor(p) {
			revoked = revoked || s3perm.Mutates(cmd)
		}
		require.True(t, revoked, "a write lock must revoke at least one of %s's commands", p)
	}

	// Unrecognized commands fail closed.
	require.True(t, s3perm.Mutates(command.MustParse("/unknown/cmd")))
}
