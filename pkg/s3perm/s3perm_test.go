package s3perm_test

import (
	"testing"

	"github.com/fil-forge/hilt/pkg/rpc/service/auth"
	"github.com/fil-forge/hilt/pkg/s3perm"
	s3 "github.com/fil-forge/libforge/commands/s3"
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

	t.Run("bucket-level permissions map to no commands", func(t *testing.T) {
		require.Empty(t, strs("s3:CreateBucket", "s3:ListAllMyBuckets", "s3:DeleteBucket"))
	})

	t.Run("deduplicates across permissions, preserving first-seen order", func(t *testing.T) {
		require.Equal(t, []string{
			"/content/retrieve", "/blob/add", "/index/add", "/upload/add", "/blob/abort",
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
}
