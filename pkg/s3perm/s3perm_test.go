package s3perm_test

import (
	"slices"
	"testing"

	s3bkt "github.com/fil-forge/libforge/commands/s3/bucket"

	"github.com/fil-forge/hilt/pkg/rpc/service/auth"
	"github.com/fil-forge/hilt/pkg/s3perm"
	s3 "github.com/fil-forge/libforge/commands/s3"
	"github.com/stretchr/testify/require"
)

func TestValid(t *testing.T) {
	for _, p := range []string{
		"s3:GetObject", "s3:PutObject", "s3:DeleteObject",
		"s3:CreateBucket", "s3:ListAllMyBuckets", "s3:DeleteBucket",
		"s3:GetBucketPolicy", "s3:PutBucketPolicy", "s3:DeleteBucketPolicy",
		"s3:AbortMultipartUpload", "s3:ListMultipartUploadParts", "s3:ListBucketMultipartUploads",
		"s3:GetEncryptionConfiguration", "s3:PutEncryptionConfiguration",
	} {
		require.True(t, s3perm.Valid(p), p)
	}

	for _, p := range []string{"", "s3:Frobnicate", "s3:getobject", "GetObject"} {
		require.False(t, s3perm.Valid(p), p)
	}
}

// strs names the Forge commands a set of S3 permissions delegates.
func strs(perms ...string) []string {
	var out []string
	for _, c := range s3perm.CommandsFor(perms...) {
		out = append(out, c.String())
	}
	return out
}

func TestCommandsFor(t *testing.T) {
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

	t.Run("no write registers a version with the upload service", func(t *testing.T) {
		// The gateway counts its own objects and reports them itself, so an
		// overwrite, a delete marker and a deleted version need no
		// /upload/add or /upload/remove.
		for _, p := range []string{"s3:PutObject", "s3:DeleteObject", "s3:DeleteObjectVersion", "s3:DeleteBucket", "s3:AbortMultipartUpload"} {
			require.NotContains(t, strs(p), "/upload/add", p)
			require.NotContains(t, strs(p), "/upload/remove", p)
		}
	})

	t.Run("a delete releases a body and ships the catalog change", func(t *testing.T) {
		// A delete, of the current version or of one named, releases the
		// removed version's blobs and changes the catalog, so it owes the
		// ship that change costs.
		want := []string{"/blob/remove", "/blob/add", "/index/add", "/content/retrieve"}
		require.ElementsMatch(t, want, strs("s3:DeleteObject"))
		require.ElementsMatch(t, want, strs("s3:DeleteObjectVersion"))
	})

	t.Run("setting a lock ships the catalog change it makes", func(t *testing.T) {
		// Retention and legal hold rewrite one version's lock state: no bytes
		// stored, no version minted or retired, no blob released. What is left
		// is the catalog write itself, and the ship it owes.
		want := []string{"/blob/add", "/index/add", "/content/retrieve"}
		require.ElementsMatch(t, want, strs("s3:PutObjectRetention"))
		require.ElementsMatch(t, want, strs("s3:PutObjectLegalHold"))
		for _, p := range []string{"s3:PutObjectRetention", "s3:PutObjectLegalHold"} {
			require.NotContains(t, strs(p), "/blob/remove", p)
		}
	})

	t.Run("every catalog-changing permission can ship the change", func(t *testing.T) {
		// The floor: a change to the catalog is sealed into a CAR and sent,
		// and its index published, whoever caused it.
		for _, p := range []string{
			"s3:PutObject", "s3:PutObjectRetention", "s3:PutObjectLegalHold",
			"s3:DeleteObject", "s3:DeleteObjectVersion",
		} {
			require.Contains(t, strs(p), "/blob/add", p)
			require.Contains(t, strs(p), "/index/add", p)
		}
	})

	t.Run("bucket-level permissions map to no commands", func(t *testing.T) {
		require.Empty(t, strs("s3:CreateBucket", "s3:ListAllMyBuckets", "s3:GetBucketPolicy", "s3:PutBucketPolicy", "s3:DeleteBucketPolicy"))
	})

	t.Run("deleting a bucket unwinds the blobs its space holds", func(t *testing.T) {
		// Parked parts are abandoned and everything else the space still
		// registers is released.
		require.ElementsMatch(t,
			[]string{"/blob/abort", "/blob/remove"},
			strs("s3:DeleteBucket"))
	})

	t.Run("deduplicates across permissions, preserving first-seen order", func(t *testing.T) {
		// /content/retrieve belongs to both permissions. It comes out once, in
		// the place the first permission put it, and the second permission's
		// other commands follow in their own order. Derive that expectation
		// from the sets rather than spelling it out, so a set reordered on its
		// own terms does not fail a test about deduplication.
		var want []string
		for _, c := range append(strs("s3:GetObject"), strs("s3:PutObject")...) {
			if !slices.Contains(want, c) {
				want = append(want, c)
			}
		}
		require.Equal(t, want, strs("s3:GetObject", "s3:PutObject"))
		// And the two sets do overlap, so the deduplication is exercised.
		require.Less(t, len(want), len(strs("s3:GetObject"))+len(strs("s3:PutObject")))
	})

	t.Run("ignores unknown permissions", func(t *testing.T) {
		require.Empty(t, strs("s3:Frobnicate"))
		require.Equal(t, []string{"/content/retrieve"}, strs("s3:Frobnicate", "s3:GetObject"))
	})
}

// TestClassifiedPermissionsCoverTheirShapes covers the fallbacks in
// auth.classifyRequest. Each of these permissions names a narrower shape of
// the one beside it, and a request that misses the narrower branch is
// classified as the broader operation and re-delegated its commands. So the
// broader set has to grant everything the narrower one does. Narrowing one
// below its counterpart would leave such a request a command short at
// runtime, where nothing else would catch it.
func TestClassifiedPermissionsCoverTheirShapes(t *testing.T) {
	for _, c := range []struct{ classified, specialized string }{
		{"s3:PutObject", "s3:PutObjectRetention"},
		{"s3:PutObject", "s3:PutObjectLegalHold"},
		{"s3:DeleteObject", "s3:DeleteObjectVersion"},
		{"s3:GetObject", "s3:GetObjectVersion"},
		{"s3:GetObject", "s3:GetObjectRetention"},
		{"s3:GetObject", "s3:GetObjectLegalHold"},
		{"s3:ListBucket", "s3:ListBucketVersions"},
		// A write that tags the version it creates is authorized under the
		// write's re-delegation, with s3:PutObjectTagging checked beside it
		// (auth.classification.readHeaders); the lock pairs above cover the
		// lock headers the same way.
		{"s3:PutObject", "s3:PutObjectTagging"},
	} {
		// Guard against the check going vacuous if a set is ever emptied.
		require.NotEmpty(t, strs(c.specialized), c.specialized)
		for _, cmd := range strs(c.specialized) {
			require.Contains(t, strs(c.classified), cmd,
				"%s classifies as %s, which must therefore grant %s", c.specialized, c.classified, cmd)
		}
	}
}

// TestOperationPermissionCoversCompanion pins that an operation's own
// permission grants every command its companion does. The authorize handler
// re-delegates the commands of the operation's own permission alone, so a
// companion that mapped to a command outside that set would leave the gateway
// a command short at runtime.
func TestOperationPermissionCoversCompanion(t *testing.T) {
	perms := auth.OpGetObjectAttributes.Permissions()
	require.Len(t, perms, 2)
	own, companion := perms[0], perms[1]
	require.NotEmpty(t, strs(companion), companion)
	for _, cmd := range strs(companion) {
		require.Contains(t, strs(own), cmd, "%s needs %s, which must therefore grant %s", own, companion, cmd)
	}
}

// TestPolicyAction pins the policy vocabulary: every recognized permission except
// the three bucket-level actions, which a policy can neither grant nor withhold.
func TestPolicyAction(t *testing.T) {
	for _, p := range []string{
		"s3:GetObject", "s3:PutObject", "s3:DeleteObject", "s3:ListBucket",
		"s3:AbortMultipartUpload", "s3:ListMultipartUploadParts", "s3:ListBucketMultipartUploads",
	} {
		require.True(t, s3bkt.PolicyAction(p), p)
	}
	for _, p := range []string{
		"s3:CreateBucket", "s3:DeleteBucket", "s3:ListAllMyBuckets",
		"s3:GetBucketPolicy", "s3:PutBucketPolicy", "s3:DeleteBucketPolicy",
		"", "s3:Frobnicate", "s3:getobject",
	} {
		require.False(t, s3bkt.PolicyAction(p), p)
	}
}

// TestPolicyActions pins the wildcard expansion: sorted, every PolicyAction and
// nothing else.
func TestPolicyActions(t *testing.T) {
	actions := s3bkt.PolicyActions()
	require.True(t, slices.IsSorted(actions))
	require.Len(t, actions, 25)
	for _, p := range actions {
		require.True(t, s3bkt.PolicyAction(p), p)
	}
	for _, p := range []string{"s3:CreateBucket", "s3:DeleteBucket", "s3:ListAllMyBuckets",
		"s3:GetBucketPolicy", "s3:PutBucketPolicy", "s3:DeleteBucketPolicy",
		"s3:PutBucketTagging", "s3:PutBucketVersioning", "s3:PutBucketObjectLockConfiguration", "s3:PutBucketCORS", s3bkt.PolicyWildcard} {
		require.NotContains(t, actions, p)
	}
	require.False(t, s3bkt.PolicyAction(s3bkt.PolicyWildcard))
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
		{"GET", "https://s3.example.com/bkt?versions"},
		{"GET", "https://s3.example.com/bkt/k?versionId=v"},
		{"GET", "https://s3.example.com/bkt/k?retention"},
		{"GET", "https://s3.example.com/bkt/k?legal-hold"},
		{"PUT", "https://s3.example.com/bkt/k?retention"},
		{"PUT", "https://s3.example.com/bkt/k?legal-hold"},
		{"DELETE", "https://s3.example.com/bkt/k?versionId=v"},
		{"GET", "https://s3.example.com/bkt?encryption"},
		{"PUT", "https://s3.example.com/bkt?encryption"},
		{"DELETE", "https://s3.example.com/bkt?encryption"},
		{"POST", "https://s3.example.com/bkt?delete"},
		{"GET", "https://s3.example.com/bkt?location"},
		{"GET", "https://s3.example.com/bkt?acl"},
		{"GET", "https://s3.example.com/bkt?cors"},
		{"GET", "https://s3.example.com/bkt?tagging"},
		{"PUT", "https://s3.example.com/bkt?tagging"},
		{"DELETE", "https://s3.example.com/bkt?tagging"},
		{"GET", "https://s3.example.com/bkt?versioning"},
		{"PUT", "https://s3.example.com/bkt?versioning"},
		{"GET", "https://s3.example.com/bkt?object-lock"},
		{"PUT", "https://s3.example.com/bkt?object-lock"},
		{"GET", "https://s3.example.com/bkt/k?tagging"},
		{"PUT", "https://s3.example.com/bkt/k?tagging"},
		{"DELETE", "https://s3.example.com/bkt/k?tagging"},
		{"GET", "https://s3.example.com/bkt/k?attributes"},
		{"GET", "https://s3.example.com/bkt?policyStatus"},
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
	require.True(t, s3perm.Valid(auth.SourceVersionPermission))
}
