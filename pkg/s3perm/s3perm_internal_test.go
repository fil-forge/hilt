package s3perm

import (
	"slices"
	"testing"

	s3bkt "github.com/fil-forge/libforge/commands/s3/bucket"
	"github.com/fil-forge/ucantone/ucan/command"

	"github.com/stretchr/testify/require"
)

// TestEveryPermissionIsClassified pins the policy allowlist (libforge's
// s3bkt.PolicyActions) against the
// permission table: every recognized permission is either a policy action or
// one of the bucket-management permissions named here, so a new permission is
// not a policy action until someone lists it on one side. The encryption
// configuration stays out of policies with the rest of bucket management: a
// principal that could set a bucket to store its bytes unencrypted would be
// changing the bucket, not acting within it.
func TestEveryPermissionIsClassified(t *testing.T) {
	notPolicy := []string{
		"s3:CreateBucket", "s3:DeleteBucket", "s3:ListAllMyBuckets",
		"s3:GetBucketPolicy", "s3:PutBucketPolicy", "s3:DeleteBucketPolicy",
		"s3:GetEncryptionConfiguration", "s3:PutEncryptionConfiguration",
		"s3:PutBucketTagging", "s3:PutBucketVersioning", "s3:PutBucketObjectLockConfiguration",
		"s3:PutBucketCORS", "s3:GetBucketPolicyStatus",
	}
	policyActions := s3bkt.PolicyActions()
	require.True(t, slices.IsSorted(policyActions), "policyActions must be sorted")
	for _, p := range policyActions {
		require.True(t, Valid(p), "%q is listed as a policy action but is not a permission", p)
		require.NotContains(t, notPolicy, p)
	}
	for p := range permissionCommands {
		require.True(t, slices.Contains(policyActions, p) || slices.Contains(notPolicy, p),
			"%q is neither a policy action nor listed here as excluded", p)
	}
	for _, p := range notPolicy {
		require.True(t, Valid(p), p)
		require.False(t, s3bkt.PolicyAction(p), p)
	}
	require.Len(t, policyActions, len(permissionCommands)-len(notPolicy))
}

// TestRevokedByWriteLock pins what a write-locked tenant can still do: every
// read, and s3:AbortMultipartUpload so it can drop an upload left in flight
// rather than pay for its parts until someone unlocks. A permission is usable
// only while every command it needs survives, so one revoked command cuts it
// off.
//
// The abort carve-out is why this is checked permission by permission rather
// than command by command. /blob/remove is kept for the abort and also sits in
// s3:PutObject's, s3:DeleteObject's and s3:DeleteBucket's sets; keeping a
// command grants no permission on its own, but a set rewritten later could come
// to need nothing outside the kept ones, and the lock would quietly stop
// cutting that permission off. Ranging the permission table means a permission
// added later fails here until someone classifies it.
func TestRevokedByWriteLock(t *testing.T) {
	keptByLock := map[string]bool{
		"s3:GetObject":                  true,
		"s3:GetObjectVersion":           true,
		"s3:GetObjectRetention":         true,
		"s3:GetObjectLegalHold":         true,
		"s3:GetObjectTagging":           true,
		"s3:GetObjectAttributes":        true,
		"s3:ListBucket":                 true,
		"s3:ListBucketVersions":         true,
		"s3:ListMultipartUploadParts":   true,
		"s3:ListBucketMultipartUploads": true,
		"s3:AbortMultipartUpload":       true, // the one write a freeze keeps
		"s3:PutObject":                  false,
		"s3:PutObjectRetention":         false,
		"s3:PutObjectLegalHold":         false,
		"s3:PutObjectTagging":           false,
		"s3:DeleteObjectTagging":        false,
		"s3:DeleteObject":               false,
		"s3:DeleteObjectVersion":        false,
		"s3:DeleteBucket":               false,
	}

	for p, cmds := range permissionCommands {
		// A permission that issues no command is enforced by Hilt and Ingot
		// directly, so a lock has no grant of its own to revoke for it.
		if len(cmds) == 0 {
			require.NotContains(t, keptByLock, p, "%s issues no commands, so a write lock does not decide it here", p)
			continue
		}
		kept, classified := keptByLock[p]
		require.True(t, classified, "%s issues commands but is not classified against the write lock", p)

		var revoked []string
		for _, cmd := range cmds {
			if RevokedByWriteLock(cmd) {
				revoked = append(revoked, cmd.String())
			}
		}
		if kept {
			require.Empty(t, revoked, "a write-locked tenant keeps %s, so a lock must revoke none of its commands", p)
			continue
		}
		require.NotEmpty(t, revoked, "a write lock must revoke at least one of %s's commands", p)
	}

	// Nothing is kept that no kept permission needs. The loop above only rules
	// out a kept command making a blocked permission usable; this rules out a
	// lock weakened for no one's benefit, which is how a carve-out grows.
	needed := map[string]bool{}
	for p, kept := range keptByLock {
		if !kept {
			continue
		}
		for _, cmd := range permissionCommands[p] {
			needed[cmd.String()] = true
		}
	}
	for _, cmd := range cmdsWriteLockKeeps {
		require.True(t, needed[cmd.String()], "a write lock keeps %s, which no permission it keeps needs", cmd)
	}

	// An unrecognized command fails closed, so a command added without a place
	// in a kept set is revoked rather than left live.
	require.True(t, RevokedByWriteLock(command.MustParse("/unknown/cmd")))
}
