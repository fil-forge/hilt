package s3perm

import (
	"slices"
	"testing"

	s3bkt "github.com/fil-forge/libforge/commands/s3/bucket"

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
