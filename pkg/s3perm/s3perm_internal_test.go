package s3perm

import (
	"slices"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestEveryPermissionIsClassified pins the policy allowlist against the
// permission table: every recognized permission is either a policy action or
// one of the six named here, so a new permission is not a policy action until
// someone lists it on one side.
func TestEveryPermissionIsClassified(t *testing.T) {
	notPolicy := []string{
		"s3:CreateBucket", "s3:DeleteBucket", "s3:ListAllMyBuckets",
		"s3:GetBucketPolicy", "s3:PutBucketPolicy", "s3:DeleteBucketPolicy",
	}
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
		require.False(t, PolicyAction(p), p)
	}
	require.Len(t, policyActions, len(permissionCommands)-len(notPolicy))
}
