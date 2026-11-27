package s3perm

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// TestWriteLockedRuleCoversEveryPermission pins the write-lock rule against
// the permission table: every permission the service knows is decided, and
// nothing else is, so a new permission cannot be added without saying
// whether a write-locked tenant keeps it.
func TestWriteLockedRuleCoversEveryPermission(t *testing.T) {
	for p := range permissionCommands {
		_, decided := writeLockedKeeps[p]
		require.True(t, decided, "%q has no entry in the write-lock rule", p)
	}
	for p := range writeLockedKeeps {
		require.True(t, Valid(p), "the write-lock rule decides %q, which is not a permission", p)
	}
	require.Len(t, writeLockedKeeps, len(permissionCommands))
}
