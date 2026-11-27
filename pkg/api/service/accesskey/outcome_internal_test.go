package accesskey

import (
	"errors"
	"fmt"
	"testing"

	"github.com/fil-forge/libforge/taskrunner"
	"github.com/stretchr/testify/require"
)

// A task that failed, expired or never ran has an outcome, however the
// runner reports it; only the runner's own errors leave the task's fate open.
func TestOutcomeUnknown(t *testing.T) {
	for name, err := range map[string]error{
		"a failure the handler returned":   taskrunner.Permanent(errors.New("name taken")),
		"a failure read back from the row": fmt.Errorf("running: %w", &taskrunner.HandlerError{Queue: "queue-tenant", Message: "name taken"}),
		"an expiry":                        taskrunner.ErrExpired,
		"a task that never ran":            taskrunner.ErrNotStarted,
	} {
		require.False(t, outcomeUnknown(err), name)
	}
	require.True(t, outcomeUnknown(errors.New("connection reset")), "the runner's own error")
}
