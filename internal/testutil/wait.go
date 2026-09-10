package testutil

import (
	"testing"
	"time"
)

// Grace is how long a call that must wait on a writer is watched for
// returning early.
const Grace = 300 * time.Millisecond

// RequireWaitsForWriter runs write in the background; write must close
// entered once it holds its lock and park on release before finishing. It
// then starts wait, requires that wait has not returned within [Grace],
// releases the writer, and returns the writer's and wait's errors.
func RequireWaitsForWriter(t *testing.T, write func(entered chan<- struct{}, release <-chan struct{}) error, wait func() error) (writeErr, waitErr error) {
	t.Helper()
	entered := make(chan struct{})
	release := make(chan struct{})
	wrote := make(chan error, 1)
	go func() { wrote <- write(entered, release) }()
	<-entered

	waited := make(chan error, 1)
	go func() { waited <- wait() }()
	select {
	case <-waited:
		t.Fatal("the waiting call returned while the writer held its lock")
	case <-time.After(Grace):
	}

	close(release)
	writeErr = <-wrote
	select {
	case waitErr = <-waited:
	case <-time.After(10 * time.Second):
		t.Fatal("the waiting call did not return after the writer finished")
	}
	return writeErr, waitErr
}
