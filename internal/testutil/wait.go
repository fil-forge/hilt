package testutil

import (
	"testing"
	"time"
)

// MinBlock is how long a call that must wait on a writer has to stay blocked.
const MinBlock = 300 * time.Millisecond

// WaitTimeout is how long a call that must finish is given before the test fails.
const WaitTimeout = 10 * time.Second

// RequireWaitsForWriter runs write in the background; write must close
// entered once it holds its lock and park on release before finishing. It
// then starts wait, requires that wait has not returned within [MinBlock],
// releases the writer, and returns the writer's and wait's errors.
func RequireWaitsForWriter(t *testing.T, write func(entered chan<- struct{}, release <-chan struct{}) error, wait func() error) (writeErr, waitErr error) {
	t.Helper()
	entered := make(chan struct{})
	release := make(chan struct{})
	wrote := make(chan error, 1)
	go func() { wrote <- write(entered, release) }()
	select {
	case <-entered:
	case err := <-wrote:
		t.Fatalf("the writer returned before taking its lock: %v", err)
	case <-time.After(WaitTimeout):
		t.Fatal("the writer did not take its lock")
	}

	waited := make(chan error, 1)
	go func() { waited <- wait() }()
	select {
	case <-waited:
		t.Fatal("the waiting call returned while the writer held its lock")
	case <-time.After(MinBlock):
	}

	close(release)
	writeErr = <-wrote
	select {
	case waitErr = <-waited:
	case <-time.After(WaitTimeout):
		t.Fatal("the waiting call did not return after the writer finished")
	}
	return writeErr, waitErr
}
