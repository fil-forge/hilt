package rpc

import (
	"errors"
	"fmt"
	"testing"

	"github.com/fil-forge/hilt/pkg/rpc/service/auth"
	bucketsvc "github.com/fil-forge/hilt/pkg/rpc/service/bucket"
	ucanerrors "github.com/fil-forge/ucantone/errors"
	"github.com/stretchr/testify/require"
)

// recordingFailer records the error passed to SetFailure.
type recordingFailer struct {
	called bool
	got    error
}

func (f *recordingFailer) SetFailure(err error) error {
	f.called = true
	f.got = err
	return nil
}

// requireName asserts the recorded failure resolves (via errors.As, as SetFailure
// does) to a Named error with the given name.
func requireName(t *testing.T, err error, want string) {
	t.Helper()
	var named ucanerrors.Named
	require.True(t, errors.As(err, &named), "failure must resolve to a Named error")
	require.Equal(t, want, named.Name())
}

func TestBucketFailure(t *testing.T) {
	t.Run("wrapped bucket sentinel is set as failure with its name", func(t *testing.T) {
		f := &recordingFailer{}
		err := fmt.Errorf("%w: %q", bucketsvc.ErrBucketExists, "foo")
		require.NoError(t, bucketFailure(f, err))
		require.True(t, f.called)
		requireName(t, f.got, bucketsvc.BucketExistsErrorName)
	})

	t.Run("propagated auth sentinel is set as failure with its name", func(t *testing.T) {
		f := &recordingFailer{}
		require.NoError(t, bucketFailure(f, auth.ErrOperationNotPermitted))
		require.True(t, f.called)
		requireName(t, f.got, auth.OperationNotPermittedErrorName)
	})

	t.Run("unknown error is returned, not set as failure", func(t *testing.T) {
		f := &recordingFailer{}
		boom := errors.New("boom")
		require.ErrorIs(t, bucketFailure(f, boom), boom)
		require.False(t, f.called)
	})
}

func TestAuthFailure(t *testing.T) {
	t.Run("wrapped auth sentinel is set as failure with its name", func(t *testing.T) {
		f := &recordingFailer{}
		err := fmt.Errorf("verifying signature: %w", auth.ErrSignatureMismatch)
		require.NoError(t, authFailure(f, err))
		require.True(t, f.called)
		requireName(t, f.got, auth.SignatureMismatchErrorName)
	})

	t.Run("bucket sentinel is unknown to authFailure and returned", func(t *testing.T) {
		f := &recordingFailer{}
		require.ErrorIs(t, authFailure(f, bucketsvc.ErrBucketExists), bucketsvc.ErrBucketExists)
		require.False(t, f.called)
	})
}
