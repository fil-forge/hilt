package rpc

import (
	"errors"
	"fmt"
	"testing"

	"github.com/fil-forge/hilt/pkg/rpc/service/auth"
	bucketsvc "github.com/fil-forge/hilt/pkg/rpc/service/bucket"
	"github.com/fil-forge/hilt/pkg/store"
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

	t.Run("wrapped already-owned sentinel is set as failure with its name", func(t *testing.T) {
		f := &recordingFailer{}
		err := fmt.Errorf("%w: %q", bucketsvc.ErrBucketAlreadyOwned, "foo")
		require.NoError(t, bucketFailure(f, err))
		require.True(t, f.called)
		requireName(t, f.got, bucketsvc.BucketAlreadyOwnedErrorName)
	})

	t.Run("propagated auth sentinel is set as failure with its name", func(t *testing.T) {
		f := &recordingFailer{}
		require.NoError(t, bucketFailure(f, auth.ErrOperationNotPermitted))
		require.True(t, f.called)
		requireName(t, f.got, auth.OperationNotPermittedErrorName)
	})

	t.Run("a wrapped lock timeout is set as the retryable failure", func(t *testing.T) {
		// Info reads the bucket policy share-locked, so it can return this too.
		f := &recordingFailer{}
		err := fmt.Errorf("%w: looking up bucket policy: %w", auth.ErrTemporarilyUnavailable, store.ErrLockTimeout)
		require.NoError(t, bucketFailure(f, err))
		require.True(t, f.called)
		requireName(t, f.got, auth.TemporarilyUnavailableErrorName)
	})

	t.Run("unknown error is returned, not set as failure", func(t *testing.T) {
		f := &recordingFailer{}
		boom := errors.New("boom")
		require.ErrorIs(t, bucketFailure(f, boom), boom)
		require.False(t, f.called)
	})
}

func TestAdminFailure(t *testing.T) {
	t.Run("wrapped provider-exists sentinel is set as failure with its name", func(t *testing.T) {
		f := &recordingFailer{}
		err := fmt.Errorf("%w: provider %s region %q", ErrProviderExists, "did:example:provider", "us-east-1")
		require.NoError(t, adminFailure(f, err))
		require.True(t, f.called)
		requireName(t, f.got, ProviderExistsErrorName)
	})

	t.Run("unauthorized sentinel is set as failure with its name", func(t *testing.T) {
		f := &recordingFailer{}
		err := fmt.Errorf("adding provider: %w", ErrUnauthorized)
		require.NoError(t, adminFailure(f, err))
		require.True(t, f.called)
		requireName(t, f.got, UnauthorizedErrorName)
	})

	t.Run("unknown error is returned, not set as failure", func(t *testing.T) {
		f := &recordingFailer{}
		boom := errors.New("boom")
		require.ErrorIs(t, adminFailure(f, boom), boom)
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

	t.Run("the bucket and copy rejections reach the caller by name", func(t *testing.T) {
		for _, tc := range []struct {
			err  error
			name string
		}{
			{auth.ErrUnknownBucket, auth.UnknownBucketErrorName},
			{auth.ErrForeignBucket, auth.ForeignBucketErrorName},
			{auth.ErrBucketNotPermitted, auth.BucketNotPermittedErrorName},
			{auth.ErrUnsignedCopySource, auth.UnsignedCopySourceErrorName},
		} {
			f := &recordingFailer{}
			require.NoError(t, authFailure(f, fmt.Errorf("authorizing: %w", tc.err)))
			require.True(t, f.called, tc.name)
			requireName(t, f.got, tc.name)
		}
	})

	t.Run("a bucket-scope refusal is set as failure", func(t *testing.T) {
		f := &recordingFailer{}
		err := fmt.Errorf("bucket %q: %w", "photos", auth.ErrBucketNotPermitted)
		require.NoError(t, authFailure(f, err))
		require.True(t, f.called)
		requireName(t, f.got, auth.BucketNotPermittedErrorName)
	})

	t.Run("a lock timeout is set as failure under its retryable name", func(t *testing.T) {
		f := &recordingFailer{}
		// As Authorize returns it: the named sentinel first, the store's timeout
		// wrapped after it, so the receipt carries the retryable name.
		err := fmt.Errorf("%w: looking up access key: %w", auth.ErrTemporarilyUnavailable, store.ErrLockTimeout)
		require.NoError(t, authFailure(f, err))
		require.True(t, f.called)
		requireName(t, f.got, auth.TemporarilyUnavailableErrorName)
		require.ErrorIs(t, f.got, store.ErrLockTimeout)
	})

	t.Run("bucket sentinel is unknown to authFailure and returned", func(t *testing.T) {
		f := &recordingFailer{}
		require.ErrorIs(t, authFailure(f, bucketsvc.ErrBucketExists), bucketsvc.ErrBucketExists)
		require.False(t, f.called)
	})
}
