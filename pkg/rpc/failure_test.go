package rpc

import (
	"errors"
	"fmt"
	"io"
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

// selfEncodingError is a named failure that encodes its own CBOR, standing in for
// any rejection that carries fields of its own.
type selfEncodingError struct{}

func (e *selfEncodingError) Name() string                  { return "SelfEncoding" }
func (e *selfEncodingError) Error() string                 { return "self-encoding failure" }
func (e *selfEncodingError) MarshalCBOR(w io.Writer) error { return nil }

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

	t.Run("wrapped region mismatch is set as the typed failure itself", func(t *testing.T) {
		// The typed error must reach SetFailure unwrapped so its own CBOR
		// encoding (with the regions) is what goes on the wire.
		f := &recordingFailer{}
		mismatch := &auth.BucketRegionMismatchError{Expected: "eu-west-1", Actual: "us-west-2"}
		require.NoError(t, bucketFailure(f, fmt.Errorf("create: %w", mismatch)))
		require.True(t, f.called)
		require.Same(t, mismatch, f.got)
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

	t.Run("a wrapped error that encodes its own CBOR is set as itself", func(t *testing.T) {
		// authFailure names no structured failure: it detects the encoding, so a
		// rejection that carries fields of its own reaches SetFailure unwrapped.
		f := &recordingFailer{}
		own := &selfEncodingError{}
		require.NoError(t, authFailure(f, fmt.Errorf("authorizing: %w", own)))
		require.True(t, f.called)
		require.Same(t, own, f.got)
	})

	t.Run("a wrapped sentinel keeps its context, so it is not set unwrapped", func(t *testing.T) {
		// The sentinels encode no CBOR of their own, so SetFailure receives the
		// wrapped error and reports its full message under the sentinel's name.
		f := &recordingFailer{}
		err := fmt.Errorf("authorizing: %w", auth.ErrUnknownBucket)
		require.NoError(t, authFailure(f, err))
		require.Same(t, err, f.got)
	})

	t.Run("bucket sentinel is unknown to authFailure and returned", func(t *testing.T) {
		f := &recordingFailer{}
		require.ErrorIs(t, authFailure(f, bucketsvc.ErrBucketExists), bucketsvc.ErrBucketExists)
		require.False(t, f.called)
	})
}
