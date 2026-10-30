package rpc

import (
	"errors"
	"fmt"
	"testing"

	s3bkt "github.com/fil-forge/libforge/commands/s3/bucket"

	bucketpolicysvc "github.com/fil-forge/hilt/pkg/api/service/bucketpolicy"
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

	t.Run("wrapped already-owned sentinel is set as failure with its name", func(t *testing.T) {
		f := &recordingFailer{}
		err := fmt.Errorf("%w: %q", bucketsvc.ErrBucketAlreadyOwned, "foo")
		require.NoError(t, bucketFailure(f, err))
		require.True(t, f.called)
		requireName(t, f.got, bucketsvc.BucketAlreadyOwnedErrorName)
	})

	t.Run("a rejected policy document is set as failure under the policy name", func(t *testing.T) {
		f := &recordingFailer{}
		err := fmt.Errorf("decoding policy: unknown field %q: %w", "Version", s3bkt.ErrInvalidPolicy)
		require.NoError(t, bucketFailure(f, err))
		require.True(t, f.called)
		requireName(t, f.got, s3bkt.InvalidPolicyErrorName)
	})

	t.Run("a wrapped policy-not-found rejection is set as failure with its name", func(t *testing.T) {
		f := &recordingFailer{}
		require.NoError(t, bucketFailure(f, fmt.Errorf("photos: %w", bucketpolicysvc.ErrPolicyNotFound)))
		require.True(t, f.called)
		requireName(t, f.got, bucketpolicysvc.PolicyNotFoundErrorName)
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

	t.Run("provider-not-found sentinel is set as failure with its name", func(t *testing.T) {
		f := &recordingFailer{}
		err := fmt.Errorf("setting nodes: %w", ErrProviderNotFound)
		require.NoError(t, adminFailure(f, err))
		require.True(t, f.called)
		requireName(t, f.got, ProviderNotFoundErrorName)
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
			{auth.ErrUnsignedHeader, auth.UnsignedHeaderErrorName},
			{auth.ErrInvalidBody, auth.InvalidBodyErrorName},
			{auth.ErrConflictingQuery, auth.ConflictingQueryErrorName},
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

	t.Run("bucket sentinel is unknown to authFailure and returned", func(t *testing.T) {
		f := &recordingFailer{}
		require.ErrorIs(t, authFailure(f, bucketsvc.ErrBucketExists), bucketsvc.ErrBucketExists)
		require.False(t, f.called)
	})
}
