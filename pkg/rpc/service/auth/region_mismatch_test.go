package auth_test

import (
	"bytes"
	"errors"
	"testing"

	"github.com/fil-forge/hilt/pkg/rpc/service/auth"
	edm "github.com/fil-forge/ucantone/errors/datamodel"
	"github.com/stretchr/testify/require"
)

func TestBucketRegionMismatchError(t *testing.T) {
	mismatch := &auth.BucketRegionMismatchError{Expected: "eu-west-1", Actual: "us-west-2"}
	var wire bytes.Buffer
	require.NoError(t, mismatch.MarshalCBOR(&wire))

	t.Run("decodes back with both regions", func(t *testing.T) {
		got, err := auth.DecodeFailure(wire.Bytes())
		require.NoError(t, err)
		require.Equal(t, auth.BucketRegionMismatchErrorName, got.Name())
		var typed *auth.BucketRegionMismatchError
		require.ErrorAs(t, got, &typed)
		require.Equal(t, "eu-west-1", typed.Expected)
		require.Equal(t, "us-west-2", typed.Actual)
	})

	t.Run("is readable as the standard error model", func(t *testing.T) {
		// A reader that knows only ucantone's error model (the binding's generic
		// unpack, an older gateway) still gets the name and message.
		var model edm.ErrorModel
		require.NoError(t, model.UnmarshalCBOR(bytes.NewReader(wire.Bytes())))
		require.Equal(t, auth.BucketRegionMismatchErrorName, model.Name())
		require.Equal(t, mismatch.Error(), model.Error())
	})

	t.Run("other failures decode as the standard model", func(t *testing.T) {
		var other bytes.Buffer
		require.NoError(t, (&edm.ErrorModel{ErrorName: auth.UnknownBucketErrorName, Message: "nope"}).MarshalCBOR(&other))
		got, err := auth.DecodeFailure(other.Bytes())
		require.NoError(t, err)
		require.Equal(t, auth.UnknownBucketErrorName, got.Name())
		var typed *auth.BucketRegionMismatchError
		require.False(t, errors.As(got, &typed))
	})

	t.Run("rejects a model carrying another failure's name", func(t *testing.T) {
		var other bytes.Buffer
		require.NoError(t, (&edm.ErrorModel{ErrorName: auth.UnknownBucketErrorName, Message: "nope"}).MarshalCBOR(&other))
		var typed auth.BucketRegionMismatchError
		require.Error(t, typed.UnmarshalCBOR(bytes.NewReader(other.Bytes())))
	})
}
