package datamodel_test

import (
	"bytes"
	"testing"

	"github.com/fil-forge/hilt/pkg/tasks/tenantqueue/datamodel"
	"github.com/fil-forge/libforge/testutil"
	"github.com/fil-forge/ucantone/did"
	"github.com/stretchr/testify/require"
)

func TestCreateKeyArgs(t *testing.T) {
	principal := "alice"
	expires := int64(1_800_000_000_123_456)
	for name, args := range map[string]datamodel.CreateKeyArgs{
		"a service key scoped to buckets, with an expiry": {
			Key:         testutil.RandomDID(t),
			Name:        "ci",
			Permissions: []string{"s3:GetObject", "s3:PutObject"},
			Buckets:     []did.DID{testutil.RandomDID(t), testutil.RandomDID(t)},
			ExpiresAt:   &expires,
			CreatedAt:   1_700_000_000_654_321,
		},
		"a service key over every bucket, with no expiry": {
			Key:         testutil.RandomDID(t),
			Name:        "all",
			Permissions: []string{"s3:ListBucket"},
			CreatedAt:   1_700_000_000_000_000,
		},
		"a principal-bound key": {
			Key:       testutil.RandomDID(t),
			Name:      "laptop",
			Principal: &principal,
			CreatedAt: 1_700_000_000_000_001,
		},
	} {
		t.Run(name+" round trips", func(t *testing.T) {
			var wire bytes.Buffer
			require.NoError(t, args.MarshalCBOR(&wire))
			var got datamodel.CreateKeyArgs
			require.NoError(t, got.UnmarshalCBOR(bytes.NewReader(wire.Bytes())))
			require.Equal(t, args.Key, got.Key)
			require.Equal(t, args.Name, got.Name)
			require.ElementsMatch(t, args.Permissions, got.Permissions)
			require.Equal(t, len(args.Permissions), len(got.Permissions))
			require.Equal(t, len(args.Buckets), len(got.Buckets))
			for i := range args.Buckets {
				require.Equal(t, args.Buckets[i], got.Buckets[i])
			}
			require.Equal(t, args.Principal, got.Principal)
			require.Equal(t, args.ExpiresAt, got.ExpiresAt)
			require.Equal(t, args.CreatedAt, got.CreatedAt)

			// Encoding is deterministic: the same arguments are the same bytes.
			var again bytes.Buffer
			require.NoError(t, got.MarshalCBOR(&again))
			require.Equal(t, wire.Bytes(), again.Bytes())
		})
	}

	t.Run("rejects bytes that are not the model", func(t *testing.T) {
		var got datamodel.CreateKeyArgs
		require.Error(t, got.UnmarshalCBOR(bytes.NewReader([]byte("not cbor"))))
		require.Error(t, got.UnmarshalCBOR(bytes.NewReader(nil)))
	})
}
