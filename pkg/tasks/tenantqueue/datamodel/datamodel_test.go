package datamodel_test

import (
	"bytes"
	"testing"

	"github.com/fil-forge/hilt/pkg/tasks/tenantqueue/datamodel"
	s3bkt "github.com/fil-forge/libforge/commands/s3/bucket"
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

func policyDocument() s3bkt.PolicyDocument {
	resources := s3bkt.NewStringSet(s3bkt.BucketARN("photos"), s3bkt.ObjectsARN("photos"))
	return s3bkt.PolicyDocument{Version: s3bkt.Version2012, Statements: []s3bkt.Statement{
		{Sid: "readers", Effect: s3bkt.Allow, Principal: s3bkt.Only("alice", "bob"), Actions: s3bkt.NewStringSet("s3:GetObject", "s3:ListBucket"), Resources: resources},
		{Effect: s3bkt.Deny, Principal: s3bkt.Everyone(), Actions: s3bkt.NewStringSet("s3:PutObject"), Resources: resources},
	}}
}

func TestPutPolicyArgs(t *testing.T) {
	etag := `"0a1b2c"`
	for name, args := range map[string]datamodel.PutPolicyArgs{
		"an unconditional write":       {Bucket: testutil.RandomDID(t), Name: "photos", Document: policyDocument()},
		"a write under If-Match":       {Bucket: testutil.RandomDID(t), Name: "photos", Document: policyDocument(), Conditional: true, IfMatch: &etag},
		"a create under If-None-Match": {Bucket: testutil.RandomDID(t), Name: "photos", Document: policyDocument(), Conditional: true},
	} {
		t.Run(name+" round trips", func(t *testing.T) {
			var wire bytes.Buffer
			require.NoError(t, args.MarshalCBOR(&wire))
			var got datamodel.PutPolicyArgs
			require.NoError(t, got.UnmarshalCBOR(bytes.NewReader(wire.Bytes())))
			require.Equal(t, args.Bucket, got.Bucket)
			require.Equal(t, args.Name, got.Name)
			require.Equal(t, args.Conditional, got.Conditional)
			require.Equal(t, args.IfMatch, got.IfMatch)
			// The document is the same policy: it carries the same ETag,
			// which is taken over its canonical form.
			require.Equal(t, s3bkt.ETag(args.Document), s3bkt.ETag(got.Document))
			require.Len(t, got.Document.Statements, len(args.Document.Statements))

			// Encoding is deterministic: the same arguments are the same bytes.
			var again bytes.Buffer
			require.NoError(t, got.MarshalCBOR(&again))
			require.Equal(t, wire.Bytes(), again.Bytes())
		})
	}

	t.Run("rejects bytes that are not the model", func(t *testing.T) {
		var got datamodel.PutPolicyArgs
		require.Error(t, got.UnmarshalCBOR(bytes.NewReader([]byte("not cbor"))))
		require.Error(t, got.UnmarshalCBOR(bytes.NewReader(nil)))
	})
}

func TestPutPolicyResult(t *testing.T) {
	for name, result := range map[string]datamodel.PutPolicyResult{
		"a first policy": {ETag: `"0a1b2c"`, Created: true},
		"a replacement":  {ETag: `"3d4e5f"`},
	} {
		t.Run(name+" round trips", func(t *testing.T) {
			var wire bytes.Buffer
			require.NoError(t, result.MarshalCBOR(&wire))
			var got datamodel.PutPolicyResult
			require.NoError(t, got.UnmarshalCBOR(bytes.NewReader(wire.Bytes())))
			require.Equal(t, result, got)
		})
	}

	t.Run("rejects bytes that are not the model", func(t *testing.T) {
		var got datamodel.PutPolicyResult
		require.Error(t, got.UnmarshalCBOR(bytes.NewReader([]byte("not cbor"))))
		require.Error(t, got.UnmarshalCBOR(bytes.NewReader(nil)))
	})
}

func TestDeletePolicyArgs(t *testing.T) {
	etag := `"0a1b2c"`
	for name, args := range map[string]datamodel.DeletePolicyArgs{
		"an unconditional removal": {Bucket: testutil.RandomDID(t), Name: "photos"},
		"a removal under If-Match": {Bucket: testutil.RandomDID(t), Name: "photos", IfMatch: &etag},
	} {
		t.Run(name+" round trips", func(t *testing.T) {
			var wire bytes.Buffer
			require.NoError(t, args.MarshalCBOR(&wire))
			var got datamodel.DeletePolicyArgs
			require.NoError(t, got.UnmarshalCBOR(bytes.NewReader(wire.Bytes())))
			require.Equal(t, args, got)
		})
	}

	t.Run("rejects bytes that are not the model", func(t *testing.T) {
		var got datamodel.DeletePolicyArgs
		require.Error(t, got.UnmarshalCBOR(bytes.NewReader([]byte("not cbor"))))
		require.Error(t, got.UnmarshalCBOR(bytes.NewReader(nil)))
	})
}
