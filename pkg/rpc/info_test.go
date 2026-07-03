package rpc_test

import (
	"testing"

	"github.com/fil-forge/hilt/internal/testutil"
	"github.com/fil-forge/hilt/pkg/rpc"
	accesskeymemory "github.com/fil-forge/hilt/pkg/store/accesskey/memory"
	bucketmemory "github.com/fil-forge/hilt/pkg/store/bucket/memory"
	delegationmemory "github.com/fil-forge/hilt/pkg/store/delegation/memory"
	"github.com/fil-forge/libforge/commands/content"
	s3bkt "github.com/fil-forge/libforge/commands/s3/bucket"
	"github.com/fil-forge/ucantone/did"
	"github.com/fil-forge/ucantone/multikey"
	"github.com/fil-forge/ucantone/multikey/ed25519"
	"github.com/fil-forge/ucantone/multikey/secp256k1"
	"github.com/fil-forge/ucantone/ucan"
	"github.com/fil-forge/ucantone/ucan/command"
	"github.com/fil-forge/ucantone/ucan/delegation"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

func TestBucketInfo(t *testing.T) {
	ctx := t.Context()
	const bucketName = "infobucket"

	akSigner, err := ed25519.Generate()
	require.NoError(t, err)
	akDID := akSigner.KeyDID()

	tenantSigner, err := secp256k1.Generate()
	require.NoError(t, err)
	tenantID := tenantSigner.KeyDID()

	bucketSigner, err := ed25519.Generate()
	require.NoError(t, err)
	bucketID := bucketSigner.KeyDID()

	// setup seeds a bucket, an access key, a bucket→tenant root, and a
	// tenant→access-key grant with the given subject (did.DID{} = powerline).
	setup := func(t *testing.T, grantSubject did.DID) (*bucketmemory.Store, *accesskeymemory.Store, *delegationmemory.Store) {
		t.Helper()
		accessKeys, buckets, delegations := accesskeymemory.New(), bucketmemory.New(), delegationmemory.New()
		require.NoError(t, accessKeys.Add(ctx, akDID, tenantID, "k1", nil, []string{"s3:GetObject"}, nil))
		require.NoError(t, buckets.Add(ctx, bucketID, tenantID, bucketName))

		root, err := delegation.Delegate(multikey.NewIssuer(bucketID, bucketSigner), tenantID, bucketID, command.Top())
		require.NoError(t, err)
		grant, err := delegation.Delegate(multikey.NewIssuer(tenantID, tenantSigner), akDID, grantSubject, content.Retrieve.Command)
		require.NoError(t, err)
		require.NoError(t, delegations.PutBatch(ctx, []ucan.Delegation{root, grant}))

		return buckets, accessKeys, delegations
	}

	t.Run("returns the bucket, permissions, and delegation chain", func(t *testing.T) {
		buckets, accessKeys, delegations := setup(t, did.DID{}) // powerline grant reaches the bucket
		ok, blocks, err := rpc.BucketInfo(ctx, zap.NewNop(), buckets, accessKeys, delegations, &s3bkt.InfoArguments{Name: bucketName, AccessKey: akDID})
		require.NoError(t, err)

		require.Equal(t, bucketID, ok.ID)
		require.Equal(t, []string{"s3:GetObject"}, ok.Permissions.Entries[akDID])
		require.Len(t, ok.Delegations.Entries, 1)
		require.Len(t, blocks, 2) // bucket→tenant root + tenant→access-key grant
	})

	t.Run("rejects an unknown bucket", func(t *testing.T) {
		buckets, accessKeys, delegations := setup(t, did.DID{})
		_, _, err := rpc.BucketInfo(ctx, zap.NewNop(), buckets, accessKeys, delegations, &s3bkt.InfoArguments{Name: "nope", AccessKey: akDID})
		require.Error(t, err)
	})

	t.Run("rejects an unknown access key", func(t *testing.T) {
		buckets, accessKeys, delegations := setup(t, did.DID{})
		_, _, err := rpc.BucketInfo(ctx, zap.NewNop(), buckets, accessKeys, delegations, &s3bkt.InfoArguments{Name: bucketName, AccessKey: testutil.RandomDID(t)})
		require.Error(t, err)
	})

	t.Run("returns empty delegations when no grant reaches the bucket", func(t *testing.T) {
		buckets, accessKeys, delegations := setup(t, testutil.RandomDID(t)) // grant scoped to a different bucket
		ok, blocks, err := rpc.BucketInfo(ctx, zap.NewNop(), buckets, accessKeys, delegations, &s3bkt.InfoArguments{Name: bucketName, AccessKey: akDID})
		require.NoError(t, err)

		require.Equal(t, bucketID, ok.ID)
		require.Equal(t, []string{"s3:GetObject"}, ok.Permissions.Entries[akDID])
		require.Empty(t, ok.Delegations.Entries)
		require.Empty(t, blocks)
	})
}
