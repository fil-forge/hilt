package rpc_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/fil-forge/hilt/internal/testutil"
	client "github.com/fil-forge/hilt/pkg/client"
	"github.com/fil-forge/hilt/pkg/rpc"
	"github.com/fil-forge/hilt/pkg/rpc/service/auth"
	"github.com/fil-forge/hilt/pkg/sigv4"
	"github.com/fil-forge/hilt/pkg/store"
	accesskeymemory "github.com/fil-forge/hilt/pkg/store/accesskey/memory"
	bucketmemory "github.com/fil-forge/hilt/pkg/store/bucket/memory"
	delegationmemory "github.com/fil-forge/hilt/pkg/store/delegation/memory"
	providermemory "github.com/fil-forge/hilt/pkg/store/provider/memory"
	"github.com/fil-forge/hilt/pkg/store/tenant"
	tenantmemory "github.com/fil-forge/hilt/pkg/store/tenant/memory"
	"github.com/fil-forge/hilt/pkg/vault"
	vaultmemory "github.com/fil-forge/hilt/pkg/vault/memory"
	"github.com/fil-forge/libforge/commands/content"
	s3 "github.com/fil-forge/libforge/commands/s3"
	s3bkt "github.com/fil-forge/libforge/commands/s3/bucket"
	"github.com/fil-forge/ucantone/did"
	"github.com/fil-forge/ucantone/multikey"
	"github.com/fil-forge/ucantone/multikey/ed25519"
	"github.com/fil-forge/ucantone/multikey/secp256k1"
	"github.com/fil-forge/ucantone/ucan"
	"github.com/fil-forge/ucantone/ucan/command"
	"github.com/fil-forge/ucantone/ucan/delegation"
	"github.com/multiformats/go-multibase"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

// fakeSpaceChecker is a stub SpaceChecker recording its inputs.
type fakeSpaceChecker struct {
	empty  bool
	err    error
	called bool
	space  did.DID
}

func (f *fakeSpaceChecker) SpaceEmpty(_ context.Context, space did.DID, _ ...client.MethodOption) (bool, error) {
	f.called = true
	f.space = space
	return f.empty, f.err
}

// signedDeleteArgs presigns a DeleteBucket request (path-style) for the bucket.
func signedDeleteArgs(t *testing.T, signer ed25519.Signer, bucketName, region string) *s3bkt.DeleteArguments {
	t.Helper()
	secret, err := multibase.Encode(multibase.Base64url, signer.Bytes())
	require.NoError(t, err)
	req := sigv4.Request{Method: "DELETE", URL: "https://s3.fil.one/" + bucketName}
	signed, err := sigv4.Presign(req, signer.KeyDID().Identifier(), secret, region, sigv4.SchemeV4, time.Now(), time.Hour)
	require.NoError(t, err)
	return &s3bkt.DeleteArguments{Request: s3.Request{Method: signed.Method, URL: signed.URL}}
}

func TestDeleteBucket(t *testing.T) {
	ctx := t.Context()
	const (
		region     = "us-west-2"
		bucketName = "delbucket"
	)

	akSigner, err := ed25519.Generate()
	require.NoError(t, err)
	akDID := akSigner.KeyDID()

	tenantSigner, err := secp256k1.Generate()
	require.NoError(t, err)
	tenantID := tenantSigner.KeyDID()

	providerID := testutil.RandomDID(t)

	// setup wires stores + vault and seeds the bucket, its bucket→tenant root, and
	// a bucket-scoped tenant→access-key grant (both subject == bucket).
	setup := func(t *testing.T, perms []string) (*auth.Authorizer, *bucketmemory.Store, *delegationmemory.Store, did.DID) {
		t.Helper()
		accessKeys, tenants, buckets := accesskeymemory.New(), tenantmemory.New(), bucketmemory.New()
		providers, secrets, delegations := providermemory.New(), vaultmemory.New(), delegationmemory.New()
		require.NoError(t, providers.Add(ctx, providerID, region))
		require.NoError(t, tenants.Add(ctx, tenantID, "tenant-1", providerID, "Acme", tenant.Active))
		require.NoError(t, accessKeys.Add(ctx, akDID, tenantID, "k1", nil, perms, nil))
		require.NoError(t, secrets.Write(ctx, vault.AccessKeyPath(tenantID, akDID), akSigner.Bytes()))
		require.NoError(t, secrets.Write(ctx, vault.TenantKeyPath(tenantID), tenantSigner.Bytes()))

		bucketSigner, err := ed25519.Generate()
		require.NoError(t, err)
		bucketID := bucketSigner.KeyDID()
		require.NoError(t, buckets.Add(ctx, bucketID, tenantID, bucketName))

		root, err := delegation.Delegate(multikey.NewIssuer(bucketID, bucketSigner), tenantID, bucketID, command.Top())
		require.NoError(t, err)
		grant, err := delegation.Delegate(multikey.NewIssuer(tenantID, tenantSigner), akDID, bucketID, content.Retrieve.Command)
		require.NoError(t, err)
		require.NoError(t, delegations.PutBatch(ctx, []ucan.Delegation{root, grant}))

		return auth.NewAuthorizer(zap.NewNop(), accessKeys, tenants, providers, buckets, secrets), buckets, delegations, bucketID
	}

	t.Run("deletes an empty bucket and its delegations", func(t *testing.T) {
		az, buckets, delegations, bucketID := setup(t, []string{"s3:DeleteBucket"})
		checker := &fakeSpaceChecker{empty: true}

		_, err := rpc.DeleteBucket(ctx, zap.NewNop(), az, buckets, delegations, checker, providerID, signedDeleteArgs(t, akSigner, bucketName, region))
		require.NoError(t, err)

		require.True(t, checker.called)
		require.Equal(t, bucketID, checker.space)

		// Bucket record is gone.
		_, err = buckets.GetByName(ctx, bucketName)
		require.ErrorIs(t, err, store.ErrRecordNotFound)

		// The subject == bucket delegations (root to the tenant, grant to the access
		// key) are gone.
		rootPage, err := delegations.ListByAudience(ctx, tenantID)
		require.NoError(t, err)
		require.Empty(t, rootPage.Results)
		grantPage, err := delegations.ListByAudience(ctx, akDID)
		require.NoError(t, err)
		require.Empty(t, grantPage.Results)
	})

	t.Run("rejects a key without s3:DeleteBucket", func(t *testing.T) {
		az, buckets, delegations, _ := setup(t, []string{"s3:GetObject"})
		_, err := rpc.DeleteBucket(ctx, zap.NewNop(), az, buckets, delegations, &fakeSpaceChecker{empty: true}, providerID, signedDeleteArgs(t, akSigner, bucketName, region))
		require.Error(t, err)
	})

	t.Run("rejects an unknown bucket", func(t *testing.T) {
		az, buckets, delegations, _ := setup(t, []string{"s3:DeleteBucket"})
		_, err := rpc.DeleteBucket(ctx, zap.NewNop(), az, buckets, delegations, &fakeSpaceChecker{empty: true}, providerID, signedDeleteArgs(t, akSigner, "nope", region))
		require.Error(t, err)
	})

	t.Run("rejects a non-empty bucket and keeps it", func(t *testing.T) {
		az, buckets, delegations, _ := setup(t, []string{"s3:DeleteBucket"})
		_, err := rpc.DeleteBucket(ctx, zap.NewNop(), az, buckets, delegations, &fakeSpaceChecker{empty: false}, providerID, signedDeleteArgs(t, akSigner, bucketName, region))
		require.Error(t, err)
		_, err = buckets.GetByName(ctx, bucketName)
		require.NoError(t, err) // not deleted
	})

	t.Run("propagates a SpaceEmpty error", func(t *testing.T) {
		az, buckets, delegations, _ := setup(t, []string{"s3:DeleteBucket"})
		_, err := rpc.DeleteBucket(ctx, zap.NewNop(), az, buckets, delegations, &fakeSpaceChecker{err: errors.New("sprue unavailable")}, providerID, signedDeleteArgs(t, akSigner, bucketName, region))
		require.Error(t, err)
	})
}
