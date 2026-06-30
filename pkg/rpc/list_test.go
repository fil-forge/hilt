package rpc_test

import (
	"testing"
	"time"

	"github.com/fil-forge/hilt/internal/testutil"
	"github.com/fil-forge/hilt/pkg/rpc"
	"github.com/fil-forge/hilt/pkg/sigv4"
	accesskeymemory "github.com/fil-forge/hilt/pkg/store/accesskey/memory"
	bucketmemory "github.com/fil-forge/hilt/pkg/store/bucket/memory"
	"github.com/fil-forge/hilt/pkg/store/tenant"
	tenantmemory "github.com/fil-forge/hilt/pkg/store/tenant/memory"
	"github.com/fil-forge/hilt/pkg/vault"
	vaultmemory "github.com/fil-forge/hilt/pkg/vault/memory"
	s3 "github.com/fil-forge/libforge/commands/s3"
	s3bkt "github.com/fil-forge/libforge/commands/s3/bucket"
	"github.com/fil-forge/ucantone/did"
	"github.com/fil-forge/ucantone/multikey/ed25519"
	"github.com/multiformats/go-multibase"
	"github.com/stretchr/testify/require"
)

// signedListArgs builds ListArguments whose request is presigned for the given
// access key signer and region.
func signedListArgs(t *testing.T, signer ed25519.Signer, region string) *s3bkt.ListArguments {
	t.Helper()
	secret, err := multibase.Encode(multibase.Base64url, signer.Bytes())
	require.NoError(t, err)
	req := sigv4.Request{Method: "GET", URL: "https://" + region + ".s3.fil.one/?x-id=ListBuckets"}
	signed, err := sigv4.Presign(req, signer.KeyDID().Identifier(), secret, region, sigv4.SchemeV4, time.Unix(1750000000, 0).UTC())
	require.NoError(t, err)
	return &s3bkt.ListArguments{Request: s3.Request{
		Method: signed.Method,
		URL:    signed.URL,
	}}
}

func TestListBuckets(t *testing.T) {
	ctx := t.Context()
	const region = "us-west-2"

	signer, err := ed25519.Generate()
	require.NoError(t, err)
	akDID := signer.KeyDID()

	// seed wires up the stores + vault for a tenant that owns this access key.
	seed := func(t *testing.T, perms []string, vaultSigner ed25519.Signer) (*accesskeymemory.Store, *tenantmemory.Store, *bucketmemory.Store, vault.Vault, did.DID) {
		t.Helper()
		accessKeys, tenants, buckets, secrets := accesskeymemory.New(), tenantmemory.New(), bucketmemory.New(), vaultmemory.New()
		tenantID := testutil.RandomDID(t)
		require.NoError(t, tenants.Add(ctx, tenantID, "tenant-1", testutil.RandomDID(t), "Acme", tenant.Active))
		require.NoError(t, accessKeys.Add(ctx, akDID, tenantID, "k1", nil, perms, nil))
		require.NoError(t, secrets.Write(ctx, vault.AccessKeyPath(tenantID, akDID), vaultSigner.Bytes()))
		return accessKeys, tenants, buckets, secrets, tenantID
	}

	t.Run("lists the tenant's buckets for a validly-signed request", func(t *testing.T) {
		accessKeys, tenants, buckets, secrets, tenantID := seed(t, []string{"s3:ListAllMyBuckets"}, signer)
		require.NoError(t, buckets.Add(ctx, testutil.RandomDID(t), tenantID, "alpha"))
		require.NoError(t, buckets.Add(ctx, testutil.RandomDID(t), tenantID, "bravo"))

		ok, err := rpc.ListBuckets(ctx, accessKeys, tenants, buckets, secrets, signedListArgs(t, signer, region))
		require.NoError(t, err)
		require.Equal(t, "Acme", ok.Owner.DisplayName)
		require.Equal(t, tenantID.String(), ok.Owner.ID)
		require.Len(t, ok.Buckets, 2)

		byName := map[string]s3bkt.Bucket{}
		for _, b := range ok.Buckets {
			byName[b.Name] = b
		}
		require.Equal(t, "arn:aws:s3:::alpha", byName["alpha"].ARN)
		require.Equal(t, region, byName["alpha"].Region)
		require.NotEmpty(t, byName["alpha"].CreationDate)
		require.Contains(t, byName, "bravo")
	})

	t.Run("rejects an invalid signature", func(t *testing.T) {
		// Vault holds a different key than the one that signed the request.
		other, err := ed25519.Generate()
		require.NoError(t, err)
		accessKeys, tenants, buckets, secrets, _ := seed(t, []string{"s3:ListAllMyBuckets"}, other)

		_, err = rpc.ListBuckets(ctx, accessKeys, tenants, buckets, secrets, signedListArgs(t, signer, region))
		require.Error(t, err)
	})

	t.Run("rejects an unknown access key", func(t *testing.T) {
		accessKeys, tenants, buckets, secrets := accesskeymemory.New(), tenantmemory.New(), bucketmemory.New(), vaultmemory.New()
		_, err := rpc.ListBuckets(ctx, accessKeys, tenants, buckets, secrets, signedListArgs(t, signer, region))
		require.Error(t, err)
	})

	t.Run("rejects a key without the list permission", func(t *testing.T) {
		accessKeys, tenants, buckets, secrets, _ := seed(t, []string{"s3:GetObject"}, signer)
		_, err := rpc.ListBuckets(ctx, accessKeys, tenants, buckets, secrets, signedListArgs(t, signer, region))
		require.Error(t, err)
	})
}
