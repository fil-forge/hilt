package rpc_test

import (
	"testing"
	"time"

	"github.com/fil-forge/hilt/internal/testutil"
	"github.com/fil-forge/hilt/pkg/rpc"
	"github.com/fil-forge/hilt/pkg/sigv4"
	accesskeymemory "github.com/fil-forge/hilt/pkg/store/accesskey/memory"
	bucketmemory "github.com/fil-forge/hilt/pkg/store/bucket/memory"
	providermemory "github.com/fil-forge/hilt/pkg/store/provider/memory"
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
	"go.uber.org/zap"
)

// signedListArgs builds ListArguments whose request is presigned for the given
// access key signer and region.
func signedListArgs(t *testing.T, signer ed25519.Signer, region string, signedAt time.Time, expires time.Duration) *s3bkt.ListArguments {
	t.Helper()
	secret, err := multibase.Encode(multibase.Base64url, signer.Bytes())
	require.NoError(t, err)
	req := sigv4.Request{Method: "GET", URL: "https://" + region + ".s3.fil.one/?x-id=ListBuckets"}
	signed, err := sigv4.Presign(req, signer.KeyDID().Identifier(), secret, region, sigv4.SchemeV4, signedAt, expires)
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

	// providerID is both the tenant's provider and the only legitimate
	// invocation issuer.
	providerID := testutil.RandomDID(t)

	// setup wires up the stores + vault for a tenant whose provider serves the
	// signing region and that owns this access key.
	setup := func(t *testing.T, perms []string, vaultSigner ed25519.Signer) (*accesskeymemory.Store, *tenantmemory.Store, *bucketmemory.Store, *providermemory.Store, vault.Vault, did.DID) {
		t.Helper()
		accessKeys, tenants, buckets := accesskeymemory.New(), tenantmemory.New(), bucketmemory.New()
		providers, secrets := providermemory.New(), vaultmemory.New()
		require.NoError(t, providers.Add(ctx, providerID, region))
		tenantID := testutil.RandomDID(t)
		require.NoError(t, tenants.Add(ctx, tenantID, "tenant-1", providerID, "Acme", tenant.Active))
		require.NoError(t, accessKeys.Add(ctx, akDID, tenantID, "k1", nil, perms, nil))
		require.NoError(t, secrets.Write(ctx, vault.AccessKeyPath(tenantID, akDID), vaultSigner.Bytes()))
		return accessKeys, tenants, buckets, providers, secrets, tenantID
	}

	t.Run("lists the tenant's buckets for a validly-signed request", func(t *testing.T) {
		accessKeys, tenants, buckets, providers, secrets, tenantID := setup(t, []string{"s3:ListAllMyBuckets"}, signer)
		require.NoError(t, buckets.Add(ctx, testutil.RandomDID(t), tenantID, "alpha"))
		require.NoError(t, buckets.Add(ctx, testutil.RandomDID(t), tenantID, "bravo"))

		ok, err := rpc.ListBuckets(ctx, zap.NewNop(), accessKeys, tenants, buckets, providers, secrets, providerID, signedListArgs(t, signer, region, time.Now(), time.Hour))
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
		accessKeys, tenants, buckets, providers, secrets, _ := setup(t, []string{"s3:ListAllMyBuckets"}, other)

		_, err = rpc.ListBuckets(ctx, zap.NewNop(), accessKeys, tenants, buckets, providers, secrets, providerID, signedListArgs(t, signer, region, time.Now(), time.Hour))
		require.Error(t, err)
	})

	t.Run("rejects an unknown access key", func(t *testing.T) {
		accessKeys, tenants, buckets := accesskeymemory.New(), tenantmemory.New(), bucketmemory.New()
		providers, secrets := providermemory.New(), vaultmemory.New()
		_, err := rpc.ListBuckets(ctx, zap.NewNop(), accessKeys, tenants, buckets, providers, secrets, providerID, signedListArgs(t, signer, region, time.Now(), time.Hour))
		require.Error(t, err)
	})

	t.Run("rejects a key without the list permission", func(t *testing.T) {
		accessKeys, tenants, buckets, providers, secrets, _ := setup(t, []string{"s3:GetObject"}, signer)
		_, err := rpc.ListBuckets(ctx, zap.NewNop(), accessKeys, tenants, buckets, providers, secrets, providerID, signedListArgs(t, signer, region, time.Now(), time.Hour))
		require.Error(t, err)
	})

	t.Run("rejects a region the tenant's provider does not serve", func(t *testing.T) {
		accessKeys, tenants, buckets, providers, secrets, _ := setup(t, []string{"s3:ListAllMyBuckets"}, signer)
		// A provider exists in eu-west-1, but it isn't the tenant's provider.
		require.NoError(t, providers.Add(ctx, testutil.RandomDID(t), "eu-west-1"))
		args := signedListArgs(t, signer, "eu-west-1", time.Now(), time.Hour)
		_, err := rpc.ListBuckets(ctx, zap.NewNop(), accessKeys, tenants, buckets, providers, secrets, providerID, args)
		require.Error(t, err)
	})

	t.Run("rejects an expired presigned URL", func(t *testing.T) {
		accessKeys, tenants, buckets, providers, secrets, _ := setup(t, []string{"s3:ListAllMyBuckets"}, signer)
		// Validly signed, but two hours ago with only a one-hour window.
		args := signedListArgs(t, signer, region, time.Now().Add(-2*time.Hour), time.Hour)
		_, err := rpc.ListBuckets(ctx, zap.NewNop(), accessKeys, tenants, buckets, providers, secrets, providerID, args)
		require.Error(t, err)
	})

	t.Run("rejects an invocation not from the tenant's provider", func(t *testing.T) {
		accessKeys, tenants, buckets, providers, secrets, _ := setup(t, []string{"s3:ListAllMyBuckets"}, signer)
		args := signedListArgs(t, signer, region, time.Now(), time.Hour)
		// Issuer is not the tenant's provider.
		_, err := rpc.ListBuckets(ctx, zap.NewNop(), accessKeys, tenants, buckets, providers, secrets, testutil.RandomDID(t), args)
		require.Error(t, err)
	})
}
