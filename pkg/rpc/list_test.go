package rpc_test

import (
	"testing"
	"time"

	"github.com/fil-forge/hilt/pkg/rpc"
	"github.com/fil-forge/hilt/pkg/rpc/service/auth"
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
	"github.com/fil-forge/libforge/testutil"
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
	// signing region and that owns this access key, and returns the Authorizer
	// built from them plus the bucket store subtests populate. Authentication and
	// authorization edge cases are covered by the auth service's own test suite;
	// these tests focus on the list-specific behavior.
	setup := func(t *testing.T, perms []string) (*auth.Authorizer, *bucketmemory.Store, did.DID) {
		t.Helper()
		accessKeys, tenants, buckets := accesskeymemory.New(), tenantmemory.New(), bucketmemory.New()
		providers, secrets := providermemory.New(), vaultmemory.New()
		require.NoError(t, providers.Add(ctx, providerID, region))
		tenantID := testutil.RandomDID(t)
		require.NoError(t, tenants.Add(ctx, tenantID, "tenant-1", providerID, "Acme", tenant.Active))
		require.NoError(t, accessKeys.Add(ctx, akDID, tenantID, "k1", nil, perms, nil))
		require.NoError(t, secrets.Write(ctx, vault.AccessKeyPath(tenantID, akDID), signer.Bytes()))
		az := auth.NewAuthorizer(zap.NewNop(), accessKeys, tenants, providers, buckets, secrets)
		return az, buckets, tenantID
	}

	t.Run("lists the tenant's buckets for a validly-signed request", func(t *testing.T) {
		az, buckets, tenantID := setup(t, []string{"s3:ListAllMyBuckets"})
		require.NoError(t, buckets.Add(ctx, testutil.RandomDID(t), tenantID, "alpha"))
		require.NoError(t, buckets.Add(ctx, testutil.RandomDID(t), tenantID, "bravo"))

		ok, err := rpc.ListBuckets(ctx, zap.NewNop(), az, buckets, providerID, signedListArgs(t, signer, region, time.Now(), time.Hour))
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

	t.Run("rejects a key without the list permission", func(t *testing.T) {
		az, buckets, _ := setup(t, []string{"s3:GetObject"})
		_, err := rpc.ListBuckets(ctx, zap.NewNop(), az, buckets, providerID, signedListArgs(t, signer, region, time.Now(), time.Hour))
		require.Error(t, err)
	})

	t.Run("rejects a validly-signed request for a different operation", func(t *testing.T) {
		// The key holds s3:GetObject, so a GetObject request passes Authorize — but
		// the list handler must reject it because it is not a ListBuckets operation.
		az, buckets, tenantID := setup(t, []string{"s3:GetObject"})
		require.NoError(t, buckets.Add(ctx, testutil.RandomDID(t), tenantID, "bucket-a"))
		secret, err := multibase.Encode(multibase.Base64url, signer.Bytes())
		require.NoError(t, err)
		req := sigv4.Request{Method: "GET", URL: "https://" + region + ".s3.fil.one/bucket-a/object-key"}
		signed, err := sigv4.Presign(req, akDID.Identifier(), secret, region, sigv4.SchemeV4, time.Now(), time.Hour)
		require.NoError(t, err)
		args := &s3bkt.ListArguments{Request: s3.Request{Method: signed.Method, URL: signed.URL}}
		_, err = rpc.ListBuckets(ctx, zap.NewNop(), az, buckets, providerID, args)
		require.Error(t, err)
	})
}
