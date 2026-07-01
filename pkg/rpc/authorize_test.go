package rpc_test

import (
	"testing"
	"time"

	"github.com/fil-forge/hilt/internal/testutil"
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
	"github.com/fil-forge/libforge/commands/content"
	s3 "github.com/fil-forge/libforge/commands/s3"
	s3req "github.com/fil-forge/libforge/commands/s3/request"
	"github.com/fil-forge/ucantone/did"
	"github.com/fil-forge/ucantone/multikey/ed25519"
	"github.com/fil-forge/ucantone/ucan"
	"github.com/ipfs/go-cid"
	"github.com/multiformats/go-multibase"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

// signedGetArgs builds AuthorizeArguments whose request is a presigned GET of an
// object in the named bucket (path-style addressing: bucket is the first path
// segment).
func signedGetArgs(t *testing.T, signer ed25519.Signer, bucketName, region string, signedAt time.Time, expires time.Duration) *s3req.AuthorizeArguments {
	t.Helper()
	secret, err := multibase.Encode(multibase.Base64url, signer.Bytes())
	require.NoError(t, err)
	req := sigv4.Request{Method: "GET", URL: "https://s3.fil.one/" + bucketName + "/object-key"}
	signed, err := sigv4.Presign(req, signer.KeyDID().Identifier(), secret, region, sigv4.SchemeV4, signedAt, expires)
	require.NoError(t, err)
	return &s3req.AuthorizeArguments{Request: s3.Request{Method: signed.Method, URL: signed.URL}}
}

func TestAuthorizeRequest(t *testing.T) {
	ctx := t.Context()
	const (
		region     = "us-west-2"
		bucketName = "mybucket"
	)

	// The access key signs the request; its private key lives in the vault so the
	// handler can mint delegations as the access key.
	akSigner, err := ed25519.Generate()
	require.NoError(t, err)
	akDID := akSigner.KeyDID()

	// providerID is both the tenant's provider and the only legitimate invocation
	// issuer. bucketID/tenantID are opaque DIDs — the handler no longer reads any
	// stored delegation chain.
	bucketID := testutil.RandomDID(t)
	tenantID := testutil.RandomDID(t)
	providerID := testutil.RandomDID(t)

	// setup wires the stores + vault for a tenant whose provider serves the signing
	// region and that owns this access key + bucket, returning the Authorizer built
	// from them plus the bucket store.
	setup := func(t *testing.T, perms []string, vaultSigner ed25519.Signer) (*auth.Authorizer, *bucketmemory.Store) {
		t.Helper()
		accessKeys, tenants, buckets := accesskeymemory.New(), tenantmemory.New(), bucketmemory.New()
		providers, secrets := providermemory.New(), vaultmemory.New()

		require.NoError(t, providers.Add(ctx, providerID, region))
		require.NoError(t, tenants.Add(ctx, tenantID, "tenant-1", providerID, "Acme", tenant.Active))
		require.NoError(t, accessKeys.Add(ctx, akDID, tenantID, "k1", nil, perms, nil))
		require.NoError(t, secrets.Write(ctx, vault.AccessKeyPath(tenantID, akDID), vaultSigner.Bytes()))
		require.NoError(t, buckets.Add(ctx, bucketID, tenantID, bucketName))

		return auth.NewAuthorizer(zap.NewNop(), accessKeys, tenants, providers, secrets), buckets
	}

	call := func(t *testing.T, authorizer *auth.Authorizer, buckets *bucketmemory.Store, issuer did.DID, args *s3req.AuthorizeArguments) (*s3req.AuthorizeOK, []ucan.Delegation, error) {
		t.Helper()
		return rpc.AuthorizeRequest(ctx, zap.NewNop(), authorizer, buckets, issuer, args)
	}

	t.Run("authorizes a validly-signed request and mints a delegation to the issuer", func(t *testing.T) {
		az, buckets := setup(t, []string{"s3:GetObject"}, akSigner)
		args := signedGetArgs(t, akSigner, bucketName, region, time.Now(), time.Hour)

		ok, blocks, err := call(t, az, buckets, providerID, args)
		require.NoError(t, err)

		require.Equal(t, bucketID, ok.Bucket)
		require.Equal(t, []string{"s3:GetObject"}, ok.Permissions.Entries[akDID])

		// The derived key verifies the request locally (the gateway path).
		keys := ok.Keys.Entries[akDID]
		require.Len(t, keys, 1)
		require.Equal(t, s3.KeyKindSigV4, keys[0].Kind)
		sr, err := sigv4.Parse(sigv4.Request{Method: args.Request.Method, URL: args.Request.URL})
		require.NoError(t, err)
		require.NoError(t, sigv4.VerifyWithKey(sr, keys[0].Data))

		// s3:GetObject maps to /content/retrieve: exactly one minted delegation,
		// issued to the invocation issuer over the bucket, no proof chain fetched.
		require.Len(t, blocks, 1)
		reDel := blocks[0]
		require.Equal(t, providerID, reDel.Audience())
		require.Equal(t, bucketID, reDel.Subject())
		require.Equal(t, content.Retrieve.Command.String(), reDel.Command().String())

		exp := reDel.Expiration()
		require.NotNil(t, exp)
		now := time.Now().Unix()
		// Expires at the next UTC midnight: a day boundary within the next 24h.
		require.Zero(t, int64(*exp)%86400, "expiry should be a UTC midnight")
		require.Greater(t, int64(*exp), now)
		require.LessOrEqual(t, int64(*exp), now+86400)

		// The delegations map keys the minted delegation to its own CID (the
		// initial-implementation proof chain).
		require.Len(t, ok.Delegations.Entries, 1)
		chain, found := ok.Delegations.Entries[reDel.Link()]
		require.True(t, found)
		require.Equal(t, []cid.Cid{reDel.Link()}, chain)
	})

	t.Run("rejects a key lacking the permission for the action", func(t *testing.T) {
		az, buckets := setup(t, []string{"s3:PutObject"}, akSigner)
		args := signedGetArgs(t, akSigner, bucketName, region, time.Now(), time.Hour)
		_, _, err := call(t, az, buckets, providerID, args)
		require.Error(t, err)
	})

	t.Run("rejects an unknown bucket", func(t *testing.T) {
		az, buckets := setup(t, []string{"s3:GetObject"}, akSigner)
		args := signedGetArgs(t, akSigner, "nope", region, time.Now(), time.Hour)
		_, _, err := call(t, az, buckets, providerID, args)
		require.Error(t, err)
	})
}
