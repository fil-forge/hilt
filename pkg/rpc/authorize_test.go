package rpc_test

import (
	"testing"
	"time"

	"github.com/fil-forge/hilt/pkg/bucketpolicy"
	"github.com/fil-forge/hilt/pkg/rpc"
	"github.com/fil-forge/hilt/pkg/rpc/service/auth"
	"github.com/fil-forge/hilt/pkg/s3perm"
	"github.com/fil-forge/hilt/pkg/sigv4"
	"github.com/fil-forge/hilt/pkg/store/accesskey"
	accesskeymemory "github.com/fil-forge/hilt/pkg/store/accesskey/memory"
	bucketmemory "github.com/fil-forge/hilt/pkg/store/bucket/memory"
	bucketpolicystore "github.com/fil-forge/hilt/pkg/store/bucketpolicy"
	bucketpolicymemory "github.com/fil-forge/hilt/pkg/store/bucketpolicy/memory"
	principalmemory "github.com/fil-forge/hilt/pkg/store/principal/memory"
	providermemory "github.com/fil-forge/hilt/pkg/store/provider/memory"
	"github.com/fil-forge/hilt/pkg/store/tenant"
	tenantmemory "github.com/fil-forge/hilt/pkg/store/tenant/memory"
	"github.com/fil-forge/hilt/pkg/vault"
	vaultmemory "github.com/fil-forge/hilt/pkg/vault/memory"
	"github.com/fil-forge/libforge/commands/content"
	s3 "github.com/fil-forge/libforge/commands/s3"
	s3req "github.com/fil-forge/libforge/commands/s3/request"
	"github.com/fil-forge/libforge/testutil"
	"github.com/fil-forge/ucantone/did"
	"github.com/fil-forge/ucantone/multikey/ed25519"
	"github.com/fil-forge/ucantone/multikey/secp256k1"
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

// signedCopyArgs builds AuthorizeArguments for a CopyObject of object-key from
// srcBucket into bucketName, with the copy-source header covered by the signature.
func signedCopyArgs(t *testing.T, signer ed25519.Signer, bucketName, srcBucket, region string) *s3req.AuthorizeArguments {
	t.Helper()
	secret, err := multibase.Encode(multibase.Base64url, signer.Bytes())
	require.NoError(t, err)
	headers := map[string]string{"x-amz-copy-source": srcBucket + "/object-key"}
	req := sigv4.Request{Method: "PUT", URL: "https://s3.fil.one/" + bucketName + "/object-key", Headers: headers}
	signed, err := sigv4.Presign(req, signer.KeyDID().Identifier(), secret, region, sigv4.SchemeV4, time.Now(), time.Hour,
		sigv4.WithSignedHeaders("x-amz-copy-source"))
	require.NoError(t, err)
	return &s3req.AuthorizeArguments{Request: s3.Request{Method: signed.Method, URL: signed.URL, Headers: headers}}
}

func TestAuthorizeRequest(t *testing.T) {
	ctx := t.Context()
	const (
		region     = "us-west-2"
		bucketName = "mybucket"
		srcName    = "srcbucket"
	)
	srcID := testutil.RandomDID(t)

	// The access key signs the request; its private key lives in the vault so the
	// handler can issue delegations as the access key.
	akSigner, err := ed25519.Generate()
	require.NoError(t, err)
	akDID := akSigner.KeyDID()

	// providerID is both the tenant's provider and the only legitimate invocation
	// issuer. bucketID/tenantID are opaque DIDs — the handler no longer reads any
	// stored delegation chain.
	bucketID := testutil.RandomDID(t)
	tenantID := testutil.RandomDID(t)
	providerID := testutil.RandomDID(t)

	// tenantSigner is the tenant's secp256k1 key: a principal-bound key holds no
	// delegation of its own, so the tenant signs the per-request ones.
	tenantSigner, err := secp256k1.Generate()
	require.NoError(t, err)

	// setup wires the stores + vault for a tenant whose provider serves the signing
	// region and that owns this credential + bucket, returning the Authorizer
	// built from them and the policy store. The credential is a service key
	// carrying perms unless principalBound, in which case "user-1" is a
	// principal of the tenant and the key carries none.
	setup := func(t *testing.T, perms []string, principalBound bool, vaultSigner ed25519.Signer) (*auth.Authorizer, *bucketpolicymemory.Store) {
		t.Helper()
		accessKeys, tenants, buckets := accesskeymemory.New(), tenantmemory.New(), bucketmemory.New()
		providers, secrets := providermemory.New(), vaultmemory.New()
		principals, policies := principalmemory.New(), bucketpolicymemory.New()

		require.NoError(t, providers.Add(ctx, providerID, region, nil))
		require.NoError(t, tenants.Add(ctx, tenantID, "tenant-1", providerID, tenant.Active))
		in := accesskey.Input{ID: akDID, Tenant: tenantID, Name: "k1", Permissions: perms}
		if principalBound {
			principal := "user-1"
			in = accesskey.Input{ID: akDID, Tenant: tenantID, Name: "k1", Principal: &principal}
			require.NoError(t, principals.Add(ctx, tenantID, principal))
		}
		require.NoError(t, accessKeys.Add(ctx, in))
		require.NoError(t, secrets.Write(ctx, vault.AccessKeyPath(tenantID, akDID), vaultSigner.Bytes()))
		require.NoError(t, secrets.Write(ctx, vault.TenantKeyPath(tenantID), tenantSigner.Bytes()))
		require.NoError(t, buckets.Add(ctx, bucketID, tenantID, bucketName))
		require.NoError(t, buckets.Add(ctx, srcID, tenantID, srcName))

		return auth.NewAuthorizer(zap.NewNop(), accessKeys, tenants, providers, buckets, principals, policies, secrets), policies
	}

	// grant stores a policy allowing "user-1" the given actions on the bucket.
	grant := func(t *testing.T, policies *bucketpolicymemory.Store, actions ...string) {
		t.Helper()
		_, err := policies.Put(ctx, bucketpolicystore.Input{
			Bucket: bucketID,
			Tenant: tenantID,
			Policy: bucketpolicy.Policy{Statements: []bucketpolicy.Statement{{
				Effect:     bucketpolicy.Allow,
				Principals: []string{"user-1"},
				Actions:    actions,
			}}},
		}, nil)
		require.NoError(t, err)
	}

	call := func(t *testing.T, authorizer *auth.Authorizer, issuer did.DID, args *s3req.AuthorizeArguments) (*s3req.AuthorizeOK, []ucan.Delegation, error) {
		t.Helper()
		return rpc.AuthorizeRequest(ctx, zap.NewNop(), authorizer, issuer, args)
	}

	t.Run("authorizes a validly-signed request and issues a delegation to the issuer", func(t *testing.T) {
		az, _ := setup(t, []string{"s3:GetObject"}, false, akSigner)
		args := signedGetArgs(t, akSigner, bucketName, region, time.Now(), time.Hour)

		ok, blocks, err := call(t, az, providerID, args)
		require.NoError(t, err)

		require.Equal(t, &bucketID, ok.Bucket)
		require.Equal(t, tenantID, ok.Tenant)
		require.Equal(t, []string{"s3:GetObject"}, ok.Permissions.Entries[akDID])

		// The derived key verifies the request locally (the gateway path).
		keys := ok.Keys.Entries[akDID]
		require.Len(t, keys, 1)
		require.Equal(t, s3.KeyKindSigV4, keys[0].Kind)
		sr, err := sigv4.Parse(sigv4.Request{Method: args.Request.Method, URL: args.Request.URL})
		require.NoError(t, err)
		require.NoError(t, sigv4.VerifyWithKey(sr, keys[0].Data))

		// s3:GetObject maps to /content/retrieve: exactly one delegation issued to
		// the invocation issuer over the bucket, no proof chain fetched.
		require.Len(t, blocks, 1)
		reDel := blocks[0]
		require.Equal(t, providerID, reDel.Audience())
		require.Equal(t, bucketID, reDel.Subject())
		require.Equal(t, content.Retrieve.Command.String(), reDel.Command().String())

		exp := reDel.Expiration()
		require.NotNil(t, exp)
		now := time.Now().Unix()
		// Expires at the next UTC midnight plus the max clock skew, so the gateway
		// can still enact requests signed just before the key's date rolls over.
		skew := int64(sigv4.MaxClockSkew / time.Second)
		require.Zero(t, (int64(*exp)-skew)%86400, "expiry should be a UTC midnight plus the max clock skew")
		require.Greater(t, int64(*exp), now)
		require.LessOrEqual(t, int64(*exp), now+86400+skew)

		// The delegations map keys the issued delegation to its own CID (the
		// initial-implementation proof chain).
		require.Len(t, ok.Delegations.Entries, 1)
		chain, found := ok.Delegations.Entries[reDel.Link()]
		require.True(t, found)
		require.Equal(t, []cid.Cid{reDel.Link()}, chain)
	})

	t.Run("a copy from another bucket also delegates the source's read", func(t *testing.T) {
		az, _ := setup(t, []string{"s3:GetObject", "s3:PutObject"}, false, akSigner)
		ok, blocks, err := call(t, az, providerID, signedCopyArgs(t, akSigner, bucketName, srcName, region))
		require.NoError(t, err)
		require.Equal(t, &bucketID, ok.Bucket)

		// The destination's PutObject commands plus one /content/retrieve over the
		// source, all keyed in the proof set.
		putCmds := s3perm.CommandsFor("s3:PutObject")
		require.Len(t, blocks, len(putCmds)+1)
		require.Len(t, ok.Delegations.Entries, len(putCmds)+1)
		var srcRetrieve int
		for _, d := range blocks {
			require.Equal(t, providerID, d.Audience())
			if d.Subject() == srcID {
				require.Equal(t, content.Retrieve.Command.String(), d.Command().String())
				srcRetrieve++
			} else {
				require.Equal(t, bucketID, d.Subject())
			}
		}
		require.Equal(t, 1, srcRetrieve)
	})

	t.Run("a copy within one bucket delegates nothing extra", func(t *testing.T) {
		az, _ := setup(t, []string{"s3:GetObject", "s3:PutObject"}, false, akSigner)
		_, blocks, err := call(t, az, providerID, signedCopyArgs(t, akSigner, bucketName, bucketName, region))
		require.NoError(t, err)
		require.Len(t, blocks, len(s3perm.CommandsFor("s3:PutObject")))
	})

	t.Run("a principal-bound key gets tenant-signed delegations and its effective set", func(t *testing.T) {
		az, policies := setup(t, nil, true, akSigner)
		grant(t, policies, "s3:GetObject", "s3:ListBucket")
		args := signedGetArgs(t, akSigner, bucketName, region, time.Now(), time.Hour)

		ok, blocks, err := call(t, az, providerID, args)
		require.NoError(t, err)

		require.NotNil(t, ok.Principal)
		require.Equal(t, "user-1", *ok.Principal)
		require.Equal(t, []string{"s3:GetObject", "s3:ListBucket"}, ok.Permissions.Entries[akDID])

		// The tenant issues the per-request delegation: the principal holds none
		// of its own and the key is not a hop in the chain.
		require.Len(t, blocks, 1)
		reDel := blocks[0]
		require.Equal(t, tenantID, reDel.Issuer())
		require.Equal(t, providerID, reDel.Audience())
		require.Equal(t, bucketID, reDel.Subject())
		require.Equal(t, content.Retrieve.Command.String(), reDel.Command().String())
	})

	t.Run("a service key keeps signing its own delegations", func(t *testing.T) {
		az, _ := setup(t, []string{"s3:GetObject"}, false, akSigner)
		args := signedGetArgs(t, akSigner, bucketName, region, time.Now(), time.Hour)

		ok, blocks, err := call(t, az, providerID, args)
		require.NoError(t, err)
		require.Nil(t, ok.Principal)
		require.Len(t, blocks, 1)
		require.Equal(t, akDID, blocks[0].Issuer())
	})

	t.Run("a principal with no policy on the bucket cannot see it", func(t *testing.T) {
		az, _ := setup(t, nil, true, akSigner)
		args := signedGetArgs(t, akSigner, bucketName, region, time.Now(), time.Hour)
		_, _, err := call(t, az, providerID, args)
		require.ErrorIs(t, err, auth.ErrUnknownBucket)
	})

	t.Run("rejects a key lacking the permission for the action", func(t *testing.T) {
		az, _ := setup(t, []string{"s3:PutObject"}, false, akSigner)
		args := signedGetArgs(t, akSigner, bucketName, region, time.Now(), time.Hour)
		_, _, err := call(t, az, providerID, args)
		require.Error(t, err)
	})

	t.Run("a bucket-configuration read issues no delegation", func(t *testing.T) {
		// s3:GetBucketVersioning maps to no Forge command: Ingot answers it from
		// its registry, so the gateway needs the permission and nothing else.
		az, policies := setup(t, nil, true, akSigner)
		grant(t, policies, "s3:GetBucketVersioning")
		secret, err := multibase.Encode(multibase.Base64url, akSigner.Bytes())
		require.NoError(t, err)
		signed, err := sigv4.Presign(
			sigv4.Request{Method: "GET", URL: "https://s3.fil.one/" + bucketName + "?versioning"},
			akDID.Identifier(), secret, region, sigv4.SchemeV4, time.Now(), time.Hour)
		require.NoError(t, err)

		ok, blocks, err := call(t, az, providerID, &s3req.AuthorizeArguments{
			Request: s3.Request{Method: signed.Method, URL: signed.URL},
		})
		require.NoError(t, err)
		require.Empty(t, blocks)
		require.Empty(t, ok.Delegations.Entries)
		require.Equal(t, []string{"s3:GetBucketVersioning"}, ok.Permissions.Entries[akDID])
	})

	t.Run("rejects an unknown bucket", func(t *testing.T) {
		az, _ := setup(t, []string{"s3:GetObject"}, false, akSigner)
		args := signedGetArgs(t, akSigner, "nope", region, time.Now(), time.Hour)
		_, _, err := call(t, az, providerID, args)
		require.Error(t, err)
	})
}
