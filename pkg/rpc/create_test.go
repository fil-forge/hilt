package rpc_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/fil-forge/hilt/internal/testutil"
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
	"github.com/fil-forge/ucantone/ucan/delegation"
	"github.com/multiformats/go-multibase"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

// fakeProvisioner is a stub SpaceProvisioner recording its inputs.
type fakeProvisioner struct {
	sub     string
	err     error
	called  bool
	account did.DID
	space   did.DID
}

func (f *fakeProvisioner) ProvisionSpace(_ context.Context, account ucan.Issuer, space did.DID) (string, error) {
	f.called = true
	f.account = account.DID()
	f.space = space
	return f.sub, f.err
}

// signedCreateArgs presigns a CreateBucket request (path-style) for the bucket.
func signedCreateArgs(t *testing.T, signer ed25519.Signer, bucketName, region string) *s3bkt.CreateArguments {
	t.Helper()
	secret, err := multibase.Encode(multibase.Base64url, signer.Bytes())
	require.NoError(t, err)
	req := sigv4.Request{Method: "PUT", URL: "https://s3.fil.one/" + bucketName}
	signed, err := sigv4.Presign(req, signer.KeyDID().Identifier(), secret, region, sigv4.SchemeV4, time.Now(), time.Hour)
	require.NoError(t, err)
	return &s3bkt.CreateArguments{Request: s3.Request{Method: signed.Method, URL: signed.URL}}
}

func TestCreateBucket(t *testing.T) {
	ctx := t.Context()
	const (
		region     = "us-west-2"
		bucketName = "newbucket"
	)

	// The access key signs the request.
	akSigner, err := ed25519.Generate()
	require.NoError(t, err)
	akDID := akSigner.KeyDID()

	// The tenant signs the Sprue provisioning invocation and the powerline
	// delegation; its secp256k1 key lives in the vault.
	tenantSigner, err := secp256k1.Generate()
	require.NoError(t, err)
	tenantID := tenantSigner.KeyDID()

	providerID := testutil.RandomDID(t)

	// setup wires the stores + vault and seeds a powerline (undefined-subject)
	// tenant→access-key delegation for /content/retrieve.
	setup := func(t *testing.T, perms []string) (*auth.Authorizer, *bucketmemory.Store, *delegationmemory.Store) {
		t.Helper()
		accessKeys, tenants, buckets := accesskeymemory.New(), tenantmemory.New(), bucketmemory.New()
		providers, secrets, delegations := providermemory.New(), vaultmemory.New(), delegationmemory.New()
		require.NoError(t, providers.Add(ctx, providerID, region))
		require.NoError(t, tenants.Add(ctx, tenantID, "tenant-1", providerID, "Acme", tenant.Active))
		require.NoError(t, accessKeys.Add(ctx, akDID, tenantID, "k1", nil, perms, nil))
		require.NoError(t, secrets.Write(ctx, vault.AccessKeyPath(tenantID, akDID), akSigner.Bytes()))
		require.NoError(t, secrets.Write(ctx, vault.TenantKeyPath(tenantID), tenantSigner.Bytes()))

		powerline, err := delegation.Delegate(multikey.NewIssuer(tenantID, tenantSigner), akDID, did.DID{}, content.Retrieve.Command)
		require.NoError(t, err)
		require.NoError(t, delegations.PutBatch(ctx, []ucan.Delegation{powerline}))

		return auth.NewAuthorizer(zap.NewNop(), accessKeys, tenants, providers, buckets, secrets), buckets, delegations
	}

	t.Run("creates and provisions the bucket, returning the powerline chain", func(t *testing.T) {
		az, buckets, delegations := setup(t, []string{"s3:CreateBucket", "s3:GetObject"})
		prov := &fakeProvisioner{sub: "sub-1"}

		ok, blocks, err := rpc.CreateBucket(ctx, zap.NewNop(), az, buckets, delegations, prov, providerID, signedCreateArgs(t, akSigner, bucketName, region))
		require.NoError(t, err)

		// Bucket persisted under the tenant, with the returned DID.
		rec, err := buckets.GetByName(ctx, bucketName)
		require.NoError(t, err)
		require.Equal(t, rec.ID, ok.Bucket)
		require.Equal(t, tenantID, rec.Tenant)

		// Provisioned with Sprue as the tenant, for the new bucket.
		require.True(t, prov.called)
		require.Equal(t, tenantID, prov.account)
		require.Equal(t, ok.Bucket, prov.space)

		// Permissions + a derived verification key for the access key.
		require.Equal(t, []string{"s3:CreateBucket", "s3:GetObject"}, ok.Permissions.Entries[akDID])
		keys := ok.Keys.Entries[akDID]
		require.Len(t, keys, 1)
		require.Equal(t, s3.KeyKindSigV4, keys[0].Kind)

		// The powerline chain (root bucket→tenant + tenant→access-key) is returned.
		require.Len(t, ok.Delegations.Entries, 1)
		require.Len(t, blocks, 2)
		var hasRoot bool
		for _, b := range blocks {
			if b.Subject() == ok.Bucket && b.Audience() == tenantID {
				hasRoot = true
			}
		}
		require.True(t, hasRoot, "expected a bucket→tenant root delegation among the returned blocks")
	})

	t.Run("rejects a key without s3:CreateBucket", func(t *testing.T) {
		az, buckets, delegations := setup(t, []string{"s3:GetObject"})
		_, _, err := rpc.CreateBucket(ctx, zap.NewNop(), az, buckets, delegations, &fakeProvisioner{}, providerID, signedCreateArgs(t, akSigner, bucketName, region))
		require.Error(t, err)
	})

	t.Run("rejects a duplicate bucket name", func(t *testing.T) {
		az, buckets, delegations := setup(t, []string{"s3:CreateBucket"})
		require.NoError(t, buckets.Add(ctx, testutil.RandomDID(t), tenantID, bucketName))
		_, _, err := rpc.CreateBucket(ctx, zap.NewNop(), az, buckets, delegations, &fakeProvisioner{}, providerID, signedCreateArgs(t, akSigner, bucketName, region))
		require.Error(t, err)
	})

	t.Run("rolls back the bucket when provisioning fails", func(t *testing.T) {
		az, buckets, delegations := setup(t, []string{"s3:CreateBucket"})
		prov := &fakeProvisioner{err: errors.New("sprue unavailable")}
		_, _, err := rpc.CreateBucket(ctx, zap.NewNop(), az, buckets, delegations, prov, providerID, signedCreateArgs(t, akSigner, bucketName, region))
		require.Error(t, err)
		_, err = buckets.GetByName(ctx, bucketName)
		require.ErrorIs(t, err, store.ErrRecordNotFound)
	})
}
