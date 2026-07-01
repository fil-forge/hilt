package auth_test

import (
	"testing"
	"time"

	"github.com/fil-forge/hilt/internal/testutil"
	"github.com/fil-forge/hilt/pkg/rpc/service/auth"
	"github.com/fil-forge/hilt/pkg/sigv4"
	accesskeymemory "github.com/fil-forge/hilt/pkg/store/accesskey/memory"
	providermemory "github.com/fil-forge/hilt/pkg/store/provider/memory"
	"github.com/fil-forge/hilt/pkg/store/tenant"
	tenantmemory "github.com/fil-forge/hilt/pkg/store/tenant/memory"
	"github.com/fil-forge/hilt/pkg/vault"
	vaultmemory "github.com/fil-forge/hilt/pkg/vault/memory"
	s3 "github.com/fil-forge/libforge/commands/s3"
	"github.com/fil-forge/ucantone/did"
	"github.com/fil-forge/ucantone/multikey/ed25519"
	"github.com/fil-forge/ucantone/multikey/secp256k1"
	"github.com/multiformats/go-multibase"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

// signedRequest builds an S3 request presigned by the given access key signer for
// the given region.
func signedRequest(t *testing.T, signer ed25519.Signer, region string, signedAt time.Time, expires time.Duration) s3.Request {
	t.Helper()
	secret, err := multibase.Encode(multibase.Base64url, signer.Bytes())
	require.NoError(t, err)
	req := sigv4.Request{Method: "GET", URL: "https://s3.fil.one/bucket/object-key"}
	signed, err := sigv4.Presign(req, signer.KeyDID().Identifier(), secret, region, sigv4.SchemeV4, signedAt, expires)
	require.NoError(t, err)
	return s3.Request{Method: signed.Method, URL: signed.URL}
}

func TestAuthorize(t *testing.T) {
	ctx := t.Context()
	const region = "us-west-2"

	signer, err := ed25519.Generate()
	require.NoError(t, err)
	akDID := signer.KeyDID()

	// providerID is both the tenant's provider and the only legitimate invocation
	// issuer.
	providerID := testutil.RandomDID(t)

	// setup wires the stores + vault for a tenant whose provider serves the signing
	// region and that owns this access key, returning the Authorizer built from
	// them (plus the provider handle and tenant DID subtests still use).
	setup := func(t *testing.T, vaultSigner ed25519.Signer) (*auth.Authorizer, *providermemory.Store, did.DID) {
		t.Helper()
		accessKeys, tenants := accesskeymemory.New(), tenantmemory.New()
		providers, secrets := providermemory.New(), vaultmemory.New()
		require.NoError(t, providers.Add(ctx, providerID, region))
		tenantID := testutil.RandomDID(t)
		require.NoError(t, tenants.Add(ctx, tenantID, "tenant-1", providerID, "Acme", tenant.Active))
		require.NoError(t, accessKeys.Add(ctx, akDID, tenantID, "k1", nil, []string{"s3:GetObject"}, nil))
		require.NoError(t, secrets.Write(ctx, vault.AccessKeyPath(tenantID, akDID), vaultSigner.Bytes()))
		return auth.NewAuthorizer(zap.NewNop(), accessKeys, tenants, providers, secrets), providers, tenantID
	}

	t.Run("authorizes a validly-signed request", func(t *testing.T) {
		az, _, tenantID := setup(t, signer)
		authz, err := az.Authorize(ctx, providerID, signedRequest(t, signer, region, time.Now(), time.Hour))
		require.NoError(t, err)
		require.Equal(t, akDID, authz.AccessKey.ID)
		require.Equal(t, tenantID, authz.Tenant.ID)
		require.Equal(t, region, authz.Region)
		require.NotNil(t, authz.Signed)
	})

	t.Run("rejects an invalid signature", func(t *testing.T) {
		// Vault holds a different key than the one that signed the request.
		other, err := ed25519.Generate()
		require.NoError(t, err)
		az, _, _ := setup(t, other)
		_, err = az.Authorize(ctx, providerID, signedRequest(t, signer, region, time.Now(), time.Hour))
		require.Error(t, err)
	})

	t.Run("rejects an unsigned request", func(t *testing.T) {
		az, _, _ := setup(t, signer)
		_, err := az.Authorize(ctx, providerID, s3.Request{Method: "GET", URL: "https://s3.fil.one/bucket/object-key"})
		require.Error(t, err)
	})

	t.Run("rejects an unknown access key", func(t *testing.T) {
		az := auth.NewAuthorizer(zap.NewNop(), accesskeymemory.New(), tenantmemory.New(), providermemory.New(), vaultmemory.New())
		_, err := az.Authorize(ctx, providerID, signedRequest(t, signer, region, time.Now(), time.Hour))
		require.Error(t, err)
	})

	t.Run("rejects when the access key secret is missing from the vault", func(t *testing.T) {
		// The access key record exists but its private key was never written to the
		// vault — a store/vault inconsistency the signer load must reject.
		accessKeys, tenants := accesskeymemory.New(), tenantmemory.New()
		providers, secrets := providermemory.New(), vaultmemory.New()
		require.NoError(t, providers.Add(ctx, providerID, region))
		tenantID := testutil.RandomDID(t)
		require.NoError(t, tenants.Add(ctx, tenantID, "tenant-1", providerID, "Acme", tenant.Active))
		require.NoError(t, accessKeys.Add(ctx, akDID, tenantID, "k1", nil, []string{"s3:GetObject"}, nil))
		az := auth.NewAuthorizer(zap.NewNop(), accessKeys, tenants, providers, secrets)

		_, err := az.Authorize(ctx, providerID, signedRequest(t, signer, region, time.Now(), time.Hour))
		require.Error(t, err)
	})

	t.Run("rejects a region the tenant's provider does not serve", func(t *testing.T) {
		az, providers, _ := setup(t, signer)
		// A provider exists in eu-west-1, but it isn't the tenant's provider.
		require.NoError(t, providers.Add(ctx, testutil.RandomDID(t), "eu-west-1"))
		_, err := az.Authorize(ctx, providerID, signedRequest(t, signer, "eu-west-1", time.Now(), time.Hour))
		require.Error(t, err)
	})

	t.Run("rejects a region no provider serves", func(t *testing.T) {
		az, _, _ := setup(t, signer)
		// No provider is registered for eu-west-1, so validateRegion skips it.
		_, err := az.Authorize(ctx, providerID, signedRequest(t, signer, "eu-west-1", time.Now(), time.Hour))
		require.Error(t, err)
	})

	t.Run("rejects an expired presigned URL", func(t *testing.T) {
		az, _, _ := setup(t, signer)
		// Validly signed, but two hours ago with only a one-hour window.
		_, err := az.Authorize(ctx, providerID, signedRequest(t, signer, region, time.Now().Add(-2*time.Hour), time.Hour))
		require.Error(t, err)
	})

	t.Run("rejects an invocation not from the tenant's provider", func(t *testing.T) {
		az, _, _ := setup(t, signer)
		_, err := az.Authorize(ctx, testutil.RandomDID(t), signedRequest(t, signer, region, time.Now(), time.Hour))
		require.Error(t, err)
	})
}

func TestTenantIssuer(t *testing.T) {
	ctx := t.Context()
	secrets := vaultmemory.New()
	az := auth.NewAuthorizer(zap.NewNop(), accesskeymemory.New(), tenantmemory.New(), providermemory.New(), secrets)

	tenantSigner, err := secp256k1.Generate()
	require.NoError(t, err)
	tenantID := tenantSigner.KeyDID()

	t.Run("returns an issuer for a tenant with a vaulted key", func(t *testing.T) {
		require.NoError(t, secrets.Write(ctx, vault.TenantKeyPath(tenantID), tenantSigner.Bytes()))
		iss, err := az.TenantIssuer(ctx, tenantID)
		require.NoError(t, err)
		require.Equal(t, tenantID, iss.DID())
	})

	t.Run("errors when the tenant key is missing", func(t *testing.T) {
		_, err := az.TenantIssuer(ctx, testutil.RandomDID(t))
		require.Error(t, err)
	})
}
