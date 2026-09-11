package auth_test

import (
	"testing"
	"time"

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
	"github.com/fil-forge/libforge/testutil"
	"github.com/fil-forge/ucantone/did"
	"github.com/fil-forge/ucantone/multikey"
	"github.com/fil-forge/ucantone/multikey/ed25519"
	"github.com/fil-forge/ucantone/multikey/secp256k1"
	"github.com/multiformats/go-multibase"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

// signedRequest builds an S3 request presigned by the given access key signer for
// the given region.
func signedRequest(t *testing.T, signer multikey.Signer, region string, signedAt time.Time, expires time.Duration) s3.Request {
	t.Helper()
	secret, err := multibase.Encode(multibase.Base64url, signer.Bytes())
	require.NoError(t, err)
	req := sigv4.Request{Method: "GET", URL: "https://s3.fil.one/bucket/object-key"}
	signed, err := sigv4.Presign(req, signer.KeyDID().Identifier(), secret, region, sigv4.SchemeV4, signedAt, expires)
	require.NoError(t, err)
	return s3.Request{Method: signed.Method, URL: signed.URL}
}

type setupConfig struct {
	accessKeyExpires *time.Time
	accessKeyBuckets []did.DID
	// accessKeyPermissions defaults to s3:GetObject alone.
	accessKeyPermissions []string
	tenantStatus         tenant.Status
}

// signedCopyRequest presigns a CopyObject: PUT of object-key in dstBucket with an
// x-amz-copy-source naming srcBucket/object-key. The header is covered by the
// signature only when signSource is set.
func signedCopyRequest(t *testing.T, signer multikey.Signer, dstBucket, srcBucket, region string, signSource bool) s3.Request {
	t.Helper()
	secret, err := multibase.Encode(multibase.Base64url, signer.Bytes())
	require.NoError(t, err)
	headers := map[string]string{"x-amz-copy-source": "/" + srcBucket + "/object-key"}
	req := sigv4.Request{Method: "PUT", URL: "https://s3.fil.one/" + dstBucket + "/object-key", Headers: headers}
	var opts []sigv4.PresignOption
	if signSource {
		opts = append(opts, sigv4.WithSignedHeaders("x-amz-copy-source"))
	}
	signed, err := sigv4.Presign(req, signer.KeyDID().Identifier(), secret, region, sigv4.SchemeV4, time.Now(), time.Hour, opts...)
	require.NoError(t, err)
	return s3.Request{Method: signed.Method, URL: signed.URL, Headers: headers}
}

// signedObjectRequest presigns a GET of an object in the named bucket.
func signedObjectRequest(t *testing.T, signer multikey.Signer, bucketName, region string) s3.Request {
	t.Helper()
	secret, err := multibase.Encode(multibase.Base64url, signer.Bytes())
	require.NoError(t, err)
	req := sigv4.Request{Method: "GET", URL: "https://s3.fil.one/" + bucketName + "/object-key"}
	signed, err := sigv4.Presign(req, signer.KeyDID().Identifier(), secret, region, sigv4.SchemeV4, time.Now(), time.Hour)
	require.NoError(t, err)
	return s3.Request{Method: signed.Method, URL: signed.URL}
}

func TestAuthorize(t *testing.T) {
	ctx := t.Context()
	const region = "us-west-2"

	accessKey, err := ed25519.GenerateIssuer()
	require.NoError(t, err)

	// providerID is both the tenant's provider and the only legitimate invocation
	// issuer.
	providerID := testutil.RandomDID(t)
	// The tenant's two buckets, and a bucket of some other tenant.
	bucketID, bucket2ID, theirsID := testutil.RandomDID(t), testutil.RandomDID(t), testutil.RandomDID(t)

	// setup wires the stores + vault for a tenant whose provider serves the signing
	// region and that owns this access key, returning the Authorizer built from
	// them (plus the provider handle and tenant DID subtests still use).
	setup := func(t *testing.T, accessKey multikey.Issuer, setupConfig *setupConfig) (*auth.Authorizer, *providermemory.Store, did.DID) {
		t.Helper()
		accessKeys, tenants := accesskeymemory.New(), tenantmemory.New()
		providers, buckets, secrets := providermemory.New(), bucketmemory.New(), vaultmemory.New()
		require.NoError(t, providers.Add(ctx, providerID, region, nil))
		tenantID := testutil.RandomDID(t)
		tenantStatus := tenant.Active
		if setupConfig != nil && setupConfig.tenantStatus != "" {
			tenantStatus = setupConfig.tenantStatus
		}
		require.NoError(t, tenants.Add(ctx, tenantID, "tenant-1", providerID, tenantStatus))
		// The bucket the happy-path request addresses (GET /bucket/object-key), a
		// second bucket of the same tenant (copy destination), and another tenant's.
		require.NoError(t, buckets.Add(ctx, bucketID, tenantID, "bucket"))
		require.NoError(t, buckets.Add(ctx, bucket2ID, tenantID, "bucket2"))
		otherTenant := testutil.RandomDID(t)
		require.NoError(t, tenants.Add(ctx, otherTenant, "tenant-2", providerID, tenant.Active))
		require.NoError(t, buckets.Add(ctx, theirsID, otherTenant, "theirs"))
		var accessKeyExpires *time.Time
		var accessKeyBuckets []did.DID
		permissions := []string{"s3:GetObject"}
		if setupConfig != nil {
			accessKeyExpires = setupConfig.accessKeyExpires
			accessKeyBuckets = setupConfig.accessKeyBuckets
			if setupConfig.accessKeyPermissions != nil {
				permissions = setupConfig.accessKeyPermissions
			}
		}
		require.NoError(t, accessKeys.Add(ctx, accessKey.DID(), tenantID, "k1", accessKeyBuckets, permissions, accessKeyExpires))
		require.NoError(t, secrets.Write(ctx, vault.AccessKeyPath(tenantID, accessKey.DID()), accessKey.Bytes()))
		return auth.NewAuthorizer(zap.NewNop(), accessKeys, tenants, providers, buckets, secrets), providers, tenantID
	}

	t.Run("authorizes a validly-signed request", func(t *testing.T) {
		az, _, tenantID := setup(t, accessKey, nil)
		authz, err := az.Authorize(ctx, providerID, signedRequest(t, accessKey, region, time.Now(), time.Hour))
		require.NoError(t, err)
		require.Equal(t, accessKey.DID(), authz.AccessKey.ID)
		require.Equal(t, tenantID, authz.Tenant.ID)
		require.Equal(t, region, authz.Region)
		require.Equal(t, auth.OpGetObject, authz.Operation) // GET /bucket/object-key
		require.NotNil(t, authz.Bucket)
		require.Equal(t, "bucket", authz.Bucket.Name)
		require.NotNil(t, authz.Signed)
	})

	t.Run("rejects a bucket the access key is not scoped to", func(t *testing.T) {
		// The key is scoped to some other bucket, so it may not use "bucket".
		az, _, _ := setup(t, accessKey, &setupConfig{accessKeyBuckets: []did.DID{testutil.RandomDID(t)}})
		_, err := az.Authorize(ctx, providerID, signedObjectRequest(t, accessKey, "bucket", region))
		require.ErrorIs(t, err, auth.ErrBucketNotPermitted)
	})

	t.Run("rejects an unknown bucket", func(t *testing.T) {
		// The key may use any bucket (nil scope), but "nope" does not exist.
		az, _, _ := setup(t, accessKey, nil)
		_, err := az.Authorize(ctx, providerID, signedObjectRequest(t, accessKey, "nope", region))
		require.ErrorIs(t, err, auth.ErrUnknownBucket)
	})

	t.Run("rejects another tenant's bucket distinctly from an unknown one", func(t *testing.T) {
		az, _, _ := setup(t, accessKey, nil)
		_, err := az.Authorize(ctx, providerID, signedObjectRequest(t, accessKey, "theirs", region))
		require.ErrorIs(t, err, auth.ErrForeignBucket)
		require.NotErrorIs(t, err, auth.ErrUnknownBucket)
	})

	copyPerms := &setupConfig{accessKeyPermissions: []string{"s3:GetObject", "s3:PutObject"}}

	t.Run("authorizes a copy whose signed source is the tenant's", func(t *testing.T) {
		az, _, _ := setup(t, accessKey, copyPerms)
		authz, err := az.Authorize(ctx, providerID, signedCopyRequest(t, accessKey, "bucket2", "bucket", region, true))
		require.NoError(t, err)
		require.Equal(t, auth.OpCopyObject, authz.Operation)
		require.Equal(t, "bucket2", authz.Bucket.Name)
		require.Equal(t, "bucket", authz.SourceBucketName)
		require.NotNil(t, authz.SourceBucket)
		require.Equal(t, bucketID, authz.SourceBucket.ID)
	})

	t.Run("a copy within one bucket resolves the source once", func(t *testing.T) {
		az, _, _ := setup(t, accessKey, copyPerms)
		authz, err := az.Authorize(ctx, providerID, signedCopyRequest(t, accessKey, "bucket", "bucket", region, true))
		require.NoError(t, err)
		require.Same(t, authz.Bucket, authz.SourceBucket)
	})

	t.Run("rejects a copy whose source header is not signed", func(t *testing.T) {
		az, _, _ := setup(t, accessKey, copyPerms)
		_, err := az.Authorize(ctx, providerID, signedCopyRequest(t, accessKey, "bucket2", "bucket", region, false))
		require.ErrorIs(t, err, auth.ErrUnsignedCopySource)
	})

	t.Run("rejects a copy from another tenant's bucket", func(t *testing.T) {
		az, _, _ := setup(t, accessKey, copyPerms)
		_, err := az.Authorize(ctx, providerID, signedCopyRequest(t, accessKey, "bucket2", "theirs", region, true))
		require.ErrorIs(t, err, auth.ErrForeignBucket)
	})

	t.Run("rejects a copy from a missing bucket", func(t *testing.T) {
		az, _, _ := setup(t, accessKey, copyPerms)
		_, err := az.Authorize(ctx, providerID, signedCopyRequest(t, accessKey, "bucket2", "nope", region, true))
		require.ErrorIs(t, err, auth.ErrUnknownBucket)
	})

	t.Run("rejects a copy from a bucket outside the key's scope", func(t *testing.T) {
		// The key may write bucket2 but is not scoped to bucket, the source.
		az, _, _ := setup(t, accessKey, &setupConfig{
			accessKeyPermissions: []string{"s3:GetObject", "s3:PutObject"},
			accessKeyBuckets:     []did.DID{bucket2ID},
		})
		_, err := az.Authorize(ctx, providerID, signedCopyRequest(t, accessKey, "bucket2", "bucket", region, true))
		require.ErrorIs(t, err, auth.ErrBucketNotPermitted)
	})

	t.Run("rejects a copy by a key without the source read permission", func(t *testing.T) {
		az, _, _ := setup(t, accessKey, &setupConfig{accessKeyPermissions: []string{"s3:PutObject"}})
		_, err := az.Authorize(ctx, providerID, signedCopyRequest(t, accessKey, "bucket2", "bucket", region, true))
		require.ErrorIs(t, err, auth.ErrOperationNotPermitted)
	})

	t.Run("rejects an operation the access key lacks permission for", func(t *testing.T) {
		// The key holds only s3:GetObject, but a ListBuckets-shaped request (GET
		// with no bucket in the path) requires s3:ListAllMyBuckets.
		az, _, _ := setup(t, accessKey, nil)
		secret, err := multibase.Encode(multibase.Base64url, accessKey.Bytes())
		require.NoError(t, err)
		req := sigv4.Request{Method: "GET", URL: "https://s3.fil.one/"}
		signed, err := sigv4.Presign(req, accessKey.KeyDID().Identifier(), secret, region, sigv4.SchemeV4, time.Now(), time.Hour)
		require.NoError(t, err)
		_, err = az.Authorize(ctx, providerID, s3.Request{Method: signed.Method, URL: signed.URL})
		require.ErrorIs(t, err, auth.ErrOperationNotPermitted)
	})

	t.Run("rejects an invalid signature", func(t *testing.T) {
		// The access key record exists, but the vault holds a different secret than
		// the one that signed the request, so the recomputed signature won't match.
		other, err := ed25519.GenerateIssuer()
		require.NoError(t, err)
		accessKeys, tenants := accesskeymemory.New(), tenantmemory.New()
		providers, secrets := providermemory.New(), vaultmemory.New()
		require.NoError(t, providers.Add(ctx, providerID, region, nil))
		tenantID := testutil.RandomDID(t)
		require.NoError(t, tenants.Add(ctx, tenantID, "tenant-1", providerID, tenant.Active))
		require.NoError(t, accessKeys.Add(ctx, accessKey.DID(), tenantID, "k1", nil, []string{"s3:GetObject"}, nil))
		require.NoError(t, secrets.Write(ctx, vault.AccessKeyPath(tenantID, accessKey.DID()), other.Bytes()))
		az := auth.NewAuthorizer(zap.NewNop(), accessKeys, tenants, providers, bucketmemory.New(), secrets)

		_, err = az.Authorize(ctx, providerID, signedRequest(t, accessKey, region, time.Now(), time.Hour))
		require.ErrorIs(t, err, auth.ErrSignatureMismatch)
	})

	t.Run("rejects an unsigned request", func(t *testing.T) {
		az, _, _ := setup(t, accessKey, nil)
		_, err := az.Authorize(ctx, providerID, s3.Request{Method: "GET", URL: "https://s3.fil.one/bucket/object-key"})
		require.ErrorIs(t, err, auth.ErrMalformedSignature)
	})

	t.Run("rejects an unknown access key", func(t *testing.T) {
		az := auth.NewAuthorizer(zap.NewNop(), accesskeymemory.New(), tenantmemory.New(), providermemory.New(), bucketmemory.New(), vaultmemory.New())
		_, err := az.Authorize(ctx, providerID, signedRequest(t, accessKey, region, time.Now(), time.Hour))
		require.ErrorIs(t, err, auth.ErrUnknownAccessKey)
	})

	t.Run("rejects when the access key secret is missing from the vault", func(t *testing.T) {
		// The access key record exists but its private key was never written to the
		// vault — a store/vault inconsistency the signer load must reject.
		accessKeys, tenants := accesskeymemory.New(), tenantmemory.New()
		providers, secrets := providermemory.New(), vaultmemory.New()
		require.NoError(t, providers.Add(ctx, providerID, region, nil))
		tenantID := testutil.RandomDID(t)
		require.NoError(t, tenants.Add(ctx, tenantID, "tenant-1", providerID, tenant.Active))
		require.NoError(t, accessKeys.Add(ctx, accessKey.DID(), tenantID, "k1", nil, []string{"s3:GetObject"}, nil))
		az := auth.NewAuthorizer(zap.NewNop(), accessKeys, tenants, providers, bucketmemory.New(), secrets)

		_, err := az.Authorize(ctx, providerID, signedRequest(t, accessKey, region, time.Now(), time.Hour))
		require.Error(t, err)
	})

	t.Run("rejects a region the tenant's provider does not serve", func(t *testing.T) {
		az, providers, _ := setup(t, accessKey, nil)
		// A provider exists in eu-west-1, but it isn't the tenant's provider.
		require.NoError(t, providers.Add(ctx, testutil.RandomDID(t), "eu-west-1", nil))
		_, err := az.Authorize(ctx, providerID, signedRequest(t, accessKey, "eu-west-1", time.Now(), time.Hour))
		require.ErrorIs(t, err, auth.ErrRegionNotServed)
	})

	t.Run("rejects a region no provider serves", func(t *testing.T) {
		az, _, _ := setup(t, accessKey, nil)
		// No provider is registered for eu-west-1, so validateRegion skips it.
		_, err := az.Authorize(ctx, providerID, signedRequest(t, accessKey, "eu-west-1", time.Now(), time.Hour))
		require.ErrorIs(t, err, auth.ErrRegionNotServed)
	})

	t.Run("rejects an expired presigned URL", func(t *testing.T) {
		az, _, _ := setup(t, accessKey, nil)
		// Validly signed, but two hours ago with only a one-hour window.
		_, err := az.Authorize(ctx, providerID, signedRequest(t, accessKey, region, time.Now().Add(-2*time.Hour), time.Hour))
		require.ErrorIs(t, err, auth.ErrSignatureExpired)
	})

	t.Run("rejects an invocation not from the tenant's provider", func(t *testing.T) {
		az, _, _ := setup(t, accessKey, nil)
		_, err := az.Authorize(ctx, testutil.RandomDID(t), signedRequest(t, accessKey, region, time.Now(), time.Hour))
		require.ErrorIs(t, err, auth.ErrIssuerForbidden)
	})

	t.Run("rejects an expired access key", func(t *testing.T) {
		// A freshly-signed request from the tenant's provider must still be rejected
		// when the access key itself has expired (so expiry is the only variable).
		past := time.Now().Add(-time.Hour)
		az, _, _ := setup(t, accessKey, &setupConfig{accessKeyExpires: &past})
		_, err := az.Authorize(ctx, providerID, signedRequest(t, accessKey, region, time.Now(), time.Hour))
		require.ErrorIs(t, err, auth.ErrAccessKeyExpired)
	})

	t.Run("rejects a disabled tenant", func(t *testing.T) {
		// A freshly-signed request from the tenant's provider must be rejected when
		// the tenant is disabled (so disabled status is the only variable).
		az, _, _ := setup(t, accessKey, &setupConfig{tenantStatus: tenant.Disabled})
		_, err := az.Authorize(ctx, providerID, signedRequest(t, accessKey, region, time.Now(), time.Hour))
		require.ErrorIs(t, err, auth.ErrTenantDisabled)
	})
}

func TestTenantIssuer(t *testing.T) {
	ctx := t.Context()
	buckets, secrets := bucketmemory.New(), vaultmemory.New()
	az := auth.NewAuthorizer(zap.NewNop(), accesskeymemory.New(), tenantmemory.New(), providermemory.New(), buckets, secrets)

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
