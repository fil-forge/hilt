package auth_test

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"
	"time"

	s3bkt "github.com/fil-forge/libforge/commands/s3/bucket"
	"github.com/jackc/pgx/v5/pgxpool"

	htestutil "github.com/fil-forge/hilt/internal/testutil"
	"github.com/fil-forge/hilt/pkg/rpc/service/auth"
	"github.com/fil-forge/hilt/pkg/sigv4"
	"github.com/fil-forge/hilt/pkg/store/accesskey"
	accesskeypostgres "github.com/fil-forge/hilt/pkg/store/accesskey/postgres"
	bucketpostgres "github.com/fil-forge/hilt/pkg/store/bucket/postgres"
	bucketpolicypostgres "github.com/fil-forge/hilt/pkg/store/bucketpolicy/postgres"
	delegationpostgres "github.com/fil-forge/hilt/pkg/store/delegation/postgres"
	"github.com/fil-forge/hilt/pkg/store/pglock"
	principalpostgres "github.com/fil-forge/hilt/pkg/store/principal/postgres"
	providerpostgres "github.com/fil-forge/hilt/pkg/store/provider/postgres"
	"github.com/fil-forge/hilt/pkg/store/tenant"
	tenantpostgres "github.com/fil-forge/hilt/pkg/store/tenant/postgres"
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
	// accessKeyBuckets scopes a service key to these buckets; empty is
	// tenant-wide.
	accessKeyBuckets []did.DID
	// accessKeyPermissions is a service key's own permission set. Empty means
	// s3:GetObject alone, which the happy-path request needs.
	accessKeyPermissions []string
	// principalBound seeds the credential as a principal-bound access key
	// instead of a service key.
	principalBound bool
	tenantStatus   tenant.Status
}

// signedCopyRequest presigns a CopyObject: PUT of object-key in dstBucket with an
// x-amz-copy-source naming srcBucket/object-key. The header is covered by the
// signature only when signSource is set.
func signedCopyRequest(t *testing.T, signer multikey.Signer, dstBucket, srcBucket, region string, signSource bool) s3.Request {
	t.Helper()
	return signedCopySourceRequest(t, signer, dstBucket, "/"+srcBucket+"/object-key", region, signSource)
}

// signedCopySourceRequest is signedCopyRequest with the x-amz-copy-source
// value given whole, so a test can name a source version.
func signedCopySourceRequest(t *testing.T, signer multikey.Signer, dstBucket, source, region string, signSource bool) s3.Request {
	t.Helper()
	var signed []string
	if signSource {
		signed = []string{"x-amz-copy-source"}
	}
	return signedRequestWith(t, signer, "PUT", "https://s3.fil.one/"+dstBucket+"/object-key", map[string]string{"x-amz-copy-source": source}, region, signed...)
}

// signedBodyRequest presigns a request carrying body, covered by the payload
// hash when bind is set and left unsigned otherwise.
func signedBodyRequest(t *testing.T, signer multikey.Signer, method, url, body, region string, bind bool) s3.Request {
	t.Helper()
	secret, err := multibase.Encode(multibase.Base64url, signer.Bytes())
	require.NoError(t, err)
	var opts []sigv4.PresignOption
	if bind {
		sum := sha256.Sum256([]byte(body))
		opts = append(opts, sigv4.WithPayloadHash(hex.EncodeToString(sum[:])))
	}
	presigned, err := sigv4.Presign(sigv4.Request{Method: method, URL: url}, signer.KeyDID().Identifier(), secret, region, sigv4.SchemeV4, time.Now(), time.Hour, opts...)
	require.NoError(t, err)
	return s3.Request{Method: presigned.Method, URL: presigned.URL, Body: []byte(body)}
}

// signedRequestWith presigns a request carrying the given headers, of which
// those named in signed are covered by the signature.
func signedRequestWith(t *testing.T, signer multikey.Signer, method, url string, headers map[string]string, region string, signed ...string) s3.Request {
	t.Helper()
	secret, err := multibase.Encode(multibase.Base64url, signer.Bytes())
	require.NoError(t, err)
	req := sigv4.Request{Method: method, URL: url, Headers: headers}
	var opts []sigv4.PresignOption
	if len(signed) > 0 {
		opts = append(opts, sigv4.WithSignedHeaders(signed...))
	}
	presigned, err := sigv4.Presign(req, signer.KeyDID().Identifier(), secret, region, sigv4.SchemeV4, time.Now(), time.Hour, opts...)
	require.NoError(t, err)
	return s3.Request{Method: presigned.Method, URL: presigned.URL, Headers: headers}
}

// seedKey stores the credential's record and vault entry: a service key with
// its own permissions and buckets unless principalBound, in which case a key
// bound to "user-1", which holds neither.
func seedKey(t *testing.T, accessKeys *accesskeypostgres.Store, secrets *vaultmemory.Store, delegations *delegationpostgres.Store, key multikey.Issuer, tenantID did.DID, cfg *setupConfig) {
	t.Helper()
	ctx := t.Context()
	var expires *time.Time
	var permissions []string
	var bucketIDs []did.DID
	principalBound := false
	if cfg != nil {
		expires, bucketIDs, permissions, principalBound = cfg.accessKeyExpires, cfg.accessKeyBuckets, cfg.accessKeyPermissions, cfg.principalBound
	}
	if len(permissions) == 0 {
		permissions = []string{"s3:GetObject"}
	}
	in := accesskey.Input{ID: key.DID(), Tenant: tenantID, Name: "k1", Buckets: bucketIDs, Permissions: permissions, ExpiresAt: expires}
	if principalBound {
		principal := "user-1"
		in = accesskey.Input{ID: key.DID(), Tenant: tenantID, Name: "k1", Principal: &principal, ExpiresAt: expires}
	}
	require.NoError(t, accessKeys.Add(ctx, in))
	require.NoError(t, secrets.Write(ctx, vault.AccessKeyPath(tenantID, key.DID()), key.Bytes()))
}

// signedObjectRequest presigns a GET of an object in the named bucket.
func signedObjectRequest(t *testing.T, signer multikey.Signer, bucketName, region string) s3.Request {
	t.Helper()
	return signedObjectQueryRequest(t, signer, bucketName, "", region)
}

// signedObjectQueryRequest presigns a GET of an object in the named bucket
// with the given query, such as "attributes".
func signedObjectQueryRequest(t *testing.T, signer multikey.Signer, bucketName, query, region string) s3.Request {
	t.Helper()
	secret, err := multibase.Encode(multibase.Base64url, signer.Bytes())
	require.NoError(t, err)
	url := "https://s3.fil.one/" + bucketName + "/object-key"
	if query != "" {
		url += "?" + query
	}
	req := sigv4.Request{Method: "GET", URL: url}
	signed, err := sigv4.Presign(req, signer.KeyDID().Identifier(), secret, region, sigv4.SchemeV4, time.Now(), time.Hour)
	require.NoError(t, err)
	return s3.Request{Method: signed.Method, URL: signed.URL}
}

func TestAuthorize(t *testing.T) {
	ctx := t.Context()
	// providerID serves region; provider2ID serves region2. A tenant is
	// region-free, so this one owns buckets in both.
	const region, region2 = "us-west-2", "eu-west-1"

	accessKey, err := ed25519.GenerateIssuer()
	require.NoError(t, err)

	providerID, provider2ID := testutil.RandomDID(t), testutil.RandomDID(t)
	// The tenant's two buckets in region, one in region2, and a bucket of some
	// other tenant.
	bucketID, bucket2ID, region2BucketID := testutil.RandomDID(t), testutil.RandomDID(t), testutil.RandomDID(t)
	theirsID := testutil.RandomDID(t)

	// setup wires the stores + vault for the fixture every subtest shares:
	//
	//	providerID  serves region  and holds "bucket" (bucketID) and "bucket2"
	//	                           (bucket2ID), plus another tenant's "theirs"
	//	provider2ID serves region2 and holds "remote" (remoteID)
	//
	// One tenant owns this access key and all three of its buckets. A tenant is
	// region-free, so its buckets may live with either provider. The key may use
	// any of them unless setupConfig scopes it. setupWithPolicies also hands back
	// the bucket DID and the policy store, so a subtest can grant the principal
	// actions on the bucket the request addresses.
	setupWithPolicies := func(t *testing.T, accessKey multikey.Issuer, setupConfig *setupConfig) (*auth.Authorizer, *providerpostgres.Store, did.DID, did.DID, *pgxpool.Pool) {
		t.Helper()
		pool := htestutil.PostgresOrSkip(t)
		accessKeys, tenants := accesskeypostgres.New(pool), tenantpostgres.New(pool)
		providers, buckets, secrets := providerpostgres.New(pool), bucketpostgres.New(pool), vaultmemory.New()
		principals, policies := principalpostgres.New(pool), bucketpolicypostgres.New(pool)
		dels := delegationpostgres.New(pool)
		require.NoError(t, providers.Add(ctx, providerID, region, nil))
		require.NoError(t, providers.Add(ctx, provider2ID, region2, nil))
		tenantID := testutil.RandomDID(t)
		require.NoError(t, tenants.Add(ctx, tenantID, "tenant-1", tenant.Active))
		// The bucket the happy-path request addresses (GET /bucket/object-key), a
		// second bucket of the same tenant (copy destination), and another tenant's.
		require.NoError(t, buckets.Add(ctx, bucketID, tenantID, providerID, "bucket"))
		require.NoError(t, buckets.Add(ctx, bucket2ID, tenantID, providerID, "bucket2"))
		require.NoError(t, buckets.Add(ctx, region2BucketID, tenantID, provider2ID, "bucket-in-region2"))
		otherTenant := testutil.RandomDID(t)
		require.NoError(t, tenants.Add(ctx, otherTenant, "tenant-2", tenant.Active))
		require.NoError(t, buckets.Add(ctx, theirsID, otherTenant, providerID, "theirs"))
		if setupConfig != nil && setupConfig.principalBound {
			require.NoError(t, principals.Add(ctx, tenantID, "user-1"))
		}
		seedKey(t, accessKeys, secrets, dels, accessKey, tenantID, setupConfig)
		// The status is set once the key exists: a disabled tenant takes no new key.
		if setupConfig != nil && setupConfig.tenantStatus != "" {
			require.NoError(t, tenants.SetStatus(ctx, tenantID, setupConfig.tenantStatus))
		}
		return auth.NewAuthorizer(zap.NewNop(), accessKeys, tenants, providers, buckets, principals, policies, secrets, auth.WithSnapshots(pglock.NewSnapshots(pool))),
			providers, tenantID, bucketID, pool
	}

	setup := func(t *testing.T, accessKey multikey.Issuer, setupConfig *setupConfig) (*auth.Authorizer, *providerpostgres.Store, did.DID) {
		az, providers, tenantID, _, _ := setupWithPolicies(t, accessKey, setupConfig)
		return az, providers, tenantID
	}

	// grant stores a policy on the bucket. statements are applied as given.
	grant := func(t *testing.T, pool *pgxpool.Pool, bucketID, tenantID did.DID, statements ...s3bkt.Statement) {
		t.Helper()
		htestutil.PutPolicy(t, pool, tenantID, bucketID, s3bkt.PolicyDocument{Version: s3bkt.Version2012, Statements: statements})
	}

	t.Run("authorizes a validly-signed request", func(t *testing.T) {
		az, _, tenantID := setup(t, accessKey, nil)
		authz, err := az.Authorize(ctx, providerID, signedRequest(t, accessKey, region, time.Now(), time.Hour))
		require.NoError(t, err)
		require.Equal(t, accessKey.DID(), authz.AccessKey.ID)
		require.Equal(t, tenantID, authz.Tenant.ID)
		require.Equal(t, providerID, authz.Provider.ID)
		require.Equal(t, region, authz.Region)
		require.Equal(t, auth.OpGetObject, authz.Operation) // GET /bucket/object-key
		require.NotNil(t, authz.Bucket)
		require.Equal(t, "bucket", authz.Bucket.Name)
		require.NotNil(t, authz.Signed)
		// A service key holds its own permission set.
		require.Equal(t, []string{"s3:GetObject"}, authz.Permissions)
	})

	t.Run("refuses a request naming two subresources", func(t *testing.T) {
		// Refused by name, before any permission is consulted, as S3 refuses it.
		az, _, _ := setup(t, accessKey, nil)
		secret, err := multibase.Encode(multibase.Base64url, accessKey.Bytes())
		require.NoError(t, err)
		signed, err := sigv4.Presign(sigv4.Request{Method: "GET", URL: "https://s3.fil.one/bucket?uploads&encryption"},
			accessKey.DID().Identifier(), secret, region, sigv4.SchemeV4, time.Now(), time.Hour)
		require.NoError(t, err)
		_, err = az.Authorize(ctx, providerID, s3.Request{Method: signed.Method, URL: signed.URL})
		require.ErrorIs(t, err, auth.ErrConflictingQuery)
		require.ErrorContains(t, err, "encryption, uploads")
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

	t.Run("authorizes a bucket in a second region through that region's provider", func(t *testing.T) {
		// Same tenant, same access key: setup gave "bucket-in-region2" to
		// provider2ID, and the request is signed for region2 and invoked by
		// provider2ID.
		az, _, tenantID := setup(t, accessKey, nil)
		authz, err := az.Authorize(ctx, provider2ID, signedObjectRequest(t, accessKey, "bucket-in-region2", region2))
		require.NoError(t, err)
		require.Equal(t, tenantID, authz.Tenant.ID)
		require.Equal(t, provider2ID, authz.Provider.ID)
		require.Equal(t, region2, authz.Region)
		require.Equal(t, region2BucketID, authz.Bucket.ID)
	})

	t.Run("rejects a bucket served by another region", func(t *testing.T) {
		// "bucket-in-region2" is the tenant's, but setup gave it to provider2ID in
		// region2; this request is signed for region and reaches providerID, which
		// does not hold the bucket.
		az, _, _ := setup(t, accessKey, nil)
		_, err := az.Authorize(ctx, providerID, signedObjectRequest(t, accessKey, "bucket-in-region2", region))
		var mismatch *auth.BucketRegionMismatchError
		require.ErrorAs(t, err, &mismatch)
		require.Equal(t, region2, mismatch.Expected)
		require.Equal(t, region, mismatch.Actual)
	})

	t.Run("checks the key's bucket scope before the bucket's region", func(t *testing.T) {
		// The key is scoped to bucketID ("bucket", in region) alone, so addressing
		// the tenant's other bucket is refused for scope: the caller learns nothing
		// about the region that bucket lives in.
		az, _, _ := setup(t, accessKey, &setupConfig{accessKeyBuckets: []did.DID{bucketID}})
		_, err := az.Authorize(ctx, providerID, signedObjectRequest(t, accessKey, "bucket-in-region2", region))
		require.ErrorIs(t, err, auth.ErrBucketNotPermitted)
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

	t.Run("rejects a copy whose source header appears under two spellings", func(t *testing.T) {
		// Signed as one spelling, sent with a second: which value the signature
		// covers is ambiguous, so the request is malformed before any source is
		// classified.
		az, _, _ := setup(t, accessKey, copyPerms)
		req := signedCopyRequest(t, accessKey, "bucket2", "bucket", region, true)
		req.Headers["X-Amz-Copy-Source"] = "/theirs/object-key"
		_, err := az.Authorize(ctx, providerID, req)
		require.ErrorIs(t, err, auth.ErrMalformedSignature)
	})

	t.Run("rejects a copy whose source header is not signed", func(t *testing.T) {
		az, _, _ := setup(t, accessKey, copyPerms)
		_, err := az.Authorize(ctx, providerID, signedCopyRequest(t, accessKey, "bucket2", "bucket", region, false))
		require.ErrorIs(t, err, auth.ErrUnsignedHeader)
	})

	t.Run("rejects a copy from another tenant's bucket", func(t *testing.T) {
		az, _, _ := setup(t, accessKey, copyPerms)
		_, err := az.Authorize(ctx, providerID, signedCopyRequest(t, accessKey, "bucket2", "theirs", region, true))
		require.ErrorIs(t, err, auth.ErrForeignBucket)
	})

	t.Run("rejects a copy whose source is served by another region", func(t *testing.T) {
		// The destination "bucket2" is providerID's, the source is provider2ID's.
		az, _, _ := setup(t, accessKey, copyPerms)
		_, err := az.Authorize(ctx, providerID, signedCopyRequest(t, accessKey, "bucket2", "bucket-in-region2", region, true))
		var mismatch *auth.BucketRegionMismatchError
		require.ErrorAs(t, err, &mismatch)
		require.Equal(t, region2, mismatch.Expected)
		require.Equal(t, region, mismatch.Actual)
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

	t.Run("a copy of a source version needs the version read", func(t *testing.T) {
		// S3 reads a source naming a versionId under s3:GetObjectVersion, so
		// the object read alone does not reach it.
		az, _, _ := setup(t, accessKey, copyPerms)
		authz, err := az.Authorize(ctx, providerID, signedCopyRequest(t, accessKey, "bucket2", "bucket", region, true))
		require.NoError(t, err)
		require.Equal(t, auth.SourcePermission, authz.SourcePermission)

		_, err = az.Authorize(ctx, providerID, signedCopySourceRequest(t, accessKey, "bucket2", "/bucket/object-key?versionId=v1", region, true))
		require.ErrorIs(t, err, auth.ErrOperationNotPermitted)

		az, _, _ = setup(t, accessKey, &setupConfig{accessKeyPermissions: []string{"s3:GetObjectVersion", "s3:PutObject"}})
		authz, err = az.Authorize(ctx, providerID, signedCopySourceRequest(t, accessKey, "bucket2", "/bucket/object-key?versionId=v1", region, true))
		require.NoError(t, err)
		require.Equal(t, auth.OpCopyObject, authz.Operation)
		require.Equal(t, auth.SourceVersionPermission, authz.SourcePermission)
		require.Equal(t, bucketID, authz.SourceBucket.ID)
	})

	t.Run("a header that adds a permission is checked with the write", func(t *testing.T) {
		// S3 needs s3:PutObjectRetention beside s3:PutObject to set a
		// retention period on the version a put creates, and the gateway
		// stamps it from the header, so the header is priced here.
		const objectURL = "https://s3.fil.one/bucket/object-key"
		lock := map[string]string{"x-amz-object-lock-mode": "GOVERNANCE"}

		az, _, _ := setup(t, accessKey, &setupConfig{accessKeyPermissions: []string{"s3:PutObject"}})
		_, err := az.Authorize(ctx, providerID, signedRequestWith(t, accessKey, "PUT", objectURL, lock, region, "x-amz-object-lock-mode"))
		require.ErrorIs(t, err, auth.ErrOperationNotPermitted)

		az, _, _ = setup(t, accessKey, &setupConfig{accessKeyPermissions: []string{"s3:PutObject", "s3:PutObjectRetention"}})
		authz, err := az.Authorize(ctx, providerID, signedRequestWith(t, accessKey, "PUT", objectURL, lock, region, "x-amz-object-lock-mode"))
		require.NoError(t, err)
		require.Equal(t, auth.OpPutObject, authz.Operation)
		require.Equal(t, bucketID, authz.Bucket.ID)

		// The header is trusted only when the signature covers it.
		_, err = az.Authorize(ctx, providerID, signedRequestWith(t, accessKey, "PUT", objectURL, lock, region))
		require.ErrorIs(t, err, auth.ErrUnsignedHeader)
		require.ErrorContains(t, err, "x-amz-object-lock-mode")

		// A copy replacing the tags needs the tagging write on the destination
		// beside the put and the source read.
		replace := map[string]string{"x-amz-copy-source": "/bucket/object-key", "x-amz-tagging-directive": "REPLACE"}
		az, _, _ = setup(t, accessKey, copyPerms)
		_, err = az.Authorize(ctx, providerID, signedRequestWith(t, accessKey, "PUT", "https://s3.fil.one/bucket2/object-key", replace, region, "x-amz-copy-source", "x-amz-tagging-directive"))
		require.ErrorIs(t, err, auth.ErrOperationNotPermitted)

		az, _, _ = setup(t, accessKey, &setupConfig{accessKeyPermissions: []string{"s3:GetObject", "s3:PutObject", "s3:PutObjectTagging"}})
		authz, err = az.Authorize(ctx, providerID, signedRequestWith(t, accessKey, "PUT", "https://s3.fil.one/bucket2/object-key", replace, region, "x-amz-copy-source", "x-amz-tagging-directive"))
		require.NoError(t, err)
		require.Equal(t, auth.OpCopyObject, authz.Operation)

		// With the source signed and the directive not, the copy is refused on
		// the directive.
		_, err = az.Authorize(ctx, providerID, signedRequestWith(t, accessKey, "PUT", "https://s3.fil.one/bucket2/object-key", replace, region, "x-amz-copy-source"))
		require.ErrorIs(t, err, auth.ErrUnsignedHeader)
		require.ErrorContains(t, err, "x-amz-tagging-directive")

		// A repeated directive reaches hilt comma-joined and the gateway acts
		// on its first value, so the first value decides here too.
		repeated := map[string]string{"x-amz-copy-source": "/bucket/object-key", "x-amz-tagging-directive": "REPLACE,COPY"}
		az, _, _ = setup(t, accessKey, copyPerms)
		_, err = az.Authorize(ctx, providerID, signedRequestWith(t, accessKey, "PUT", "https://s3.fil.one/bucket2/object-key", repeated, region, "x-amz-copy-source", "x-amz-tagging-directive"))
		require.ErrorIs(t, err, auth.ErrOperationNotPermitted)
		az, _, _ = setup(t, accessKey, &setupConfig{accessKeyPermissions: []string{"s3:GetObject", "s3:PutObject", "s3:PutObjectTagging"}})

		// The replacement tags are written from the tagging header, so a
		// signed directive does not cover unsigned tags.
		withTags := map[string]string{"x-amz-copy-source": "/bucket/object-key", "x-amz-tagging-directive": "REPLACE", "x-amz-tagging": "k=v"}
		_, err = az.Authorize(ctx, providerID, signedRequestWith(t, accessKey, "PUT", "https://s3.fil.one/bucket2/object-key", withTags, region, "x-amz-copy-source", "x-amz-tagging-directive"))
		require.ErrorIs(t, err, auth.ErrUnsignedHeader)
		require.ErrorContains(t, err, "x-amz-tagging")
		authz, err = az.Authorize(ctx, providerID, signedRequestWith(t, accessKey, "PUT", "https://s3.fil.one/bucket2/object-key", withTags, region, "x-amz-copy-source", "x-amz-tagging-directive", "x-amz-tagging"))
		require.NoError(t, err)
		require.Equal(t, auth.OpCopyObject, authz.Operation)
	})

	t.Run("creating a bucket with Object Lock needs the configuration permissions", func(t *testing.T) {
		// The bucket is born versioned and locked, which S3 prices as
		// s3:PutBucketVersioning and s3:PutBucketObjectLockConfiguration
		// beside s3:CreateBucket.
		const bucketURL = "https://s3.fil.one/newbucket"
		locked := map[string]string{"x-amz-bucket-object-lock-enabled": "true"}

		az, _, _ := setup(t, accessKey, &setupConfig{accessKeyPermissions: []string{"s3:CreateBucket"}})
		authz, err := az.Authorize(ctx, providerID, signedRequestWith(t, accessKey, "PUT", bucketURL, nil, region))
		require.NoError(t, err)
		require.Equal(t, auth.OpCreateBucket, authz.Operation)

		_, err = az.Authorize(ctx, providerID, signedRequestWith(t, accessKey, "PUT", bucketURL, locked, region, "x-amz-bucket-object-lock-enabled"))
		require.ErrorIs(t, err, auth.ErrOperationNotPermitted)

		az, _, _ = setup(t, accessKey, &setupConfig{accessKeyPermissions: []string{"s3:CreateBucket", "s3:PutBucketVersioning"}})
		_, err = az.Authorize(ctx, providerID, signedRequestWith(t, accessKey, "PUT", bucketURL, locked, region, "x-amz-bucket-object-lock-enabled"))
		require.ErrorIs(t, err, auth.ErrOperationNotPermitted)

		// A repeated flag is comma-joined and the gateway acts on its first
		// value: "true,false" creates a locked bucket.
		az, _, _ = setup(t, accessKey, &setupConfig{accessKeyPermissions: []string{"s3:CreateBucket"}})
		_, err = az.Authorize(ctx, providerID, signedRequestWith(t, accessKey, "PUT", bucketURL, map[string]string{"x-amz-bucket-object-lock-enabled": "true,false"}, region, "x-amz-bucket-object-lock-enabled"))
		require.ErrorIs(t, err, auth.ErrOperationNotPermitted)

		az, _, _ = setup(t, accessKey, &setupConfig{accessKeyPermissions: []string{"s3:CreateBucket", "s3:PutBucketVersioning", "s3:PutBucketObjectLockConfiguration"}})
		authz, err = az.Authorize(ctx, providerID, signedRequestWith(t, accessKey, "PUT", bucketURL, locked, region, "x-amz-bucket-object-lock-enabled"))
		require.NoError(t, err)
		require.Equal(t, auth.OpCreateBucket, authz.Operation)
		require.Nil(t, authz.Bucket)

		_, err = az.Authorize(ctx, providerID, signedRequestWith(t, accessKey, "PUT", bucketURL, locked, region))
		require.ErrorIs(t, err, auth.ErrUnsignedHeader)
	})

	t.Run("bypassing governance retention needs its permission", func(t *testing.T) {
		const objectURL = "https://s3.fil.one/bucket/object-key?versionId=v1"
		bypass := map[string]string{"x-amz-bypass-governance-retention": "true"}

		az, _, _ := setup(t, accessKey, &setupConfig{accessKeyPermissions: []string{"s3:DeleteObjectVersion"}})
		_, err := az.Authorize(ctx, providerID, signedRequestWith(t, accessKey, "DELETE", objectURL, bypass, region, "x-amz-bypass-governance-retention"))
		require.ErrorIs(t, err, auth.ErrOperationNotPermitted)

		az, _, _ = setup(t, accessKey, &setupConfig{accessKeyPermissions: []string{"s3:DeleteObjectVersion", "s3:BypassGovernanceRetention"}})
		authz, err := az.Authorize(ctx, providerID, signedRequestWith(t, accessKey, "DELETE", objectURL, bypass, region, "x-amz-bypass-governance-retention"))
		require.NoError(t, err)
		require.Equal(t, auth.OpDeleteObjectVersion, authz.Operation)

		_, err = az.Authorize(ctx, providerID, signedRequestWith(t, accessKey, "DELETE", objectURL, bypass, region))
		require.ErrorIs(t, err, auth.ErrUnsignedHeader)
	})

	t.Run("a request's requirements refuse an unsigned header as Authorize does", func(t *testing.T) {
		headers := map[string]string{"x-amz-object-lock-legal-hold": "ON", "x-amz-tagging": "k=v"}
		_, _, err := auth.RequirementsFor(signedRequestWith(t, accessKey, "PUT", "https://s3.fil.one/bucket/object-key", headers, region, "x-amz-tagging"))
		require.ErrorIs(t, err, auth.ErrUnsignedHeader)
		require.ErrorContains(t, err, "x-amz-object-lock-legal-hold")

		op, reqs, err := auth.RequirementsFor(signedRequestWith(t, accessKey, "PUT", "https://s3.fil.one/bucket/object-key", headers, region, "x-amz-tagging", "x-amz-object-lock-legal-hold"))
		require.NoError(t, err)
		require.Equal(t, auth.OpPutObject, op)
		require.Equal(t, []auth.Requirement{{Bucket: "bucket", Permission: "s3:PutObject"}, {Bucket: "bucket", Permission: "s3:PutObjectLegalHold"}, {Bucket: "bucket", Permission: "s3:PutObjectTagging"}}, reqs)
	})

	t.Run("a DeleteObjects naming a version needs the version permission", func(t *testing.T) {
		// S3 needs s3:DeleteObjectVersion for each entry that names a version;
		// hilt reads the body, bound by the payload hash, and needs it for the
		// whole request.
		const deleteURL = "https://s3.fil.one/bucket?delete"
		const versions = `<Delete><Object><Key>a</Key></Object><Object><Key>b</Key><VersionId>v1</VersionId></Object></Delete>`
		const plain = `<Delete><Object><Key>a</Key></Object></Delete>`

		az, _, _ := setup(t, accessKey, &setupConfig{accessKeyPermissions: []string{"s3:DeleteObject"}})
		authz, err := az.Authorize(ctx, providerID, signedBodyRequest(t, accessKey, "POST", deleteURL, plain, region, true))
		require.NoError(t, err)
		require.Equal(t, auth.OpDeleteObjects, authz.Operation)
		_, err = az.Authorize(ctx, providerID, signedBodyRequest(t, accessKey, "POST", deleteURL, versions, region, true))
		require.ErrorIs(t, err, auth.ErrOperationNotPermitted)

		az, _, _ = setup(t, accessKey, &setupConfig{accessKeyPermissions: []string{"s3:DeleteObject", "s3:DeleteObjectVersion"}})
		authz, err = az.Authorize(ctx, providerID, signedBodyRequest(t, accessKey, "POST", deleteURL, versions, region, true))
		require.NoError(t, err)
		require.Equal(t, auth.OpDeleteObjects, authz.Operation)
		require.Equal(t, bucketID, authz.Bucket.ID)

		// The body is trusted only when the signature binds it.
		_, err = az.Authorize(ctx, providerID, signedBodyRequest(t, accessKey, "POST", deleteURL, versions, region, false))
		require.ErrorIs(t, err, auth.ErrInvalidBody)
		req := signedBodyRequest(t, accessKey, "POST", deleteURL, plain, region, true)
		req.Body = []byte(versions)
		_, err = az.Authorize(ctx, providerID, req)
		require.ErrorIs(t, err, auth.ErrInvalidBody)
		req = signedBodyRequest(t, accessKey, "POST", deleteURL, "", region, true)
		_, err = az.Authorize(ctx, providerID, req)
		require.ErrorIs(t, err, auth.ErrInvalidBody)

		// A body on an operation hilt reads none for is refused too.
		req = signedObjectRequest(t, accessKey, "bucket", region)
		req.Body = []byte(plain)
		_, err = az.Authorize(ctx, providerID, req)
		require.ErrorIs(t, err, auth.ErrInvalidBody)

		// An unparseable or oversized body is refused by name through
		// Authorize as it is through RequirementsFor, never as an
		// unsupported operation.
		_, err = az.Authorize(ctx, providerID, signedBodyRequest(t, accessKey, "POST", deleteURL, "<Delete><Object>", region, true))
		require.ErrorIs(t, err, auth.ErrInvalidBody)
		require.NotErrorIs(t, err, auth.ErrUnsupportedOperation)
		huge := string(make([]byte, auth.MaxBodySize+1))
		_, err = az.Authorize(ctx, providerID, signedBodyRequest(t, accessKey, "POST", deleteURL, huge, region, true))
		require.ErrorIs(t, err, auth.ErrInvalidBody)
	})

	t.Run("an operation that copies nothing names no source permission", func(t *testing.T) {
		az, _, _ := setup(t, accessKey, nil)
		authz, err := az.Authorize(ctx, providerID, signedObjectRequest(t, accessKey, "bucket", region))
		require.NoError(t, err)
		require.Empty(t, authz.SourcePermission)
	})

	t.Run("an attributes read needs the object read too", func(t *testing.T) {
		// S3 requires s3:GetObject beside s3:GetObjectAttributes, so a key
		// holding the attributes permission alone reads nothing.
		az, _, _ := setup(t, accessKey, &setupConfig{accessKeyPermissions: []string{"s3:GetObjectAttributes"}})
		_, err := az.Authorize(ctx, providerID, signedObjectQueryRequest(t, accessKey, "bucket", "attributes", region))
		require.ErrorIs(t, err, auth.ErrOperationNotPermitted)

		az, _, _ = setup(t, accessKey, &setupConfig{accessKeyPermissions: []string{"s3:GetObjectAttributes", "s3:GetObject"}})
		authz, err := az.Authorize(ctx, providerID, signedObjectQueryRequest(t, accessKey, "bucket", "attributes", region))
		require.NoError(t, err)
		require.Equal(t, auth.OpGetObjectAttributes, authz.Operation)
		require.Equal(t, bucketID, authz.Bucket.ID)
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

	t.Run("a principal-bound key holds no permissions of its own", func(t *testing.T) {
		// The key carries neither permissions nor buckets: every action it has comes
		// from the bucket policies, so with no policy it reaches nothing, and the
		// bucket it addressed is not one it can see.
		az, _, _, _, _ := setupWithPolicies(t, accessKey, &setupConfig{principalBound: true})
		_, err := az.Authorize(ctx, providerID, signedObjectRequest(t, accessKey, "bucket", region))
		require.ErrorIs(t, err, auth.ErrUnknownBucket)
	})

	t.Run("a service key holding s3:ListAllMyBuckets may list", func(t *testing.T) {
		az, _, _ := setup(t, accessKey, &setupConfig{accessKeyPermissions: []string{"s3:ListAllMyBuckets"}})
		secret, err := multibase.Encode(multibase.Base64url, accessKey.Bytes())
		require.NoError(t, err)
		req := sigv4.Request{Method: "GET", URL: "https://s3.fil.one/"}
		signed, err := sigv4.Presign(req, accessKey.KeyDID().Identifier(), secret, region, sigv4.SchemeV4, time.Now(), time.Hour)
		require.NoError(t, err)
		authz, err := az.Authorize(ctx, providerID, s3.Request{Method: signed.Method, URL: signed.URL})
		require.NoError(t, err)
		require.Equal(t, auth.OpListBuckets, authz.Operation)
		require.Nil(t, authz.Bucket)
		require.Equal(t, []string{"s3:ListAllMyBuckets"}, authz.Permissions)
	})

	t.Run("authorizes a principal-bound key for what the policy grants it", func(t *testing.T) {
		az, _, tenantID, bucketID, pool := setupWithPolicies(t, accessKey, &setupConfig{principalBound: true})
		grant(t, pool, bucketID, tenantID, s3bkt.Statement{
			Effect:    s3bkt.Allow,
			Principal: s3bkt.Only("user-1"),
			Actions:   s3bkt.NewStringSet("s3:GetObject", "s3:ListBucket"),
			Resources: s3bkt.NewStringSet(s3bkt.BucketARN("photos"), s3bkt.ObjectsARN("photos")),
		})

		authz, err := az.Authorize(ctx, providerID, signedObjectRequest(t, accessKey, "bucket", region))
		require.NoError(t, err)
		require.Equal(t, []string{"s3:GetObject", "s3:ListBucket"}, authz.Permissions)
		require.NotNil(t, authz.Bucket)
		require.Equal(t, bucketID, authz.Bucket.ID)
	})

	t.Run("a principal's attributes read needs both actions from the policy", func(t *testing.T) {
		allow := func(actions ...string) s3bkt.Statement {
			return s3bkt.Statement{Effect: s3bkt.Allow, Principal: s3bkt.Only("user-1"), Actions: s3bkt.NewStringSet(actions...), Resources: s3bkt.NewStringSet(s3bkt.BucketARN("photos"), s3bkt.ObjectsARN("photos"))}
		}
		az, _, tenantID, bucketID, pool := setupWithPolicies(t, accessKey, &setupConfig{principalBound: true})
		grant(t, pool, bucketID, tenantID, allow("s3:GetObjectAttributes"))
		_, err := az.Authorize(ctx, providerID, signedObjectQueryRequest(t, accessKey, "bucket", "attributes", region))
		require.ErrorIs(t, err, auth.ErrOperationNotPermitted)

		az, _, tenantID, bucketID, pool = setupWithPolicies(t, accessKey, &setupConfig{principalBound: true})
		grant(t, pool, bucketID, tenantID, allow("s3:GetObjectAttributes", "s3:GetObject"))
		authz, err := az.Authorize(ctx, providerID, signedObjectQueryRequest(t, accessKey, "bucket", "attributes", region))
		require.NoError(t, err)
		require.Equal(t, auth.OpGetObjectAttributes, authz.Operation)
		require.Equal(t, bucketID, authz.Bucket.ID)
	})

	t.Run("a principal's DeleteObjects naming a version needs the version action", func(t *testing.T) {
		allow := func(actions ...string) s3bkt.Statement {
			return s3bkt.Statement{Effect: s3bkt.Allow, Principal: s3bkt.Only("user-1"), Actions: s3bkt.NewStringSet(actions...), Resources: s3bkt.NewStringSet(s3bkt.BucketARN("photos"), s3bkt.ObjectsARN("photos"))}
		}
		const versions = `<Delete><Object><Key>b</Key><VersionId>v1</VersionId></Object></Delete>`
		az, _, tenantID, bucketID, pool := setupWithPolicies(t, accessKey, &setupConfig{principalBound: true})
		grant(t, pool, bucketID, tenantID, allow("s3:DeleteObject"))
		_, err := az.Authorize(ctx, providerID, signedBodyRequest(t, accessKey, "POST", "https://s3.fil.one/bucket?delete", versions, region, true))
		require.ErrorIs(t, err, auth.ErrOperationNotPermitted)

		az, _, tenantID, bucketID, pool = setupWithPolicies(t, accessKey, &setupConfig{principalBound: true})
		grant(t, pool, bucketID, tenantID, allow("s3:DeleteObject", "s3:DeleteObjectVersion"))
		authz, err := az.Authorize(ctx, providerID, signedBodyRequest(t, accessKey, "POST", "https://s3.fil.one/bucket?delete", versions, region, true))
		require.NoError(t, err)
		require.Equal(t, auth.OpDeleteObjects, authz.Operation)
		require.Equal(t, bucketID, authz.Bucket.ID)
	})

	t.Run("a Deny wins over an Allow naming the same action", func(t *testing.T) {
		az, _, tenantID, bucketID, pool := setupWithPolicies(t, accessKey, &setupConfig{principalBound: true})
		grant(t, pool, bucketID, tenantID,
			s3bkt.Statement{Effect: s3bkt.Allow, Principal: s3bkt.Everyone(), Actions: s3bkt.NewStringSet("s3:GetObject", "s3:ListBucket"), Resources: s3bkt.NewStringSet(s3bkt.BucketARN("photos"), s3bkt.ObjectsARN("photos"))},
			s3bkt.Statement{Effect: s3bkt.Deny, Principal: s3bkt.Only("user-1"), Actions: s3bkt.NewStringSet("s3:GetObject"), Resources: s3bkt.NewStringSet(s3bkt.BucketARN("photos"), s3bkt.ObjectsARN("photos"))},
		)

		_, err := az.Authorize(ctx, providerID, signedObjectRequest(t, accessKey, "bucket", region))
		require.ErrorIs(t, err, auth.ErrOperationNotPermitted)
	})

	t.Run("an empty effective set hides the bucket", func(t *testing.T) {
		// No policy at all, and a policy that denies everything it allows, both
		// leave the principal with nothing, which reads as an unknown bucket
		// rather than a refusal.
		az, _, _, _, _ := setupWithPolicies(t, accessKey, &setupConfig{principalBound: true})
		_, err := az.Authorize(ctx, providerID, signedObjectRequest(t, accessKey, "bucket", region))
		require.ErrorIs(t, err, auth.ErrUnknownBucket)

		az, _, tenantID, bucketID, pool := setupWithPolicies(t, accessKey, &setupConfig{principalBound: true})
		grant(t, pool, bucketID, tenantID,
			s3bkt.Statement{Effect: s3bkt.Allow, Principal: s3bkt.Only("user-1"), Actions: s3bkt.NewStringSet("s3:GetObject"), Resources: s3bkt.NewStringSet(s3bkt.BucketARN("photos"), s3bkt.ObjectsARN("photos"))},
			s3bkt.Statement{Effect: s3bkt.Deny, Principal: s3bkt.Only("user-1"), Actions: s3bkt.NewStringSet("s3:GetObject"), Resources: s3bkt.NewStringSet(s3bkt.BucketARN("photos"), s3bkt.ObjectsARN("photos"))},
		)
		_, err = az.Authorize(ctx, providerID, signedObjectRequest(t, accessKey, "bucket", region))
		require.ErrorIs(t, err, auth.ErrUnknownBucket)
	})

	t.Run("a principal-bound key may not create or delete a bucket or set its encryption or CORS", func(t *testing.T) {
		az, _, tenantID, bucketID, pool := setupWithPolicies(t, accessKey, &setupConfig{principalBound: true})
		grant(t, pool, bucketID, tenantID, s3bkt.Statement{
			Effect:    s3bkt.Allow,
			Principal: s3bkt.Only("user-1"),
			Actions:   s3bkt.NewStringSet("s3:GetObject"),
			Resources: s3bkt.NewStringSet(s3bkt.BucketARN("photos"), s3bkt.ObjectsARN("photos")),
		})
		secret, err := multibase.Encode(multibase.Base64url, accessKey.Bytes())
		require.NoError(t, err)

		for _, req := range []sigv4.Request{
			{Method: "PUT", URL: "https://s3.fil.one/bucket"},
			{Method: "DELETE", URL: "https://s3.fil.one/bucket"},
			{Method: "GET", URL: "https://s3.fil.one/bucket?encryption"},
			{Method: "PUT", URL: "https://s3.fil.one/bucket?encryption"},
			{Method: "DELETE", URL: "https://s3.fil.one/bucket?encryption"},
			{Method: "PUT", URL: "https://s3.fil.one/bucket?cors"},
			{Method: "DELETE", URL: "https://s3.fil.one/bucket?cors"},
		} {
			signed, err := sigv4.Presign(req, accessKey.DID().Identifier(), secret, region, sigv4.SchemeV4, time.Now(), time.Hour)
			require.NoError(t, err)
			_, err = az.Authorize(ctx, providerID, s3.Request{Method: signed.Method, URL: signed.URL})
			require.ErrorIs(t, err, auth.ErrOperationNotPermitted, req.Method)
		}
	})

	t.Run("every principal lists the tenant's buckets", func(t *testing.T) {
		// ListBuckets consults no policy: the principal holds it with no grant at
		// all, and the listing addresses no bucket.
		az, _, _, _, _ := setupWithPolicies(t, accessKey, &setupConfig{principalBound: true})
		secret, err := multibase.Encode(multibase.Base64url, accessKey.Bytes())
		require.NoError(t, err)
		signed, err := sigv4.Presign(sigv4.Request{Method: "GET", URL: "https://s3.fil.one/"},
			accessKey.DID().Identifier(), secret, region, sigv4.SchemeV4, time.Now(), time.Hour)
		require.NoError(t, err)
		authz, err := az.Authorize(ctx, providerID, s3.Request{Method: signed.Method, URL: signed.URL})
		require.NoError(t, err)
		require.Equal(t, auth.OpListBuckets, authz.Operation)
		require.Equal(t, []string{"s3:ListAllMyBuckets"}, authz.Permissions)
		require.Nil(t, authz.Bucket)
	})

	t.Run("a principal-bound key copies only what both policies grant", func(t *testing.T) {
		// A copy is two decisions for a principal as much as for a service key:
		// the write on the destination and the read on the source, each against
		// the effective set the bucket's own policy gives the principal.
		allow := func(actions ...string) s3bkt.Statement {
			return s3bkt.Statement{Effect: s3bkt.Allow, Principal: s3bkt.Only("user-1"), Actions: s3bkt.NewStringSet(actions...), Resources: s3bkt.NewStringSet(s3bkt.BucketARN("photos"), s3bkt.ObjectsARN("photos"))}
		}

		t.Run("the source's policy grants the read", func(t *testing.T) {
			az, _, tenantID, bucketID, pool := setupWithPolicies(t, accessKey, &setupConfig{principalBound: true})
			grant(t, pool, bucket2ID, tenantID, allow("s3:PutObject"))
			grant(t, pool, bucketID, tenantID, allow("s3:GetObject"))

			authz, err := az.Authorize(ctx, providerID, signedCopyRequest(t, accessKey, "bucket2", "bucket", region, true))
			require.NoError(t, err)
			require.Equal(t, auth.OpCopyObject, authz.Operation)
			require.Equal(t, bucket2ID, authz.Bucket.ID)
			require.Equal(t, "bucket", authz.SourceBucketName)
			require.NotNil(t, authz.SourceBucket)
			require.Equal(t, bucketID, authz.SourceBucket.ID)
		})

		t.Run("the source's policy grants everything but the read", func(t *testing.T) {
			az, _, tenantID, bucketID, pool := setupWithPolicies(t, accessKey, &setupConfig{principalBound: true})
			grant(t, pool, bucket2ID, tenantID, allow("s3:PutObject", "s3:GetObject"))
			grant(t, pool, bucketID, tenantID, allow("s3:ListBucket"))

			_, err := az.Authorize(ctx, providerID, signedCopyRequest(t, accessKey, "bucket2", "bucket", region, true))
			require.ErrorIs(t, err, auth.ErrOperationNotPermitted)
		})

		t.Run("the read on the destination does not carry to the source", func(t *testing.T) {
			// Holding the read on the destination is what a copy of an object
			// already in the bucket needs; it says nothing about another bucket.
			az, _, tenantID, _, pool := setupWithPolicies(t, accessKey, &setupConfig{principalBound: true})
			grant(t, pool, bucket2ID, tenantID, allow("s3:PutObject", "s3:GetObject"))

			_, err := az.Authorize(ctx, providerID, signedCopyRequest(t, accessKey, "bucket2", "bucket", region, true))
			// No policy on the source, so it is not a bucket the principal may
			// learn exists.
			require.ErrorIs(t, err, auth.ErrUnknownBucket)
		})

		t.Run("a source version needs the version read from the source's policy", func(t *testing.T) {
			az, _, tenantID, bucketID, pool := setupWithPolicies(t, accessKey, &setupConfig{principalBound: true})
			grant(t, pool, bucket2ID, tenantID, allow("s3:PutObject"))
			grant(t, pool, bucketID, tenantID, allow("s3:GetObject"))
			_, err := az.Authorize(ctx, providerID, signedCopySourceRequest(t, accessKey, "bucket2", "/bucket/object-key?versionId=v1", region, true))
			require.ErrorIs(t, err, auth.ErrOperationNotPermitted)

			az, _, tenantID, bucketID, pool = setupWithPolicies(t, accessKey, &setupConfig{principalBound: true})
			grant(t, pool, bucket2ID, tenantID, allow("s3:PutObject"))
			grant(t, pool, bucketID, tenantID, allow("s3:GetObjectVersion"))
			authz, err := az.Authorize(ctx, providerID, signedCopySourceRequest(t, accessKey, "bucket2", "/bucket/object-key?versionId=v1", region, true))
			require.NoError(t, err)
			require.Equal(t, auth.SourceVersionPermission, authz.SourcePermission)
			require.Equal(t, bucketID, authz.SourceBucket.ID)
		})

		t.Run("a bypass header needs the bypass action from the policy", func(t *testing.T) {
			bypass := map[string]string{"x-amz-bypass-governance-retention": "true"}
			az, _, tenantID, bucketID, pool := setupWithPolicies(t, accessKey, &setupConfig{principalBound: true})
			grant(t, pool, bucketID, tenantID, allow("s3:DeleteObjectVersion"))
			_, err := az.Authorize(ctx, providerID, signedRequestWith(t, accessKey, "DELETE", "https://s3.fil.one/bucket/object-key?versionId=v1", bypass, region, "x-amz-bypass-governance-retention"))
			require.ErrorIs(t, err, auth.ErrOperationNotPermitted)

			az, _, tenantID, bucketID, pool = setupWithPolicies(t, accessKey, &setupConfig{principalBound: true})
			grant(t, pool, bucketID, tenantID, allow("s3:DeleteObjectVersion", "s3:BypassGovernanceRetention"))
			authz, err := az.Authorize(ctx, providerID, signedRequestWith(t, accessKey, "DELETE", "https://s3.fil.one/bucket/object-key?versionId=v1", bypass, region, "x-amz-bypass-governance-retention"))
			require.NoError(t, err)
			require.Equal(t, bucketID, authz.Bucket.ID)
		})

		t.Run("a lock header needs the lock action from the destination's policy", func(t *testing.T) {
			hold := map[string]string{"x-amz-copy-source": "/bucket/object-key", "x-amz-object-lock-legal-hold": "ON"}
			az, _, tenantID, bucketID, pool := setupWithPolicies(t, accessKey, &setupConfig{principalBound: true})
			grant(t, pool, bucket2ID, tenantID, allow("s3:PutObject"))
			grant(t, pool, bucketID, tenantID, allow("s3:GetObject", "s3:PutObjectLegalHold"))
			_, err := az.Authorize(ctx, providerID, signedRequestWith(t, accessKey, "PUT", "https://s3.fil.one/bucket2/object-key", hold, region, "x-amz-copy-source", "x-amz-object-lock-legal-hold"))
			require.ErrorIs(t, err, auth.ErrOperationNotPermitted)

			az, _, tenantID, bucketID, pool = setupWithPolicies(t, accessKey, &setupConfig{principalBound: true})
			grant(t, pool, bucket2ID, tenantID, allow("s3:PutObject", "s3:PutObjectLegalHold"))
			grant(t, pool, bucketID, tenantID, allow("s3:GetObject"))
			authz, err := az.Authorize(ctx, providerID, signedRequestWith(t, accessKey, "PUT", "https://s3.fil.one/bucket2/object-key", hold, region, "x-amz-copy-source", "x-amz-object-lock-legal-hold"))
			require.NoError(t, err)
			require.Equal(t, bucket2ID, authz.Bucket.ID)
		})

		t.Run("a copy within one bucket needs both actions there", func(t *testing.T) {
			az, _, tenantID, bucketID, pool := setupWithPolicies(t, accessKey, &setupConfig{principalBound: true})
			grant(t, pool, bucketID, tenantID, allow("s3:PutObject"))
			_, err := az.Authorize(ctx, providerID, signedCopyRequest(t, accessKey, "bucket", "bucket", region, true))
			require.ErrorIs(t, err, auth.ErrOperationNotPermitted)

			az, _, tenantID, bucketID, pool = setupWithPolicies(t, accessKey, &setupConfig{principalBound: true})
			grant(t, pool, bucketID, tenantID, allow("s3:PutObject", "s3:GetObject"))
			authz, err := az.Authorize(ctx, providerID, signedCopyRequest(t, accessKey, "bucket", "bucket", region, true))
			require.NoError(t, err)
			require.Same(t, authz.Bucket, authz.SourceBucket)
		})

		t.Run("a copy from another tenant's bucket is refused before any policy", func(t *testing.T) {
			az, _, tenantID, _, pool := setupWithPolicies(t, accessKey, &setupConfig{principalBound: true})
			grant(t, pool, bucket2ID, tenantID, allow("s3:PutObject", "s3:GetObject"))

			_, err := az.Authorize(ctx, providerID, signedCopyRequest(t, accessKey, "bucket2", "theirs", region, true))
			require.ErrorIs(t, err, auth.ErrForeignBucket)
		})

		t.Run("an unsigned source header is refused for a principal too", func(t *testing.T) {
			az, _, tenantID, bucketID, pool := setupWithPolicies(t, accessKey, &setupConfig{principalBound: true})
			grant(t, pool, bucket2ID, tenantID, allow("s3:PutObject"))
			grant(t, pool, bucketID, tenantID, allow("s3:GetObject"))

			_, err := az.Authorize(ctx, providerID, signedCopyRequest(t, accessKey, "bucket2", "bucket", region, false))
			require.ErrorIs(t, err, auth.ErrUnsignedHeader)
		})
	})

	t.Run("a principal-bound key whose principal was removed is an unknown key", func(t *testing.T) {
		pool := htestutil.PostgresOrSkip(t)
		// The principal exists as a tombstone: removal marks the row rather than
		// deleting it, and the authorizer must not see it.
		accessKeys, tenants := accesskeypostgres.New(pool), tenantpostgres.New(pool)
		providers, buckets, secrets := providerpostgres.New(pool), bucketpostgres.New(pool), vaultmemory.New()
		require.NoError(t, providers.Add(ctx, providerID, region, nil))
		tenantID := testutil.RandomDID(t)
		require.NoError(t, tenants.Add(ctx, tenantID, "tenant-1", tenant.Active))
		require.NoError(t, buckets.Add(ctx, testutil.RandomDID(t), tenantID, providerID, "bucket"))
		delegations := delegationpostgres.New(pool)
		principals := principalpostgres.New(pool)
		require.NoError(t, principals.Add(ctx, tenantID, "user-1"))
		seedKey(t, accessKeys, secrets, delegations, accessKey, tenantID, &setupConfig{principalBound: true})
		removed := principals.TombstoneStatement(tenantID, "user-1")
		_, err := pool.Exec(ctx, removed.SQL, removed.Args...)
		require.NoError(t, err)
		gone := auth.NewAuthorizer(zap.NewNop(), accessKeys, tenants, providers, buckets,
			principals, bucketpolicypostgres.New(pool), secrets, auth.WithSnapshots(pglock.NewSnapshots(pool)))

		_, err = gone.Authorize(ctx, providerID, signedObjectRequest(t, accessKey, "bucket", region))
		require.ErrorIs(t, err, auth.ErrUnknownAccessKey)
	})

	t.Run("rejects an invalid signature", func(t *testing.T) {
		pool := htestutil.PostgresOrSkip(t)
		// The access key record exists, but the vault holds a different secret than
		// the one that signed the request, so the recomputed signature won't match.
		other, err := ed25519.GenerateIssuer()
		require.NoError(t, err)
		accessKeys, tenants := accesskeypostgres.New(pool), tenantpostgres.New(pool)
		providers, secrets := providerpostgres.New(pool), vaultmemory.New()
		require.NoError(t, providers.Add(ctx, providerID, region, nil))
		tenantID := testutil.RandomDID(t)
		require.NoError(t, tenants.Add(ctx, tenantID, "tenant-1", tenant.Active))
		require.NoError(t, accessKeys.Add(ctx, accesskey.Input{ID: accessKey.DID(), Tenant: tenantID, Name: "k1", Permissions: []string{"s3:GetObject"}}))
		require.NoError(t, secrets.Write(ctx, vault.AccessKeyPath(tenantID, accessKey.DID()), other.Bytes()))
		az := auth.NewAuthorizer(zap.NewNop(), accessKeys, tenants, providers, bucketpostgres.New(pool), principalpostgres.New(pool), bucketpolicypostgres.New(pool), secrets)

		_, err = az.Authorize(ctx, providerID, signedRequest(t, accessKey, region, time.Now(), time.Hour))
		require.ErrorIs(t, err, auth.ErrSignatureMismatch)
	})

	t.Run("rejects an unsigned request", func(t *testing.T) {
		az, _, _ := setup(t, accessKey, nil)
		_, err := az.Authorize(ctx, providerID, s3.Request{Method: "GET", URL: "https://s3.fil.one/bucket/object-key"})
		require.ErrorIs(t, err, auth.ErrMalformedSignature)
	})

	t.Run("rejects an unknown access key", func(t *testing.T) {
		pool := htestutil.PostgresOrSkip(t)
		az := auth.NewAuthorizer(zap.NewNop(), accesskeypostgres.New(pool), tenantpostgres.New(pool), providerpostgres.New(pool), bucketpostgres.New(pool), principalpostgres.New(pool), bucketpolicypostgres.New(pool), vaultmemory.New())
		_, err := az.Authorize(ctx, providerID, signedRequest(t, accessKey, region, time.Now(), time.Hour))
		require.ErrorIs(t, err, auth.ErrUnknownAccessKey)
	})

	t.Run("rejects when the access key secret is missing from the vault", func(t *testing.T) {
		pool := htestutil.PostgresOrSkip(t)
		// The access key record exists but its private key was never written to the
		// vault — a store/vault inconsistency the signer load must reject.
		accessKeys, tenants := accesskeypostgres.New(pool), tenantpostgres.New(pool)
		providers, secrets := providerpostgres.New(pool), vaultmemory.New()
		require.NoError(t, providers.Add(ctx, providerID, region, nil))
		tenantID := testutil.RandomDID(t)
		require.NoError(t, tenants.Add(ctx, tenantID, "tenant-1", tenant.Active))
		require.NoError(t, accessKeys.Add(ctx, accesskey.Input{ID: accessKey.DID(), Tenant: tenantID, Name: "k1", Permissions: []string{"s3:GetObject"}}))
		az := auth.NewAuthorizer(zap.NewNop(), accessKeys, tenants, providers, bucketpostgres.New(pool), principalpostgres.New(pool), bucketpolicypostgres.New(pool), secrets)

		_, err := az.Authorize(ctx, providerID, signedRequest(t, accessKey, region, time.Now(), time.Hour))
		require.Error(t, err)
	})

	t.Run("rejects a request signed for a region another provider serves", func(t *testing.T) {
		// setup gave region2 to provider2ID, so providerID may not act on a request
		// signed for it, even though the tenant has a bucket there.
		az, _, _ := setup(t, accessKey, nil)
		_, err := az.Authorize(ctx, providerID, signedRequest(t, accessKey, region2, time.Now(), time.Hour))
		require.ErrorIs(t, err, auth.ErrIssuerForbidden)
	})

	t.Run("rejects a region no provider serves", func(t *testing.T) {
		az, _, _ := setup(t, accessKey, nil)
		_, err := az.Authorize(ctx, providerID, signedRequest(t, accessKey, "ap-south-1", time.Now(), time.Hour))
		require.ErrorIs(t, err, auth.ErrRegionNotServed)
	})

	t.Run("rejects an expired presigned URL", func(t *testing.T) {
		az, _, _ := setup(t, accessKey, nil)
		// Validly signed, but two hours ago with only a one-hour window.
		_, err := az.Authorize(ctx, providerID, signedRequest(t, accessKey, region, time.Now().Add(-2*time.Hour), time.Hour))
		require.ErrorIs(t, err, auth.ErrSignatureExpired)
	})

	t.Run("rejects an invocation not from the provider serving the request region", func(t *testing.T) {
		az, _, _ := setup(t, accessKey, nil)
		_, err := az.Authorize(ctx, testutil.RandomDID(t), signedRequest(t, accessKey, region, time.Now(), time.Hour))
		require.ErrorIs(t, err, auth.ErrIssuerForbidden)
	})

	t.Run("rejects an expired access key", func(t *testing.T) {
		// A freshly-signed request from the region's provider must still be rejected
		// when the access key itself has expired (so expiry is the only variable).
		past := time.Now().Add(-time.Hour)
		az, _, _ := setup(t, accessKey, &setupConfig{accessKeyExpires: &past})
		_, err := az.Authorize(ctx, providerID, signedRequest(t, accessKey, region, time.Now(), time.Hour))
		require.ErrorIs(t, err, auth.ErrAccessKeyExpired)
	})

	t.Run("rejects a disabled tenant", func(t *testing.T) {
		// A freshly-signed request from the region's provider must be rejected when
		// the tenant is disabled (so disabled status is the only variable).
		az, _, _ := setup(t, accessKey, &setupConfig{tenantStatus: tenant.Disabled})
		_, err := az.Authorize(ctx, providerID, signedRequest(t, accessKey, region, time.Now(), time.Hour))
		require.ErrorIs(t, err, auth.ErrTenantDisabled)
	})

	// everyPermission is a service key that holds whatever a request in
	// writeLockCases needs, so the tenant's status is the only thing that
	// decides between them.
	everyPermission := []string{
		"s3:GetObject", "s3:GetObjectVersion", "s3:GetObjectTagging", "s3:ListBucket", "s3:ListBucketVersions",
		"s3:ListAllMyBuckets", "s3:ListBucketMultipartUploads", "s3:ListMultipartUploadParts",
		"s3:GetBucketPolicy", "s3:GetBucketVersioning",
		"s3:DeleteObject", "s3:DeleteObjectVersion", "s3:DeleteBucket", "s3:AbortMultipartUpload",
		"s3:PutObject", "s3:CreateBucket",
		"s3:PutBucketPolicy", "s3:DeleteBucketPolicy", "s3:PutEncryptionConfiguration", "s3:PutBucketCORS",
		"s3:PutBucketTagging", "s3:PutBucketVersioning", "s3:PutBucketObjectLockConfiguration",
		"s3:PutObjectRetention", "s3:PutObjectLegalHold", "s3:PutObjectTagging", "s3:DeleteObjectTagging",
		"s3:BypassGovernanceRetention",
	}
	keptPermissions := []string{
		"s3:GetObject", "s3:GetObjectVersion", "s3:GetObjectTagging", "s3:ListBucket", "s3:ListBucketVersions",
		"s3:ListAllMyBuckets", "s3:ListBucketMultipartUploads", "s3:ListMultipartUploadParts",
		"s3:GetBucketPolicy", "s3:GetBucketVersioning",
		"s3:DeleteObject", "s3:DeleteObjectVersion", "s3:DeleteBucket", "s3:AbortMultipartUpload",
		"s3:BypassGovernanceRetention",
	}
	plain := func(method, path string) func(*testing.T) s3.Request {
		return func(t *testing.T) s3.Request {
			return signedRequestWith(t, accessKey, method, "https://s3.fil.one"+path, nil, region)
		}
	}
	withHeader := func(method, path, header, value string) func(*testing.T) s3.Request {
		return func(t *testing.T) s3.Request {
			return signedRequestWith(t, accessKey, method, "https://s3.fil.one"+path, map[string]string{header: value}, region, header)
		}
	}
	writeLockCases := []struct {
		name    string
		request func(*testing.T) s3.Request
		op      auth.Operation
		// kept is whether a write-locked tenant is still authorized.
		kept bool
	}{
		{"GetObject", plain("GET", "/bucket/object-key"), auth.OpGetObject, true},
		{"HeadObject", plain("HEAD", "/bucket/object-key"), auth.OpGetObject, true},
		{"GetObjectVersion", plain("GET", "/bucket/object-key?versionId=v1"), auth.OpGetObjectVersion, true},
		{"GetObjectTagging", plain("GET", "/bucket/object-key?tagging"), auth.OpGetObjectTagging, true},
		{"ListBucket", plain("GET", "/bucket"), auth.OpListBucket, true},
		{"ListBucketVersions", plain("GET", "/bucket?versions"), auth.OpListBucketVersions, true},
		{"ListBuckets", plain("GET", "/"), auth.OpListBuckets, true},
		{"ListBucketMultipartUploads", plain("GET", "/bucket?uploads"), auth.OpListBucketMultipartUploads, true},
		{"ListMultipartUploadParts", plain("GET", "/bucket/object-key?uploadId=u"), auth.OpListMultipartUploadParts, true},
		{"GetBucketPolicy", plain("GET", "/bucket?policy"), auth.OpGetBucketPolicy, true},
		{"GetBucketVersioning", plain("GET", "/bucket?versioning"), auth.OpGetBucketVersioning, true},
		{"DeleteObject", plain("DELETE", "/bucket/object-key"), auth.OpDeleteObject, true},
		{"DeleteObjectVersion", plain("DELETE", "/bucket/object-key?versionId=v1"), auth.OpDeleteObjectVersion, true},
		{"DeleteObjects naming a version", func(t *testing.T) s3.Request {
			return signedBodyRequest(t, accessKey, "POST", "https://s3.fil.one/bucket?delete",
				"<Delete><Object><Key>one</Key><VersionId>v1</VersionId></Object></Delete>", region, true)
		}, auth.OpDeleteObjects, true},
		{"AbortMultipartUpload", plain("DELETE", "/bucket/object-key?uploadId=u"), auth.OpAbortMultipartUpload, true},
		{"DeleteBucket", plain("DELETE", "/bucket"), auth.OpDeleteBucket, true},

		{"PutObject", plain("PUT", "/bucket/object-key"), auth.OpPutObject, false},
		{"CopyObject", func(t *testing.T) s3.Request {
			return signedCopyRequest(t, accessKey, "bucket", "bucket2", region, true)
		}, auth.OpCopyObject, false},
		{"CreateMultipartUpload", plain("POST", "/bucket/object-key?uploads"), auth.OpCreateMultipartUpload, false},
		{"UploadPart", plain("PUT", "/bucket/object-key?uploadId=u&partNumber=1"), auth.OpUploadPart, false},
		{"UploadPartCopy", withHeader("PUT", "/bucket/object-key?uploadId=u&partNumber=1", "x-amz-copy-source", "/bucket2/object-key"), auth.OpUploadPartCopy, false},
		{"CompleteMultipartUpload", plain("POST", "/bucket/object-key?uploadId=u"), auth.OpCompleteMultipartUpload, false},
		{"CreateBucket", plain("PUT", "/newbucket"), auth.OpCreateBucket, false},
		{"PutBucketPolicy", plain("PUT", "/bucket?policy"), auth.OpPutBucketPolicy, false},
		{"DeleteBucketPolicy", plain("DELETE", "/bucket?policy"), auth.OpDeleteBucketPolicy, false},
		{"PutBucketEncryption", plain("PUT", "/bucket?encryption"), auth.OpPutBucketEncryption, false},
		{"DeleteBucketEncryption", plain("DELETE", "/bucket?encryption"), auth.OpDeleteBucketEncryption, false},
		{"PutBucketCors", plain("PUT", "/bucket?cors"), auth.OpPutBucketCors, false},
		{"DeleteBucketCors", plain("DELETE", "/bucket?cors"), auth.OpDeleteBucketCors, false},
		{"PutBucketTagging", plain("PUT", "/bucket?tagging"), auth.OpPutBucketTagging, false},
		{"DeleteBucketTagging", plain("DELETE", "/bucket?tagging"), auth.OpDeleteBucketTagging, false},
		{"PutBucketVersioning", plain("PUT", "/bucket?versioning"), auth.OpPutBucketVersioning, false},
		{"PutObjectLockConfiguration", plain("PUT", "/bucket?object-lock"), auth.OpPutObjectLockConfiguration, false},
		{"PutObjectRetention", plain("PUT", "/bucket/object-key?retention"), auth.OpPutObjectRetention, false},
		{"PutObjectLegalHold", plain("PUT", "/bucket/object-key?legal-hold"), auth.OpPutObjectLegalHold, false},
		{"PutObjectTagging", plain("PUT", "/bucket/object-key?tagging"), auth.OpPutObjectTagging, false},
		{"DeleteObjectTagging", plain("DELETE", "/bucket/object-key?tagging"), auth.OpDeleteObjectTagging, false},
		{"DeleteObject bypassing governance retention", withHeader("DELETE", "/bucket/object-key?versionId=v1", "x-amz-bypass-governance-retention", "true"), auth.OpDeleteObjectVersion, true},
	}

	t.Run("a write-locked tenant keeps its reads, listings and deletions and is refused the rest", func(t *testing.T) {
		az, _, _ := setup(t, accessKey, &setupConfig{tenantStatus: tenant.WriteLocked, accessKeyPermissions: everyPermission})
		for _, tc := range writeLockCases {
			t.Run(tc.name, func(t *testing.T) {
				got, err := az.Authorize(ctx, providerID, tc.request(t))
				if !tc.kept {
					require.ErrorIs(t, err, auth.ErrTenantWriteLocked)
					require.Nil(t, got)
					return
				}
				require.NoError(t, err)
				require.Equal(t, tc.op, got.Operation)
				require.Equal(t, keptPermissions, got.Permissions, "the permissions the gateway caches are the kept ones")
			})
		}
	})

	t.Run("an active tenant is authorized all of them, with its full permissions", func(t *testing.T) {
		az, _, _ := setup(t, accessKey, &setupConfig{accessKeyPermissions: everyPermission})
		for _, tc := range writeLockCases {
			t.Run(tc.name, func(t *testing.T) {
				got, err := az.Authorize(ctx, providerID, tc.request(t))
				require.NoError(t, err)
				require.Equal(t, tc.op, got.Operation)
				require.Equal(t, everyPermission, got.Permissions)
			})
		}
	})

	t.Run("a write-locked tenant is refused as write-locked whatever its key holds", func(t *testing.T) {
		// The key may only read, so an active tenant's upload is refused for
		// the key; a write-locked tenant's is refused for the tenant.
		active, _, _ := setup(t, accessKey, nil)
		_, err := active.Authorize(ctx, providerID, plain("PUT", "/bucket/object-key")(t))
		require.ErrorIs(t, err, auth.ErrOperationNotPermitted)

		locked, _, _ := setup(t, accessKey, &setupConfig{tenantStatus: tenant.WriteLocked})
		_, err = locked.Authorize(ctx, providerID, plain("PUT", "/bucket/object-key")(t))
		require.ErrorIs(t, err, auth.ErrTenantWriteLocked)
		// A kept operation the key lacks is still the key's refusal.
		_, err = locked.Authorize(ctx, providerID, plain("DELETE", "/bucket/object-key")(t))
		require.ErrorIs(t, err, auth.ErrOperationNotPermitted)
	})

	t.Run("a write-locked tenant's principal-bound key keeps the kept part of its policy", func(t *testing.T) {
		az, _, tenantID, bucketID, pool := setupWithPolicies(t, accessKey, &setupConfig{tenantStatus: tenant.WriteLocked, principalBound: true})
		grant(t, pool, bucketID, tenantID, s3bkt.Statement{Effect: s3bkt.Allow, Principal: s3bkt.Only("user-1"),
			Actions:   s3bkt.NewStringSet("s3:GetObject", "s3:PutObject", "s3:DeleteObject", "s3:DeleteObjectTagging"),
			Resources: s3bkt.NewStringSet(s3bkt.ObjectsARN("bucket"))})

		for _, kept := range []func(*testing.T) s3.Request{plain("GET", "/bucket/object-key"), plain("DELETE", "/bucket/object-key")} {
			got, err := az.Authorize(ctx, providerID, kept(t))
			require.NoError(t, err)
			require.ElementsMatch(t, []string{"s3:GetObject", "s3:DeleteObject"}, got.Permissions)
		}
		for _, lost := range []func(*testing.T) s3.Request{plain("PUT", "/bucket/object-key"), plain("DELETE", "/bucket/object-key?tagging"), plain("PUT", "/newbucket")} {
			_, err := az.Authorize(ctx, providerID, lost(t))
			require.ErrorIs(t, err, auth.ErrTenantWriteLocked)
		}
		got, err := az.Authorize(ctx, providerID, plain("GET", "/")(t))
		require.NoError(t, err)
		require.Equal(t, []string{"s3:ListAllMyBuckets"}, got.Permissions)
	})
}

func TestTenantIssuer(t *testing.T) {
	pool := htestutil.PostgresOrSkip(t)
	ctx := t.Context()
	buckets, secrets := bucketpostgres.New(pool), vaultmemory.New()
	az := auth.NewAuthorizer(zap.NewNop(), accesskeypostgres.New(pool), tenantpostgres.New(pool), providerpostgres.New(pool), buckets, principalpostgres.New(pool), bucketpolicypostgres.New(pool), secrets)

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
