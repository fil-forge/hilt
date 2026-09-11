package auth_test

import (
	"context"
	"testing"
	"time"

	"github.com/fil-forge/hilt/pkg/bucketpolicy"
	"github.com/fil-forge/hilt/pkg/rpc/service/auth"
	"github.com/fil-forge/hilt/pkg/sigv4"
	"github.com/fil-forge/hilt/pkg/store"
	"github.com/fil-forge/hilt/pkg/store/accesskey"
	accesskeymemory "github.com/fil-forge/hilt/pkg/store/accesskey/memory"
	bucketmemory "github.com/fil-forge/hilt/pkg/store/bucket/memory"
	bucketpolicystore "github.com/fil-forge/hilt/pkg/store/bucketpolicy"
	bucketpolicymemory "github.com/fil-forge/hilt/pkg/store/bucketpolicy/memory"
	principalstore "github.com/fil-forge/hilt/pkg/store/principal"
	principalmemory "github.com/fil-forge/hilt/pkg/store/principal/memory"
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

// seedKey stores the credential's record and vault entry: a service key with
// its own permissions and buckets unless principalBound, in which case a key
// bound to "user-1", which holds neither.
func seedKey(t *testing.T, accessKeys *accesskeymemory.Store, secrets *vaultmemory.Store, key multikey.Issuer, tenantID did.DID, cfg *setupConfig) {
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
	// setupWithPolicies also hands back the bucket DID and the policy store, so a
	// subtest can grant the principal actions on the bucket the request
	// addresses.
	setupWithPolicies := func(t *testing.T, accessKey multikey.Issuer, setupConfig *setupConfig) (*auth.Authorizer, *providermemory.Store, did.DID, did.DID, *bucketpolicymemory.Store) {
		t.Helper()
		accessKeys, tenants := accesskeymemory.New(), tenantmemory.New()
		providers, buckets, secrets := providermemory.New(), bucketmemory.New(), vaultmemory.New()
		principals, policies := principalmemory.New(), bucketpolicymemory.New()
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
		if setupConfig != nil && setupConfig.principalBound {
			require.NoError(t, principals.Add(ctx, tenantID, "user-1"))
		}
		seedKey(t, accessKeys, secrets, accessKey, tenantID, setupConfig)
		return auth.NewAuthorizer(zap.NewNop(), accessKeys, tenants, providers, buckets, principals, policies, secrets),
			providers, tenantID, bucketID, policies
	}

	setup := func(t *testing.T, accessKey multikey.Issuer, setupConfig *setupConfig) (*auth.Authorizer, *providermemory.Store, did.DID) {
		az, providers, tenantID, _, _ := setupWithPolicies(t, accessKey, setupConfig)
		return az, providers, tenantID
	}

	// grant stores a policy on the bucket. statements are applied as given.
	grant := func(t *testing.T, policies *bucketpolicymemory.Store, bucketID, tenantID did.DID, statements ...bucketpolicy.Statement) {
		t.Helper()
		_, err := policies.Put(ctx, bucketpolicystore.Input{
			Bucket: bucketID,
			Tenant: tenantID,
			Policy: bucketpolicy.Policy{Statements: statements},
		}, nil)
		require.NoError(t, err)
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
		// A service key holds its own permission set.
		require.Equal(t, []string{"s3:GetObject"}, authz.Permissions)
		require.Nil(t, authz.Principal)
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
		az, _, tenantID, bucketID, policies := setupWithPolicies(t, accessKey, &setupConfig{principalBound: true})
		grant(t, policies, bucketID, tenantID, bucketpolicy.Statement{
			Effect:     bucketpolicy.Allow,
			Principals: []string{"user-1"},
			Actions:    []string{"s3:GetObject", "s3:ListBucket"},
		})

		authz, err := az.Authorize(ctx, providerID, signedObjectRequest(t, accessKey, "bucket", region))
		require.NoError(t, err)
		require.NotNil(t, authz.Principal)
		require.Equal(t, "user-1", *authz.Principal)
		require.Equal(t, []string{"s3:GetObject", "s3:ListBucket"}, authz.Permissions)
		require.NotNil(t, authz.Bucket)
		require.Equal(t, bucketID, authz.Bucket.ID)
	})

	t.Run("a Deny wins over an Allow naming the same action", func(t *testing.T) {
		az, _, tenantID, bucketID, policies := setupWithPolicies(t, accessKey, &setupConfig{principalBound: true})
		grant(t, policies, bucketID, tenantID,
			bucketpolicy.Statement{Effect: bucketpolicy.Allow, Principals: []string{bucketpolicy.Wildcard}, Actions: []string{"s3:GetObject", "s3:ListBucket"}},
			bucketpolicy.Statement{Effect: bucketpolicy.Deny, Principals: []string{"user-1"}, Actions: []string{"s3:GetObject"}},
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

		az, _, tenantID, bucketID, policies := setupWithPolicies(t, accessKey, &setupConfig{principalBound: true})
		grant(t, policies, bucketID, tenantID,
			bucketpolicy.Statement{Effect: bucketpolicy.Allow, Principals: []string{"user-1"}, Actions: []string{"s3:GetObject"}},
			bucketpolicy.Statement{Effect: bucketpolicy.Deny, Principals: []string{"user-1"}, Actions: []string{"s3:GetObject"}},
		)
		_, err = az.Authorize(ctx, providerID, signedObjectRequest(t, accessKey, "bucket", region))
		require.ErrorIs(t, err, auth.ErrUnknownBucket)
	})

	t.Run("a principal-bound key may not create or delete a bucket", func(t *testing.T) {
		az, _, tenantID, bucketID, policies := setupWithPolicies(t, accessKey, &setupConfig{principalBound: true})
		grant(t, policies, bucketID, tenantID, bucketpolicy.Statement{
			Effect:     bucketpolicy.Allow,
			Principals: []string{"user-1"},
			Actions:    []string{"s3:GetObject"},
		})
		secret, err := multibase.Encode(multibase.Base64url, accessKey.Bytes())
		require.NoError(t, err)

		for _, req := range []sigv4.Request{
			{Method: "PUT", URL: "https://s3.fil.one/bucket"},
			{Method: "DELETE", URL: "https://s3.fil.one/bucket"},
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
		allow := func(actions ...string) bucketpolicy.Statement {
			return bucketpolicy.Statement{Effect: bucketpolicy.Allow, Principals: []string{"user-1"}, Actions: actions}
		}

		t.Run("the source's policy grants the read", func(t *testing.T) {
			az, _, tenantID, bucketID, policies := setupWithPolicies(t, accessKey, &setupConfig{principalBound: true})
			grant(t, policies, bucket2ID, tenantID, allow("s3:PutObject"))
			grant(t, policies, bucketID, tenantID, allow("s3:GetObject"))

			authz, err := az.Authorize(ctx, providerID, signedCopyRequest(t, accessKey, "bucket2", "bucket", region, true))
			require.NoError(t, err)
			require.Equal(t, auth.OpCopyObject, authz.Operation)
			require.Equal(t, bucket2ID, authz.Bucket.ID)
			require.Equal(t, "bucket", authz.SourceBucketName)
			require.NotNil(t, authz.SourceBucket)
			require.Equal(t, bucketID, authz.SourceBucket.ID)
		})

		t.Run("the source's policy grants everything but the read", func(t *testing.T) {
			az, _, tenantID, bucketID, policies := setupWithPolicies(t, accessKey, &setupConfig{principalBound: true})
			grant(t, policies, bucket2ID, tenantID, allow("s3:PutObject", "s3:GetObject"))
			grant(t, policies, bucketID, tenantID, allow("s3:ListBucket"))

			_, err := az.Authorize(ctx, providerID, signedCopyRequest(t, accessKey, "bucket2", "bucket", region, true))
			require.ErrorIs(t, err, auth.ErrOperationNotPermitted)
		})

		t.Run("the read on the destination does not carry to the source", func(t *testing.T) {
			// Holding the read on the destination is what a copy of an object
			// already in the bucket needs; it says nothing about another bucket.
			az, _, tenantID, _, policies := setupWithPolicies(t, accessKey, &setupConfig{principalBound: true})
			grant(t, policies, bucket2ID, tenantID, allow("s3:PutObject", "s3:GetObject"))

			_, err := az.Authorize(ctx, providerID, signedCopyRequest(t, accessKey, "bucket2", "bucket", region, true))
			// No policy on the source, so it is not a bucket the principal may
			// learn exists.
			require.ErrorIs(t, err, auth.ErrUnknownBucket)
		})

		t.Run("a copy within one bucket needs both actions there", func(t *testing.T) {
			az, _, tenantID, bucketID, policies := setupWithPolicies(t, accessKey, &setupConfig{principalBound: true})
			grant(t, policies, bucketID, tenantID, allow("s3:PutObject"))
			_, err := az.Authorize(ctx, providerID, signedCopyRequest(t, accessKey, "bucket", "bucket", region, true))
			require.ErrorIs(t, err, auth.ErrOperationNotPermitted)

			az, _, tenantID, bucketID, policies = setupWithPolicies(t, accessKey, &setupConfig{principalBound: true})
			grant(t, policies, bucketID, tenantID, allow("s3:PutObject", "s3:GetObject"))
			authz, err := az.Authorize(ctx, providerID, signedCopyRequest(t, accessKey, "bucket", "bucket", region, true))
			require.NoError(t, err)
			require.Same(t, authz.Bucket, authz.SourceBucket)
		})

		t.Run("a copy from another tenant's bucket is refused before any policy", func(t *testing.T) {
			az, _, tenantID, _, policies := setupWithPolicies(t, accessKey, &setupConfig{principalBound: true})
			grant(t, policies, bucket2ID, tenantID, allow("s3:PutObject", "s3:GetObject"))

			_, err := az.Authorize(ctx, providerID, signedCopyRequest(t, accessKey, "bucket2", "theirs", region, true))
			require.ErrorIs(t, err, auth.ErrForeignBucket)
		})

		t.Run("an unsigned source header is refused for a principal too", func(t *testing.T) {
			az, _, tenantID, bucketID, policies := setupWithPolicies(t, accessKey, &setupConfig{principalBound: true})
			grant(t, policies, bucket2ID, tenantID, allow("s3:PutObject"))
			grant(t, policies, bucketID, tenantID, allow("s3:GetObject"))

			_, err := az.Authorize(ctx, providerID, signedCopyRequest(t, accessKey, "bucket2", "bucket", region, false))
			require.ErrorIs(t, err, auth.ErrUnsignedCopySource)
		})
	})

	t.Run("a principal-bound key whose principal is gone is an unknown key", func(t *testing.T) {
		// Seed a key bound to a principal the tenant does not have: what a removal
		// leaves behind for the moment before it deletes the key.
		accessKeys, tenants := accesskeymemory.New(), tenantmemory.New()
		providers, buckets, secrets := providermemory.New(), bucketmemory.New(), vaultmemory.New()
		require.NoError(t, providers.Add(ctx, providerID, region, nil))
		tenantID := testutil.RandomDID(t)
		require.NoError(t, tenants.Add(ctx, tenantID, "tenant-1", providerID, tenant.Active))
		require.NoError(t, buckets.Add(ctx, testutil.RandomDID(t), tenantID, "bucket"))
		seedKey(t, accessKeys, secrets, accessKey, tenantID, &setupConfig{principalBound: true})
		gone := auth.NewAuthorizer(zap.NewNop(), accessKeys, tenants, providers, buckets,
			principalmemory.New(), bucketpolicymemory.New(), secrets)

		_, err := gone.Authorize(ctx, providerID, signedObjectRequest(t, accessKey, "bucket", region))
		require.ErrorIs(t, err, auth.ErrUnknownAccessKey)
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
		require.NoError(t, accessKeys.Add(ctx, accesskey.Input{ID: accessKey.DID(), Tenant: tenantID, Name: "k1", Permissions: []string{"s3:GetObject"}}))
		require.NoError(t, secrets.Write(ctx, vault.AccessKeyPath(tenantID, accessKey.DID()), other.Bytes()))
		az := auth.NewAuthorizer(zap.NewNop(), accessKeys, tenants, providers, bucketmemory.New(), principalmemory.New(), bucketpolicymemory.New(), secrets)

		_, err = az.Authorize(ctx, providerID, signedRequest(t, accessKey, region, time.Now(), time.Hour))
		require.ErrorIs(t, err, auth.ErrSignatureMismatch)
	})

	t.Run("rejects an unsigned request", func(t *testing.T) {
		az, _, _ := setup(t, accessKey, nil)
		_, err := az.Authorize(ctx, providerID, s3.Request{Method: "GET", URL: "https://s3.fil.one/bucket/object-key"})
		require.ErrorIs(t, err, auth.ErrMalformedSignature)
	})

	t.Run("rejects an unknown access key", func(t *testing.T) {
		az := auth.NewAuthorizer(zap.NewNop(), accesskeymemory.New(), tenantmemory.New(), providermemory.New(), bucketmemory.New(), principalmemory.New(), bucketpolicymemory.New(), vaultmemory.New())
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
		require.NoError(t, accessKeys.Add(ctx, accesskey.Input{ID: accessKey.DID(), Tenant: tenantID, Name: "k1", Permissions: []string{"s3:GetObject"}}))
		az := auth.NewAuthorizer(zap.NewNop(), accessKeys, tenants, providers, bucketmemory.New(), principalmemory.New(), bucketpolicymemory.New(), secrets)

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

// lockedAccessKeys, lockedPrincipals and lockedPolicies fail every Get with
// err, standing in for a share-locked read the store gave up on behind a write
// still holding the row.
type lockedAccessKeys struct {
	accesskey.Store
	err error
}

func (l *lockedAccessKeys) Get(context.Context, did.DID, ...store.ReadOption) (accesskey.Record, error) {
	return accesskey.Record{}, l.err
}

type lockedPrincipals struct {
	principalstore.Store
	err error
}

func (l *lockedPrincipals) Get(context.Context, did.DID, string, ...store.ReadOption) (principalstore.Record, error) {
	return principalstore.Record{}, l.err
}

type lockedPolicies struct {
	bucketpolicystore.Store
	err error
}

func (l *lockedPolicies) Get(context.Context, did.DID, ...store.ReadOption) (bucketpolicystore.Record, error) {
	return bucketpolicystore.Record{}, l.err
}

// TestAuthorizeLockTimeout pins that a share-locked read the store gave up on
// is the named, retryable failure rather than an internal error, at each of
// the three reads that take the lock.
func TestAuthorizeLockTimeout(t *testing.T) {
	ctx := t.Context()
	const region = "us-west-2"
	providerID := testutil.RandomDID(t)
	accessKey, err := ed25519.GenerateIssuer()
	require.NoError(t, err)

	accessKeys, tenants := accesskeymemory.New(), tenantmemory.New()
	providers, buckets, secrets := providermemory.New(), bucketmemory.New(), vaultmemory.New()
	principals, policies := principalmemory.New(), bucketpolicymemory.New()
	require.NoError(t, providers.Add(ctx, providerID, region, nil))
	tenantID := testutil.RandomDID(t)
	require.NoError(t, tenants.Add(ctx, tenantID, "tenant-1", providerID, tenant.Active))
	bucketID := testutil.RandomDID(t)
	require.NoError(t, buckets.Add(ctx, bucketID, tenantID, "bucket"))
	require.NoError(t, principals.Add(ctx, tenantID, "user-1"))
	seedKey(t, accessKeys, secrets, accessKey, tenantID, &setupConfig{principalBound: true})
	_, err = policies.Put(ctx, bucketpolicystore.Input{Bucket: bucketID, Tenant: tenantID, Policy: bucketpolicy.Policy{
		Statements: []bucketpolicy.Statement{{Effect: bucketpolicy.Allow, Principals: []string{"user-1"}, Actions: []string{"s3:GetObject"}}},
	}}, nil)
	require.NoError(t, err)

	// With every read answered, the request is authorized.
	az := auth.NewAuthorizer(zap.NewNop(), accessKeys, tenants, providers, buckets, principals, policies, secrets)
	_, err = az.Authorize(ctx, providerID, signedObjectRequest(t, accessKey, "bucket", region))
	require.NoError(t, err)

	timeout := store.ErrLockTimeout
	cases := map[string]*auth.Authorizer{
		"access key":    auth.NewAuthorizer(zap.NewNop(), &lockedAccessKeys{accessKeys, timeout}, tenants, providers, buckets, principals, policies, secrets),
		"principal":     auth.NewAuthorizer(zap.NewNop(), accessKeys, tenants, providers, buckets, &lockedPrincipals{principals, timeout}, policies, secrets),
		"bucket policy": auth.NewAuthorizer(zap.NewNop(), accessKeys, tenants, providers, buckets, principals, &lockedPolicies{policies, timeout}, secrets),
	}
	for name, az := range cases {
		t.Run(name+" read waited out the lock timeout", func(t *testing.T) {
			_, err := az.Authorize(ctx, providerID, signedObjectRequest(t, accessKey, "bucket", region))
			require.ErrorIs(t, err, auth.ErrTemporarilyUnavailable)
			require.ErrorIs(t, err, store.ErrLockTimeout, "the failure must carry the store's timeout")
		})
	}
}

func TestTenantIssuer(t *testing.T) {
	ctx := t.Context()
	buckets, secrets := bucketmemory.New(), vaultmemory.New()
	az := auth.NewAuthorizer(zap.NewNop(), accesskeymemory.New(), tenantmemory.New(), providermemory.New(), buckets, principalmemory.New(), bucketpolicymemory.New(), secrets)

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
