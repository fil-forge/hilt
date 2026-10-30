package bucket_test

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"testing"
	"time"

	htestutil "github.com/fil-forge/hilt/internal/testutil"
	bucketpolicysvc "github.com/fil-forge/hilt/pkg/api/service/bucketpolicy"
	"github.com/fil-forge/hilt/pkg/grant"
	"github.com/fil-forge/hilt/pkg/rpc/service/auth"
	bucketsvc "github.com/fil-forge/hilt/pkg/rpc/service/bucket"
	"github.com/fil-forge/hilt/pkg/sigv4"
	accesskeymemory "github.com/fil-forge/hilt/pkg/store/accesskey/memory"
	bucketmemory "github.com/fil-forge/hilt/pkg/store/bucket/memory"
	bucketpolicymemory "github.com/fil-forge/hilt/pkg/store/bucketpolicy/memory"
	delegationmemory "github.com/fil-forge/hilt/pkg/store/delegation/memory"
	principalmemory "github.com/fil-forge/hilt/pkg/store/principal/memory"
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
	"github.com/fil-forge/ucantone/multikey/secp256k1"
	"github.com/multiformats/go-multibase"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

// TestPolicy covers /s3/bucket/policy: the three S3 bucket policy operations,
// reached with a service key holding the operation's permission, with the
// PUT body covered by the signature.
func TestPolicy(t *testing.T) {
	ctx := t.Context()
	const region, bucketName = "us-west-2", "photos"
	policyPerms := []string{"s3:GetBucketPolicy", "s3:PutBucketPolicy", "s3:DeleteBucketPolicy", "s3:GetObject"}

	akSigner, err := ed25519.Generate()
	require.NoError(t, err)
	tenantSigner, err := secp256k1.Generate()
	require.NoError(t, err)
	tenantID := tenantSigner.KeyDID()
	providerID := testutil.RandomDID(t)

	type fixture struct {
		svc        *bucketsvc.Service
		policies   *bucketpolicymemory.Store
		bucketID   did.DID
		bucketGone *bool // the policy store's view of the bucket, for a delete racing a write
	}
	// setup seeds the tenant, the photos bucket, principal user-1 with one
	// key, and akSigner as a service key holding perms (or bound to user-1).
	setup := func(t *testing.T, perms []string, principalBound bool) fixture {
		t.Helper()
		accessKeys, tenants, buckets := accesskeymemory.New(), tenantmemory.New(), bucketmemory.New()
		providers, secrets, delegations := providermemory.New(), vaultmemory.New(), delegationmemory.New()
		bucketGone := new(bool)
		principals := principalmemory.New()
		policies := bucketpolicymemory.New(bucketpolicymemory.WithBuckets(func(did.DID) bool { return !*bucketGone }))
		require.NoError(t, providers.Add(ctx, providerID, region, nil))
		require.NoError(t, tenants.Add(ctx, tenantID, "tenant-1", providerID, tenant.Active))
		if !principalBound { // seedKey adds user-1 itself for a bound key
			require.NoError(t, principals.Add(ctx, tenantID, "user-1"))
		}
		bucketID := testutil.RandomDID(t)
		require.NoError(t, buckets.Add(ctx, bucketID, tenantID, bucketName))
		seedKey(t, accessKeys, secrets, delegations, principals, akSigner, tenantID, perms, principalBound)
		require.NoError(t, secrets.Write(ctx, vault.TenantKeyPath(tenantID), tenantSigner.Bytes()))
		az := auth.NewAuthorizer(zap.NewNop(), accessKeys, tenants, providers, buckets, principals, policies, secrets)
		swarf := &htestutil.FakeSwarf{}
		grants := grant.NewRotator(zap.NewNop(), delegations, accessKeys, secrets, swarf)
		policyWrites := bucketpolicysvc.New(zap.NewNop(), tenants, buckets, principals, policies, grants)
		return fixture{bucketsvc.New(zap.NewNop(), az, buckets, delegations, accessKeys, tenants, policies, &fakeSprue{}, swarf, policyWrites), policies, bucketID, bucketGone}
	}

	type reqOpts struct {
		headers      map[string]string // sent with the request
		body         []byte
		unsignedBody bool   // sign with UNSIGNED-PAYLOAD
		signedBody   []byte // when set, the signature covers this body instead
		bucket       string
	}
	// request presigns a policy operation on the bucket. The body is covered
	// by the signature unless unsignedBody is set; every header is signed.
	request := func(t *testing.T, method string, o reqOpts) *s3bkt.PolicyArguments {
		t.Helper()
		secret, err := multibase.Encode(multibase.Base64url, akSigner.Bytes())
		require.NoError(t, err)
		bucket := bucketName
		if o.bucket != "" {
			bucket = o.bucket
		}
		var opts []sigv4.PresignOption
		for name := range o.headers {
			opts = append(opts, sigv4.WithSignedHeaders(name))
		}
		if !o.unsignedBody {
			signed := o.body
			if o.signedBody != nil {
				signed = o.signedBody
			}
			sum := sha256.Sum256(signed)
			opts = append(opts, sigv4.WithPayloadHash(hex.EncodeToString(sum[:])))
		}
		req := sigv4.Request{Method: method, URL: "https://s3.fil.one/" + bucket + "?policy", Headers: o.headers}
		signed, err := sigv4.Presign(req, akSigner.KeyDID().Identifier(), secret, region, sigv4.SchemeV4, time.Now(), time.Hour, opts...)
		require.NoError(t, err)
		return &s3bkt.PolicyArguments{Request: s3.Request{Method: signed.Method, URL: signed.URL, Headers: o.headers}, Body: o.body}
	}
	encode := func(t *testing.T, doc s3bkt.PolicyDocument) []byte {
		t.Helper()
		raw, err := json.Marshal(doc)
		require.NoError(t, err)
		return raw
	}
	read := s3bkt.PolicyDocument{Version: s3bkt.Version2012, Statements: []s3bkt.Statement{
		{Effect: s3bkt.Allow, Principal: s3bkt.Only("user-1"), Actions: s3bkt.NewStringSet("s3:GetObject"), Resources: s3bkt.NewStringSet(s3bkt.BucketARN("photos"), s3bkt.ObjectsARN("photos"))},
	}}
	write := s3bkt.PolicyDocument{Version: s3bkt.Version2012, Statements: []s3bkt.Statement{
		{Effect: s3bkt.Allow, Principal: s3bkt.Only("user-1"), Actions: s3bkt.NewStringSet("s3:PutObject"), Resources: s3bkt.NewStringSet(s3bkt.BucketARN("photos"), s3bkt.ObjectsARN("photos"))},
	}}

	t.Run("a PUT stores the policy on a bucket without one", func(t *testing.T) {
		f := setup(t, policyPerms, false)
		ok, err := f.svc.Policy(ctx, providerID, request(t, "PUT", reqOpts{body: encode(t, read)}))
		require.NoError(t, err)
		require.Equal(t, &s3bkt.PolicyOK{}, ok)
		stored, err := f.policies.Get(ctx, f.bucketID)
		require.NoError(t, err)
		require.Equal(t, read, stored.Policy)
	})

	t.Run("a GET returns the canonical document", func(t *testing.T) {
		f := setup(t, policyPerms, false)
		_, err := f.svc.Policy(ctx, providerID, request(t, "PUT", reqOpts{body: encode(t, read)}))
		require.NoError(t, err)
		ok, err := f.svc.Policy(ctx, providerID, request(t, "GET", reqOpts{}))
		require.NoError(t, err)
		require.Equal(t, &read, ok.Policy)
	})

	t.Run("a PUT replaces the stored policy", func(t *testing.T) {
		f := setup(t, policyPerms, false)
		_, err := f.svc.Policy(ctx, providerID, request(t, "PUT", reqOpts{body: encode(t, read)}))
		require.NoError(t, err)
		_, err = f.svc.Policy(ctx, providerID, request(t, "PUT", reqOpts{body: encode(t, write)}))
		require.NoError(t, err)
		stored, err := f.policies.Get(ctx, f.bucketID)
		require.NoError(t, err)
		require.Equal(t, write, stored.Policy)
	})

	// Writes are unconditional, as on AWS: a conditional header neither
	// guards the write nor makes it invalid.
	t.Run("a PUT replaces the stored policy whatever conditional header it carries", func(t *testing.T) {
		for name, headers := range map[string]map[string]string{
			"If-Match with any tag": {"If-Match": `"any-tag"`},
			"If-None-Match: *":      {"If-None-Match": "*"},
		} {
			t.Run(name, func(t *testing.T) {
				f := setup(t, policyPerms, false)
				_, err := f.svc.Policy(ctx, providerID, request(t, "PUT", reqOpts{body: encode(t, read)}))
				require.NoError(t, err)
				_, err = f.svc.Policy(ctx, providerID, request(t, "PUT", reqOpts{body: encode(t, write), headers: headers}))
				require.NoError(t, err)
				stored, err := f.policies.Get(ctx, f.bucketID)
				require.NoError(t, err)
				require.Equal(t, write, stored.Policy)
			})
		}
	})

	t.Run("a PUT whose body the signature does not cover, or does not match, is a signature mismatch", func(t *testing.T) {
		f := setup(t, policyPerms, false)
		_, err := f.svc.Policy(ctx, providerID, request(t, "PUT", reqOpts{body: encode(t, read), unsignedBody: true}))
		require.ErrorIs(t, err, auth.ErrSignatureMismatch)
		_, err = f.svc.Policy(ctx, providerID, request(t, "PUT", reqOpts{body: encode(t, read), signedBody: encode(t, write)}))
		require.ErrorIs(t, err, auth.ErrSignatureMismatch)
	})

	t.Run("a document the tenant may not store is refused", func(t *testing.T) {
		f := setup(t, policyPerms, false)
		unknown := s3bkt.PolicyDocument{Version: s3bkt.Version2012, Statements: []s3bkt.Statement{
			{Effect: s3bkt.Allow, Principal: s3bkt.Only("nobody"), Actions: s3bkt.NewStringSet("s3:GetObject"), Resources: s3bkt.NewStringSet(s3bkt.BucketARN("photos"), s3bkt.ObjectsARN("photos"))},
		}}
		_, err := f.svc.Policy(ctx, providerID, request(t, "PUT", reqOpts{body: encode(t, unknown)}))
		require.ErrorIs(t, err, s3bkt.ErrInvalidPolicy)
		_, err = f.svc.Policy(ctx, providerID, request(t, "PUT", reqOpts{body: []byte(`{"Version": "2012-10-17"}`)}))
		require.ErrorIs(t, err, s3bkt.ErrInvalidPolicy)
	})

	t.Run("a DELETE on a bucket without a policy is PolicyNotFound", func(t *testing.T) {
		f := setup(t, policyPerms, false)
		_, err := f.svc.Policy(ctx, providerID, request(t, "DELETE", reqOpts{}))
		require.ErrorIs(t, err, bucketpolicysvc.ErrPolicyNotFound)
	})

	t.Run("a DELETE removes the stored policy", func(t *testing.T) {
		f := setup(t, policyPerms, false)
		_, err := f.svc.Policy(ctx, providerID, request(t, "PUT", reqOpts{body: encode(t, read)}))
		require.NoError(t, err)
		ok, err := f.svc.Policy(ctx, providerID, request(t, "DELETE", reqOpts{}))
		require.NoError(t, err)
		require.Equal(t, &s3bkt.PolicyOK{}, ok)
		_, err = f.svc.Policy(ctx, providerID, request(t, "GET", reqOpts{}))
		require.ErrorIs(t, err, bucketpolicysvc.ErrPolicyNotFound)
	})

	t.Run("a principal-bound key and a service key without the permission are refused", func(t *testing.T) {
		f := setup(t, nil, true)
		_, err := f.svc.Policy(ctx, providerID, request(t, "GET", reqOpts{}))
		require.ErrorIs(t, err, auth.ErrOperationNotPermitted)

		f = setup(t, []string{"s3:GetBucketPolicy"}, false)
		_, err = f.svc.Policy(ctx, providerID, request(t, "PUT", reqOpts{body: encode(t, read)}))
		require.ErrorIs(t, err, auth.ErrOperationNotPermitted)
	})

	t.Run("a bucket that does not exist is UnknownBucket", func(t *testing.T) {
		f := setup(t, policyPerms, false)
		_, err := f.svc.Policy(ctx, providerID, request(t, "GET", reqOpts{bucket: "nowhere"}))
		require.ErrorIs(t, err, auth.ErrUnknownBucket)

		f = setup(t, policyPerms, false)
		*f.bucketGone = true
		_, err = f.svc.Policy(ctx, providerID, request(t, "PUT", reqOpts{body: encode(t, read)}))
		require.ErrorIs(t, err, bucketsvc.ErrUnknownBucket, "a bucket deleted between Authorize and the write")
	})
}
