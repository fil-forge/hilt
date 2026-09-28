package bucket_test

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"testing"
	"time"

	htestutil "github.com/fil-forge/hilt/internal/testutil"
	bucketpolicysvc "github.com/fil-forge/hilt/pkg/api/service/bucketpolicy"
	"github.com/fil-forge/hilt/pkg/bucketpolicy"
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
// PUT body covered by the signature and the preconditions as signed headers.
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
		svc      *bucketsvc.Service
		policies *bucketpolicymemory.Store
		bucketID did.DID
	}
	// setup seeds the tenant, the photos bucket, principal user-1 with one
	// key, and akSigner as a service key holding perms (or bound to user-1).
	setup := func(t *testing.T, perms []string, principalBound bool) fixture {
		t.Helper()
		accessKeys, tenants, buckets := accesskeymemory.New(), tenantmemory.New(), bucketmemory.New()
		providers, secrets, delegations := providermemory.New(), vaultmemory.New(), delegationmemory.New()
		principals, policies := principalmemory.New(), bucketpolicymemory.New()
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
		return fixture{bucketsvc.New(zap.NewNop(), az, buckets, delegations, accessKeys, tenants, policies, &fakeSprue{}, swarf, policyWrites), policies, bucketID}
	}

	type reqOpts struct {
		headers      map[string]string // sent with the request
		unsigned     []string          // headers sent but left out of the signature
		body         []byte
		unsignedBody bool   // sign with UNSIGNED-PAYLOAD
		signedBody   []byte // when set, the signature covers this body instead
		bucket       string
	}
	// request presigns a policy operation on the bucket. The body is covered
	// by the signature unless unsignedBody is set; every header is signed
	// unless listed in unsigned.
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
			signed := true
			for _, u := range o.unsigned {
				if u == name {
					signed = false
				}
			}
			if signed {
				opts = append(opts, sigv4.WithSignedHeaders(name))
			}
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
	encode := func(t *testing.T, doc bucketpolicy.Policy) []byte {
		t.Helper()
		raw, err := json.Marshal(doc)
		require.NoError(t, err)
		return raw
	}
	read := bucketpolicy.Policy{Statements: []bucketpolicy.Statement{
		{Effect: bucketpolicy.Allow, Principal: bucketpolicy.Only("user-1"), Actions: []string{"s3:GetObject"}},
	}}
	write := bucketpolicy.Policy{Statements: []bucketpolicy.Statement{
		{Effect: bucketpolicy.Allow, Principal: bucketpolicy.Only("user-1"), Actions: []string{"s3:PutObject"}},
	}}

	t.Run("a PUT without a precondition creates the policy and returns its ETag", func(t *testing.T) {
		f := setup(t, policyPerms, false)
		ok, err := f.svc.Policy(ctx, providerID, request(t, "PUT", reqOpts{body: encode(t, read)}))
		require.NoError(t, err)
		require.Equal(t, bucketpolicy.ETag(read), ok.ETag)
		require.Empty(t, ok.Policy)
		stored, err := f.policies.Get(ctx, f.bucketID)
		require.NoError(t, err)
		require.Equal(t, read, stored.Policy)
	})

	t.Run("a GET returns the canonical document and its ETag", func(t *testing.T) {
		f := setup(t, policyPerms, false)
		_, err := f.svc.Policy(ctx, providerID, request(t, "PUT", reqOpts{body: encode(t, read)}))
		require.NoError(t, err)
		ok, err := f.svc.Policy(ctx, providerID, request(t, "GET", reqOpts{}))
		require.NoError(t, err)
		require.Equal(t, bucketpolicy.ETag(read), ok.ETag)
		require.Equal(t, bucketpolicy.Canonical(read), ok.Policy)
	})

	t.Run("a PUT without a precondition replaces whatever is stored", func(t *testing.T) {
		f := setup(t, policyPerms, false)
		_, err := f.svc.Policy(ctx, providerID, request(t, "PUT", reqOpts{body: encode(t, read)}))
		require.NoError(t, err)
		ok, err := f.svc.Policy(ctx, providerID, request(t, "PUT", reqOpts{body: encode(t, write)}))
		require.NoError(t, err)
		require.Equal(t, bucketpolicy.ETag(write), ok.ETag)
	})

	t.Run("If-Match replaces on the current tag and is refused on a stale one", func(t *testing.T) {
		f := setup(t, policyPerms, false)
		first, err := f.svc.Policy(ctx, providerID, request(t, "PUT", reqOpts{body: encode(t, read)}))
		require.NoError(t, err)
		_, err = f.svc.Policy(ctx, providerID, request(t, "PUT", reqOpts{body: encode(t, write), headers: map[string]string{"If-Match": `"stale"`}}))
		require.ErrorIs(t, err, bucketpolicysvc.ErrPreconditionFailed)
		ok, err := f.svc.Policy(ctx, providerID, request(t, "PUT", reqOpts{body: encode(t, write), headers: map[string]string{"If-Match": first.ETag}}))
		require.NoError(t, err)
		require.Equal(t, bucketpolicy.ETag(write), ok.ETag)
	})

	t.Run("If-None-Match: * creates only the first policy", func(t *testing.T) {
		f := setup(t, policyPerms, false)
		create := map[string]string{"If-None-Match": "*"}
		_, err := f.svc.Policy(ctx, providerID, request(t, "PUT", reqOpts{body: encode(t, read), headers: create}))
		require.NoError(t, err)
		_, err = f.svc.Policy(ctx, providerID, request(t, "PUT", reqOpts{body: encode(t, write), headers: create}))
		require.ErrorIs(t, err, bucketpolicysvc.ErrPreconditionFailed)
	})

	t.Run("a precondition the signature does not cover, both at once, or another If-None-Match is invalid", func(t *testing.T) {
		f := setup(t, policyPerms, false)
		for name, o := range map[string]reqOpts{
			"unsigned If-Match":      {headers: map[string]string{"If-Match": `"x"`}, unsigned: []string{"If-Match"}},
			"both headers":           {headers: map[string]string{"If-Match": `"x"`, "If-None-Match": "*"}},
			"If-None-Match not star": {headers: map[string]string{"If-None-Match": `"x"`}},
		} {
			o.body = encode(t, read)
			_, err := f.svc.Policy(ctx, providerID, request(t, "PUT", o))
			require.ErrorIs(t, err, bucketpolicysvc.ErrInvalidPrecondition, name)
		}
		_, err := f.policies.Get(ctx, f.bucketID)
		require.Error(t, err, "nothing was written")
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
		unknown := bucketpolicy.Policy{Statements: []bucketpolicy.Statement{
			{Effect: bucketpolicy.Allow, Principal: bucketpolicy.Only("nobody"), Actions: []string{"s3:GetObject"}},
		}}
		_, err := f.svc.Policy(ctx, providerID, request(t, "PUT", reqOpts{body: encode(t, unknown)}))
		require.ErrorIs(t, err, bucketpolicy.ErrInvalidPolicy)
		_, err = f.svc.Policy(ctx, providerID, request(t, "PUT", reqOpts{body: []byte(`{"Version": "2012-10-17"}`)}))
		require.ErrorIs(t, err, bucketpolicy.ErrInvalidPolicy)
	})

	t.Run("a DELETE removes the policy, conditionally or not, and a bucket without one is PolicyNotFound", func(t *testing.T) {
		f := setup(t, policyPerms, false)
		_, err := f.svc.Policy(ctx, providerID, request(t, "DELETE", reqOpts{}))
		require.ErrorIs(t, err, bucketpolicysvc.ErrPolicyNotFound)

		first, err := f.svc.Policy(ctx, providerID, request(t, "PUT", reqOpts{body: encode(t, read)}))
		require.NoError(t, err)
		_, err = f.svc.Policy(ctx, providerID, request(t, "DELETE", reqOpts{headers: map[string]string{"If-Match": `"stale"`}}))
		require.ErrorIs(t, err, bucketpolicysvc.ErrPreconditionFailed)
		_, err = f.svc.Policy(ctx, providerID, request(t, "DELETE", reqOpts{headers: map[string]string{"If-None-Match": "*"}}))
		require.ErrorIs(t, err, bucketpolicysvc.ErrInvalidPrecondition)
		ok, err := f.svc.Policy(ctx, providerID, request(t, "DELETE", reqOpts{headers: map[string]string{"If-Match": first.ETag}}))
		require.NoError(t, err)
		require.Empty(t, ok.ETag)

		_, err = f.svc.Policy(ctx, providerID, request(t, "PUT", reqOpts{body: encode(t, read)}))
		require.NoError(t, err)
		_, err = f.svc.Policy(ctx, providerID, request(t, "DELETE", reqOpts{}))
		require.NoError(t, err)
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
	})
}
