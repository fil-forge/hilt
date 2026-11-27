package rpc_test

import (
	"slices"
	"testing"
	"time"

	s3bkt "github.com/fil-forge/libforge/commands/s3/bucket"
	"github.com/jackc/pgx/v5/pgxpool"

	htestutil "github.com/fil-forge/hilt/internal/testutil"
	"github.com/fil-forge/hilt/pkg/grant"
	"github.com/fil-forge/hilt/pkg/rpc"
	"github.com/fil-forge/hilt/pkg/rpc/service/auth"
	"github.com/fil-forge/hilt/pkg/s3perm"
	"github.com/fil-forge/hilt/pkg/sigv4"
	"github.com/fil-forge/hilt/pkg/store/accesskey"
	accesskeypostgres "github.com/fil-forge/hilt/pkg/store/accesskey/postgres"
	bucketpostgres "github.com/fil-forge/hilt/pkg/store/bucket/postgres"
	bucketpolicypostgres "github.com/fil-forge/hilt/pkg/store/bucketpolicy/postgres"
	delegationstore "github.com/fil-forge/hilt/pkg/store/delegation"
	delegationpostgres "github.com/fil-forge/hilt/pkg/store/delegation/postgres"
	"github.com/fil-forge/hilt/pkg/store/pglock"
	principalpostgres "github.com/fil-forge/hilt/pkg/store/principal/postgres"
	providerpostgres "github.com/fil-forge/hilt/pkg/store/provider/postgres"
	"github.com/fil-forge/hilt/pkg/store/tenant"
	tenantpostgres "github.com/fil-forge/hilt/pkg/store/tenant/postgres"
	"github.com/fil-forge/hilt/pkg/vault"
	vaultmemory "github.com/fil-forge/hilt/pkg/vault/memory"
	"github.com/fil-forge/libforge/commands/blob"
	"github.com/fil-forge/libforge/commands/content"
	s3 "github.com/fil-forge/libforge/commands/s3"
	s3req "github.com/fil-forge/libforge/commands/s3/request"
	"github.com/fil-forge/libforge/testutil"
	"github.com/fil-forge/ucantone/did"
	"github.com/fil-forge/ucantone/multikey"
	"github.com/fil-forge/ucantone/multikey/ed25519"
	"github.com/fil-forge/ucantone/multikey/secp256k1"
	"github.com/fil-forge/ucantone/ucan"
	"github.com/fil-forge/ucantone/ucan/command"
	"github.com/fil-forge/ucantone/ucan/delegation"
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

// signedArgs builds AuthorizeArguments for a presigned request of any method
// and URL, for the shapes whose query parameters name the operation.
func signedArgs(t *testing.T, signer ed25519.Signer, method, url, region string) *s3req.AuthorizeArguments {
	t.Helper()
	secret, err := multibase.Encode(multibase.Base64url, signer.Bytes())
	require.NoError(t, err)
	signed, err := sigv4.Presign(sigv4.Request{Method: method, URL: url},
		signer.KeyDID().Identifier(), secret, region, sigv4.SchemeV4, time.Now(), time.Hour)
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
	srcSigner, err := ed25519.Generate()
	require.NoError(t, err)
	srcID := srcSigner.KeyDID()

	// The access key signs the request; its private key lives in the vault so the
	// handler can issue delegations as the access key.
	akSigner, err := ed25519.Generate()
	require.NoError(t, err)
	akDID := akSigner.KeyDID()
	// roots holds each bucket's root delegation, as bucket creation stores
	// it, by bucket.
	roots := map[did.DID]ucan.Delegation{}
	// issueGrants is grant.Issue, which the grant helper below shadows.
	issueGrants := grant.Issue

	// providerID serves the signing region and both buckets, so it is the only
	// legitimate invocation issuer. bucketID/tenantID are opaque DIDs — the handler no longer reads any
	// stored delegation chain.
	bucketSigner, err := ed25519.Generate()
	require.NoError(t, err)
	bucketID := bucketSigner.KeyDID()
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
	// principal of the tenant and the key holds its grants over the bucket.
	// Each opt adjusts the stored key before it is added.
	// storeFor is the delegation store each setup built its authorizer over.
	storeFor := map[*auth.Authorizer]delegationstore.Store{}
	setup := func(t *testing.T, perms []string, principalBound bool, vaultSigner ed25519.Signer, opts ...func(*accesskey.Input)) (*auth.Authorizer, *pgxpool.Pool) {
		t.Helper()
		pool := htestutil.PostgresOrSkip(t)
		accessKeys, tenants, buckets := accesskeypostgres.New(pool), tenantpostgres.New(pool), bucketpostgres.New(pool)
		providers, secrets := providerpostgres.New(pool), vaultmemory.New()
		principals, policies := principalpostgres.New(pool), bucketpolicypostgres.New(pool)
		dels := delegationpostgres.New(pool)

		require.NoError(t, providers.Add(ctx, providerID, region, nil))
		require.NoError(t, tenants.Add(ctx, tenantID, "tenant-1", tenant.Active))
		in := accesskey.Input{ID: akDID, Tenant: tenantID, Name: "k1", Permissions: perms}
		if principalBound {
			principal := "user-1"
			in = accesskey.Input{ID: akDID, Tenant: tenantID, Name: "k1", Principal: &principal}
			require.NoError(t, principals.Add(ctx, tenantID, principal))
			grants, err := grant.Issue(multikey.NewIssuer(tenantID, tenantSigner), akDID, []did.DID{bucketID}, []string{"s3:GetObject", "s3:ListBucket"}, nil)
			require.NoError(t, err)
			require.NoError(t, dels.PutBatch(ctx, grants))
		}
		for _, opt := range opts {
			opt(&in)
		}
		require.NoError(t, accessKeys.Add(ctx, in))
		require.NoError(t, secrets.Write(ctx, vault.AccessKeyPath(tenantID, akDID), vaultSigner.Bytes()))
		require.NoError(t, secrets.Write(ctx, vault.TenantKeyPath(tenantID), tenantSigner.Bytes()))
		require.NoError(t, buckets.Add(ctx, bucketID, tenantID, providerID, bucketName))
		require.NoError(t, buckets.Add(ctx, srcID, tenantID, providerID, srcName))
		// Each bucket's root delegation, as bucket creation stores it.
		for id, signer := range map[did.DID]ed25519.Signer{bucketID: bucketSigner, srcID: srcSigner} {
			root, err := delegation.Delegate(multikey.NewIssuer(id, signer), tenantID, id, command.Top(), delegation.WithNoExpiration())
			require.NoError(t, err)
			require.NoError(t, dels.PutBatch(ctx, []ucan.Delegation{root}))
			roots[id] = root
		}

		az := auth.NewAuthorizer(zap.NewNop(), accessKeys, tenants, providers, buckets, principals, policies, secrets,
			auth.WithSnapshots(pglock.NewSnapshots(pool)))
		storeFor[az] = dels
		return az, pool
	}

	// grant stores a policy allowing "user-1" the given actions on the bucket.
	grant := func(t *testing.T, pool *pgxpool.Pool, actions ...string) {
		t.Helper()
		htestutil.PutPolicy(t, pool, tenantID, bucketID, s3bkt.PolicyDocument{Version: s3bkt.Version2012, Statements: []s3bkt.Statement{{
			Effect:    s3bkt.Allow,
			Principal: s3bkt.Only("user-1"),
			Actions:   s3bkt.NewStringSet(actions...),
			Resources: s3bkt.NewStringSet(s3bkt.BucketARN("photos"), s3bkt.ObjectsARN("photos")),
		}}})
	}

	call := func(t *testing.T, authorizer *auth.Authorizer, issuer did.DID, args *s3req.AuthorizeArguments) (*s3req.AuthorizeOK, []ucan.Delegation, error) {
		t.Helper()
		return rpc.AuthorizeRequest(ctx, zap.NewNop(), authorizer, storeFor[authorizer], issuer, args)
	}

	t.Run("authorizes a validly-signed request and issues a delegation to the issuer", func(t *testing.T) {
		az, _ := setup(t, []string{"s3:GetObject"}, false, akSigner)
		args := signedGetArgs(t, akSigner, bucketName, region, time.Now(), time.Hour)

		ok, blocks, err := call(t, az, providerID, args)
		require.NoError(t, err)

		require.Equal(t, &bucketID, ok.Bucket)
		require.Nil(t, ok.SourceBucket, "only a copy names a source bucket")
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
		// can still enact requests signed just before the key's date rolls over,
		// plus the async overhang so work the request queued outlives it.
		skew := int64(sigv4.MaxClockSkew / time.Second)
		overhang := int64(rpc.AsyncOverhang / time.Second)
		require.Zero(t, (int64(*exp)-skew-overhang)%86400,
			"expiry should be a UTC midnight plus the max clock skew and the async overhang")
		require.Greater(t, int64(*exp), now)
		require.LessOrEqual(t, int64(*exp), now+86400+skew+overhang)
		// However late in the day the request lands, the delegation outlives
		// the gateway's retry budget: a change queued at 23:59 is not stuck
		// with minutes of authority to finish hours of work.
		require.GreaterOrEqual(t, int64(*exp)-now, overhang,
			"a delegation must always carry at least the async overhang")

		// The delegations map keys the issued delegation to its own CID (the
		// initial-implementation proof chain).
		require.Len(t, ok.Delegations.Entries, 1)
		chain, found := ok.Delegations.Entries[reDel.Link()]
		require.True(t, found)
		require.Equal(t, []cid.Cid{reDel.Link()}, chain)
	})

	// expiringAt stores the key with the given expiry.
	expiringAt := func(at time.Time) func(*accesskey.Input) {
		return func(in *accesskey.Input) { in.ExpiresAt = &at }
	}

	t.Run("a key expiring before the next UTC midnight caps the delegation's expiry", func(t *testing.T) {
		// An hour out is always sooner than the next UTC midnight plus the
		// skew and the overhang, so the key's own expiry must win, and it
		// leaves a stalled test run ample time before the key lapses.
		keyExpiry := time.Now().Add(time.Hour).Truncate(time.Second)
		az, _ := setup(t, []string{"s3:GetObject"}, false, akSigner, expiringAt(keyExpiry))
		args := signedGetArgs(t, akSigner, bucketName, region, time.Now(), time.Hour)

		_, blocks, err := call(t, az, providerID, args)
		require.NoError(t, err)
		require.Len(t, blocks, 1)
		exp := blocks[0].Expiration()
		require.NotNil(t, exp)
		require.Equal(t, keyExpiry.Unix(), int64(*exp),
			"the gateway must not hold authority past the access key's expiry")
	})

	t.Run("a key expiring after the next UTC midnight leaves the delegation's expiry alone", func(t *testing.T) {
		keyExpiry := time.Now().Add(72 * time.Hour)
		az, _ := setup(t, []string{"s3:GetObject"}, false, akSigner, expiringAt(keyExpiry))
		args := signedGetArgs(t, akSigner, bucketName, region, time.Now(), time.Hour)

		_, blocks, err := call(t, az, providerID, args)
		require.NoError(t, err)
		require.Len(t, blocks, 1)
		exp := blocks[0].Expiration()
		require.NotNil(t, exp)
		skew := int64(sigv4.MaxClockSkew / time.Second)
		overhang := int64(rpc.AsyncOverhang / time.Second)
		require.Zero(t, (int64(*exp)-skew-overhang)%86400,
			"expiry should be a UTC midnight plus the max clock skew and the async overhang")
		require.Less(t, int64(*exp), keyExpiry.Unix())
	})

	t.Run("a copy from another bucket also delegates the source's read", func(t *testing.T) {
		az, _ := setup(t, []string{"s3:GetObject", "s3:PutObject"}, false, akSigner)
		ok, blocks, err := call(t, az, providerID, signedCopyArgs(t, akSigner, bucketName, srcName, region))
		require.NoError(t, err)
		require.Equal(t, &bucketID, ok.Bucket)
		require.Equal(t, &srcID, ok.SourceBucket, "the source the copy was authorized to read")

		// The destination's PutObject commands plus one /content/retrieve over the
		// source, all keyed in the proof set.
		putCmds := s3perm.CommandsFor("s3:PutObject")
		keySigned := issuedBy(blocks, akDID)
		require.Len(t, keySigned, len(putCmds)+1)
		for _, d := range keySigned {
			require.Contains(t, ok.Delegations.Entries, d.Link())
		}
		var srcRetrieve int
		for _, d := range keySigned {
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

	// keyGrants stores the grants the tenant issues the key for perms over
	// the buckets, as key creation does, and returns them.
	keyGrants := func(t *testing.T, az *auth.Authorizer, perms []string, buckets ...did.DID) []ucan.Delegation {
		t.Helper()
		grants, err := issueGrants(multikey.NewIssuer(tenantID, tenantSigner), akDID, buckets, perms, nil)
		require.NoError(t, err)
		require.NotEmpty(t, grants)
		require.NoError(t, storeFor[az].PutBatch(ctx, grants))
		return grants
	}

	// The reply carries the grants the decision rests on, so the gateway can
	// tell an out-of-date reply by its revoked grants.
	t.Run("the reply carries the key's grants over the bucket, with their chains from its root", func(t *testing.T) {
		perms := []string{"s3:GetObject"}
		az, _ := setup(t, perms, false, akSigner)
		grants := keyGrants(t, az, perms, bucketID)
		elsewhere := keyGrants(t, az, perms, srcID)

		ok, blocks, err := call(t, az, providerID, signedGetArgs(t, akSigner, bucketName, region, time.Now(), time.Hour))
		require.NoError(t, err)

		root := roots[bucketID]
		require.Subset(t, cids(blocks), append(cids(grants), root.Link()))
		require.NotContains(t, cids(blocks), elsewhere[0].Link(), "a grant over another bucket stays out")
		for _, g := range grants {
			require.Equal(t, []cid.Cid{root.Link(), g.Link()}, ok.Delegations.Entries[g.Link()])
		}
		require.Len(t, cids(blocks), len(slices.Compact(slices.Sorted(slices.Values(cidStrings(blocks))))), "each delegation once")
	})

	t.Run("a copy from another bucket also carries the key's grants over the source", func(t *testing.T) {
		perms := []string{"s3:GetObject", "s3:PutObject"}
		az, _ := setup(t, perms, false, akSigner)
		grants := keyGrants(t, az, perms, bucketID, srcID)

		_, blocks, err := call(t, az, providerID, signedCopyArgs(t, akSigner, bucketName, srcName, region))
		require.NoError(t, err)
		require.Subset(t, cids(blocks), append(cids(grants), roots[bucketID].Link(), roots[srcID].Link()))
	})

	t.Run("a copy within one bucket delegates nothing extra", func(t *testing.T) {
		az, _ := setup(t, []string{"s3:GetObject", "s3:PutObject"}, false, akSigner)
		ok, blocks, err := call(t, az, providerID, signedCopyArgs(t, akSigner, bucketName, bucketName, region))
		require.NoError(t, err)
		require.Equal(t, &bucketID, ok.SourceBucket, "a copy within one bucket names it as the source too")
		require.Len(t, issuedBy(blocks, akDID), len(s3perm.CommandsFor("s3:PutObject")))
	})

	t.Run("a principal-bound key signs its own per-request delegations and gets its effective set", func(t *testing.T) {
		az, pool := setup(t, nil, true, akSigner)
		grant(t, pool, "s3:GetObject", "s3:ListBucket")
		args := signedGetArgs(t, akSigner, bucketName, region, time.Now(), time.Hour)

		ok, blocks, err := call(t, az, providerID, args)
		require.NoError(t, err)

		require.Equal(t, []string{"s3:GetObject", "s3:ListBucket"}, ok.Permissions.Entries[akDID])

		// The key re-delegates to the gateway as a service key does. Its stored
		// grants over the bucket, which the reply carries with the bucket's
		// root, are what the policy's actions map to.
		keySigned := issuedBy(blocks, akDID)
		require.Len(t, keySigned, 1)
		reDel := keySigned[0]
		require.Equal(t, providerID, reDel.Audience())
		require.Equal(t, bucketID, reDel.Subject())
		require.Equal(t, content.Retrieve.Command.String(), reDel.Command().String())
		require.Equal(t, []cid.Cid{reDel.Link()}, ok.Delegations.Entries[reDel.Link()])

		held := issuedBy(blocks, tenantID)
		require.NotEmpty(t, held)
		for _, g := range held {
			require.Equal(t, akDID, g.Audience())
			require.Equal(t, []cid.Cid{roots[bucketID].Link(), g.Link()}, ok.Delegations.Entries[g.Link()])
		}
		require.Contains(t, cids(blocks), roots[bucketID].Link())
		require.Len(t, blocks, 1+len(held)+1, "the re-delegation, the key's grants and the root")
	})

	t.Run("a service key signs its own delegations", func(t *testing.T) {
		az, _ := setup(t, []string{"s3:GetObject"}, false, akSigner)
		args := signedGetArgs(t, akSigner, bucketName, region, time.Now(), time.Hour)

		_, blocks, err := call(t, az, providerID, args)
		require.NoError(t, err)
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

	t.Run("the object-lock and version permissions are required for their shapes", func(t *testing.T) {
		// The query parameter names the operation, so holding the plain write
		// or delete is not enough: placing a retention period or a legal hold,
		// and deleting a named version, each need their own permission.
		lock := "https://s3.fil.one/" + bucketName + "/object-key?retention"
		version := "https://s3.fil.one/" + bucketName + "/object-key?versionId=v"

		az, _ := setup(t, []string{"s3:PutObject", "s3:DeleteObject"}, false, akSigner)
		_, _, err := call(t, az, providerID, signedArgs(t, akSigner, "PUT", lock, region))
		require.Error(t, err, "s3:PutObject alone must not authorize a retention write")
		_, _, err = call(t, az, providerID, signedArgs(t, akSigner, "DELETE", version, region))
		require.Error(t, err, "s3:DeleteObject alone must not authorize a version delete")

		// Granted, the retention write is delegated its own narrower set: it
		// ships the catalog change it makes and nothing more.
		az, _ = setup(t, []string{"s3:PutObjectRetention"}, false, akSigner)
		_, blocks, err := call(t, az, providerID, signedArgs(t, akSigner, "PUT", lock, region))
		require.NoError(t, err)
		var cmds []string
		for _, d := range blocks {
			cmds = append(cmds, d.Command().String())
		}
		require.ElementsMatch(t, []string{"/blob/add", "/index/add", "/content/retrieve"}, cmds)
	})

	t.Run("rejects an unknown bucket", func(t *testing.T) {
		az, _ := setup(t, []string{"s3:GetObject"}, false, akSigner)
		args := signedGetArgs(t, akSigner, "nope", region, time.Now(), time.Hour)
		_, _, err := call(t, az, providerID, args)
		require.Error(t, err)
	})

	t.Run("a write also delegates its cleanup commands from the tenant, past the key's expiry", func(t *testing.T) {
		keyExpiry := time.Now().Add(time.Hour)
		az, _ := setup(t, []string{"s3:PutObject"}, false, akSigner, expiringAt(keyExpiry))
		args := signedArgs(t, akSigner, "PUT", "https://s3.fil.one/"+bucketName+"/object-key", region)

		ok, blocks, err := call(t, az, providerID, args)
		require.NoError(t, err)

		// Everything the access key issued is as before.
		require.Len(t, issuedBy(blocks, akDID), len(s3perm.CommandsFor("s3:PutObject")))

		var cmds []string
		for _, d := range issuedBy(blocks, tenantID) {
			cmds = append(cmds, d.Command().String())
			require.Equal(t, providerID, d.Audience())
			require.Equal(t, bucketID, d.Subject())
			exp := d.Expiration()
			require.NotNil(t, exp)
			// CleanupLifetime past the next UTC midnight plus the clock skew,
			// when the gateway stops using this response's delegations.
			skew := int64(sigv4.MaxClockSkew / time.Second)
			lifetime := int64(rpc.CleanupLifetime / time.Second)
			require.Zero(t, (int64(*exp)-skew-lifetime)%86400,
				"a cleanup delegation's lifetime runs from a UTC midnight plus the clock skew")
			require.GreaterOrEqual(t, int64(*exp), time.Now().Add(rpc.CleanupLifetime).Unix(),
				"and lasts at least CleanupLifetime")
			require.LessOrEqual(t, int64(*exp), time.Now().Add(rpc.CleanupLifetime+24*time.Hour+sigv4.MaxClockSkew).Unix(),
				"from the next one")
			require.Greater(t, int64(*exp), keyExpiry.Unix(), "and outlives the key")
		}
		require.ElementsMatch(t, []string{blob.Remove.Command.String(), blob.Abort.Command.String()}, cmds)

		// The bucket's root rides along, and each cleanup delegation's proof
		// set entry is the chain through it.
		roots := issuedBy(blocks, bucketID)
		require.Len(t, roots, 1)
		root := roots[0]
		require.Equal(t, tenantID, root.Audience())
		for _, d := range issuedBy(blocks, tenantID) {
			require.Equal(t, []cid.Cid{root.Link(), d.Link()}, ok.Delegations.Entries[d.Link()])
		}
	})

	t.Run("a read delegates no cleanup commands", func(t *testing.T) {
		az, _ := setup(t, []string{"s3:GetObject"}, false, akSigner)
		_, blocks, err := call(t, az, providerID, signedGetArgs(t, akSigner, bucketName, region, time.Now(), time.Hour))
		require.NoError(t, err)
		require.Empty(t, issuedBy(blocks, tenantID))
		require.Empty(t, issuedBy(blocks, bucketID))
	})

	t.Run("a bucket with no root delegation gets no cleanup delegations", func(t *testing.T) {
		pool := htestutil.PostgresOrSkip(t)
		az, _ := setup(t, []string{"s3:PutObject"}, false, akSigner)
		args := signedArgs(t, akSigner, "PUT", "https://s3.fil.one/"+bucketName+"/object-key", region)
		_, blocks, err := rpc.AuthorizeRequest(ctx, zap.NewNop(), az, delegationpostgres.New(pool), providerID, args)
		require.NoError(t, err)
		require.Empty(t, issuedBy(blocks, tenantID))
		require.Len(t, blocks, len(s3perm.CommandsFor("s3:PutObject")))
	})
}

// issuedBy returns the delegations among ds that issuer issued.
// cidStrings returns the delegations' CIDs as strings.
func cidStrings(ds []ucan.Delegation) []string {
	out := make([]string, len(ds))
	for i, d := range ds {
		out[i] = d.Link().String()
	}
	return out
}

func issuedBy(ds []ucan.Delegation, issuer did.DID) []ucan.Delegation {
	var out []ucan.Delegation
	for _, d := range ds {
		if d.Issuer() == issuer {
			out = append(out, d)
		}
	}
	return out
}
