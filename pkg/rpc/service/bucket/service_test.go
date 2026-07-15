package bucket_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	client "github.com/fil-forge/hilt/pkg/client"
	"github.com/fil-forge/hilt/pkg/rpc/service/auth"
	bucketsvc "github.com/fil-forge/hilt/pkg/rpc/service/bucket"
	"github.com/fil-forge/hilt/pkg/sigv4"
	"github.com/fil-forge/hilt/pkg/store"
	accesskeymemory "github.com/fil-forge/hilt/pkg/store/accesskey/memory"
	bucketmemory "github.com/fil-forge/hilt/pkg/store/bucket/memory"
	delegationstore "github.com/fil-forge/hilt/pkg/store/delegation"
	delegationmemory "github.com/fil-forge/hilt/pkg/store/delegation/memory"
	providermemory "github.com/fil-forge/hilt/pkg/store/provider/memory"
	"github.com/fil-forge/hilt/pkg/store/tenant"
	tenantmemory "github.com/fil-forge/hilt/pkg/store/tenant/memory"
	"github.com/fil-forge/hilt/pkg/vault"
	vaultmemory "github.com/fil-forge/hilt/pkg/vault/memory"
	"github.com/fil-forge/libforge/commands/content"
	s3 "github.com/fil-forge/libforge/commands/s3"
	s3bkt "github.com/fil-forge/libforge/commands/s3/bucket"
	"github.com/fil-forge/libforge/testutil"
	"github.com/fil-forge/ucantone/did"
	"github.com/fil-forge/ucantone/multikey"
	"github.com/fil-forge/ucantone/multikey/ed25519"
	"github.com/fil-forge/ucantone/multikey/secp256k1"
	"github.com/fil-forge/ucantone/ucan"
	"github.com/fil-forge/ucantone/ucan/command"
	"github.com/fil-forge/ucantone/ucan/delegation"
	"github.com/multiformats/go-multibase"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

// fakeSprue is a combined stub of the Sprue dependency (ProvisionSpace +
// SpaceEmpty), recording its inputs.
type fakeSprue struct {
	sub         string
	provErr     error
	provCalled  bool
	provAccount did.DID
	provSpace   did.DID

	empty       bool
	emptyErr    error
	emptyCalled bool
	emptySpace  did.DID
}

func (f *fakeSprue) ProvisionSpace(_ context.Context, account ucan.Issuer, space did.DID) (string, error) {
	f.provCalled = true
	f.provAccount = account.DID()
	f.provSpace = space
	return f.sub, f.provErr
}

func (f *fakeSprue) SpaceEmpty(_ context.Context, space did.DID, _ ...client.MethodOption) (bool, error) {
	f.emptyCalled = true
	f.emptySpace = space
	return f.empty, f.emptyErr
}

func presign(t *testing.T, signer ed25519.Signer, method, url, region string) s3.Request {
	t.Helper()
	secret, err := multibase.Encode(multibase.Base64url, signer.Bytes())
	require.NoError(t, err)
	signed, err := sigv4.Presign(sigv4.Request{Method: method, URL: url}, signer.KeyDID().Identifier(), secret, region, sigv4.SchemeV4, time.Now(), time.Hour)
	require.NoError(t, err)
	return s3.Request{Method: signed.Method, URL: signed.URL}
}

func TestCreate(t *testing.T) {
	ctx := t.Context()
	const region, bucketName = "us-west-2", "newbucket"

	akSigner, err := ed25519.Generate()
	require.NoError(t, err)
	akDID := akSigner.KeyDID()
	tenantSigner, err := secp256k1.Generate()
	require.NoError(t, err)
	tenantID := tenantSigner.KeyDID()
	providerID := testutil.RandomDID(t)

	// setup seeds a powerline tenant→access-key delegation for /content/retrieve.
	setup := func(t *testing.T, perms []string, sprue bucketsvc.UploadClient, delegations delegationstore.Store) (*bucketsvc.Service, *bucketmemory.Store) {
		t.Helper()
		accessKeys, tenants, buckets := accesskeymemory.New(), tenantmemory.New(), bucketmemory.New()
		providers, secrets := providermemory.New(), vaultmemory.New()
		require.NoError(t, providers.Add(ctx, providerID, region))
		require.NoError(t, tenants.Add(ctx, tenantID, "tenant-1", providerID, tenant.Active))
		require.NoError(t, accessKeys.Add(ctx, akDID, tenantID, "k1", nil, perms, nil))
		require.NoError(t, secrets.Write(ctx, vault.AccessKeyPath(tenantID, akDID), akSigner.Bytes()))
		require.NoError(t, secrets.Write(ctx, vault.TenantKeyPath(tenantID), tenantSigner.Bytes()))
		powerline, err := delegation.Delegate(multikey.NewIssuer(tenantID, tenantSigner), akDID, did.DID{}, content.Retrieve.Command)
		require.NoError(t, err)
		require.NoError(t, delegations.PutBatch(ctx, []ucan.Delegation{powerline}))
		az := auth.NewAuthorizer(zap.NewNop(), accessKeys, tenants, providers, buckets, secrets)
		return bucketsvc.New(zap.NewNop(), az, buckets, delegations, accessKeys, sprue), buckets
	}

	args := func() *s3bkt.CreateArguments {
		return &s3bkt.CreateArguments{Request: presign(t, akSigner, "PUT", "https://s3.fil.one/"+bucketName, region)}
	}

	t.Run("creates and provisions the bucket, returning the powerline chain", func(t *testing.T) {
		sprue := &fakeSprue{sub: "sub-1"}
		svc, buckets := setup(t, []string{"s3:CreateBucket", "s3:GetObject"}, sprue, delegationmemory.New())
		ok, blocks, err := svc.Create(ctx, providerID, args())
		require.NoError(t, err)

		rec, err := buckets.GetByName(ctx, bucketName)
		require.NoError(t, err)
		require.Equal(t, &rec.ID, ok.Bucket)
		require.True(t, sprue.provCalled)
		require.Equal(t, tenantID, sprue.provAccount)
		require.Equal(t, *ok.Bucket, sprue.provSpace)
		require.Len(t, ok.Delegations.Entries, 1)
		require.Len(t, blocks, 2) // bucket→tenant root + tenant→access-key powerline
	})

	t.Run("rejects a key without s3:CreateBucket", func(t *testing.T) {
		svc, _ := setup(t, []string{"s3:GetObject"}, &fakeSprue{}, delegationmemory.New())
		_, _, err := svc.Create(ctx, providerID, args())
		require.ErrorIs(t, err, auth.ErrOperationNotPermitted)
	})

	t.Run("rejects a duplicate bucket name", func(t *testing.T) {
		svc, buckets := setup(t, []string{"s3:CreateBucket"}, &fakeSprue{}, delegationmemory.New())
		require.NoError(t, buckets.Add(ctx, testutil.RandomDID(t), tenantID, bucketName))
		_, _, err := svc.Create(ctx, providerID, args())
		require.ErrorIs(t, err, bucketsvc.ErrBucketExists)
	})

	t.Run("rolls back the bucket when provisioning fails", func(t *testing.T) {
		svc, buckets := setup(t, []string{"s3:CreateBucket"}, &fakeSprue{provErr: errors.New("sprue unavailable")}, delegationmemory.New())
		_, _, err := svc.Create(ctx, providerID, args())
		require.Error(t, err)
		_, err = buckets.GetByName(ctx, bucketName)
		require.ErrorIs(t, err, store.ErrRecordNotFound)
	})

	t.Run("rolls back the bucket when listing delegations fails", func(t *testing.T) {
		// A failure after provisioning (listing the access key's delegations) must
		// still roll the bucket record back.
		delegations := failingListDelegations{Store: delegationmemory.New(), err: errors.New("boom")}
		svc, buckets := setup(t, []string{"s3:CreateBucket"}, &fakeSprue{}, delegations)
		_, _, err := svc.Create(ctx, providerID, args())
		require.Error(t, err)
		_, err = buckets.GetByName(ctx, bucketName)
		require.ErrorIs(t, err, store.ErrRecordNotFound)
	})
}

// failingListDelegations wraps a delegation store, failing ListByAudience so a
// post-provisioning failure can be exercised.
type failingListDelegations struct {
	delegationstore.Store
	err error
}

func (f failingListDelegations) ListByAudience(context.Context, did.DID, ...store.PaginationOption) (store.Page[ucan.Delegation], error) {
	return store.Page[ucan.Delegation]{}, f.err
}

func TestDelete(t *testing.T) {
	ctx := t.Context()
	const region, bucketName = "us-west-2", "delbucket"

	akSigner, err := ed25519.Generate()
	require.NoError(t, err)
	akDID := akSigner.KeyDID()
	tenantSigner, err := secp256k1.Generate()
	require.NoError(t, err)
	tenantID := tenantSigner.KeyDID()
	providerID := testutil.RandomDID(t)

	setup := func(t *testing.T, perms []string, sprue bucketsvc.UploadClient) (*bucketsvc.Service, *bucketmemory.Store, did.DID) {
		t.Helper()
		accessKeys, tenants, buckets := accesskeymemory.New(), tenantmemory.New(), bucketmemory.New()
		providers, secrets, delegations := providermemory.New(), vaultmemory.New(), delegationmemory.New()
		require.NoError(t, providers.Add(ctx, providerID, region))
		require.NoError(t, tenants.Add(ctx, tenantID, "tenant-1", providerID, tenant.Active))
		require.NoError(t, accessKeys.Add(ctx, akDID, tenantID, "k1", nil, perms, nil))
		require.NoError(t, secrets.Write(ctx, vault.AccessKeyPath(tenantID, akDID), akSigner.Bytes()))
		require.NoError(t, secrets.Write(ctx, vault.TenantKeyPath(tenantID), tenantSigner.Bytes()))
		bucketSigner, err := ed25519.Generate()
		require.NoError(t, err)
		bucketID := bucketSigner.KeyDID()
		require.NoError(t, buckets.Add(ctx, bucketID, tenantID, bucketName))
		root, err := delegation.Delegate(multikey.NewIssuer(bucketID, bucketSigner), tenantID, bucketID, command.Top())
		require.NoError(t, err)
		grant, err := delegation.Delegate(multikey.NewIssuer(tenantID, tenantSigner), akDID, bucketID, content.Retrieve.Command)
		require.NoError(t, err)
		require.NoError(t, delegations.PutBatch(ctx, []ucan.Delegation{root, grant}))
		az := auth.NewAuthorizer(zap.NewNop(), accessKeys, tenants, providers, buckets, secrets)
		return bucketsvc.New(zap.NewNop(), az, buckets, delegations, accessKeys, sprue), buckets, bucketID
	}

	del := func(name string) *s3bkt.DeleteArguments {
		return &s3bkt.DeleteArguments{Request: presign(t, akSigner, "DELETE", "https://s3.fil.one/"+name, region)}
	}

	t.Run("deletes an empty bucket", func(t *testing.T) {
		sprue := &fakeSprue{empty: true}
		svc, buckets, bucketID := setup(t, []string{"s3:DeleteBucket"}, sprue)
		_, err := svc.Delete(ctx, providerID, del(bucketName))
		require.NoError(t, err)
		require.True(t, sprue.emptyCalled)
		require.Equal(t, bucketID, sprue.emptySpace)
		_, err = buckets.GetByName(ctx, bucketName)
		require.ErrorIs(t, err, store.ErrRecordNotFound)
	})

	t.Run("rejects a key without s3:DeleteBucket", func(t *testing.T) {
		svc, _, _ := setup(t, []string{"s3:GetObject"}, &fakeSprue{empty: true})
		_, err := svc.Delete(ctx, providerID, del(bucketName))
		require.ErrorIs(t, err, auth.ErrOperationNotPermitted)
	})

	t.Run("rejects an unknown bucket", func(t *testing.T) {
		svc, _, _ := setup(t, []string{"s3:DeleteBucket"}, &fakeSprue{empty: true})
		_, err := svc.Delete(ctx, providerID, del("nope"))
		require.ErrorIs(t, err, auth.ErrUnknownBucket)
	})

	t.Run("rejects a non-empty bucket and keeps it", func(t *testing.T) {
		svc, buckets, _ := setup(t, []string{"s3:DeleteBucket"}, &fakeSprue{empty: false})
		_, err := svc.Delete(ctx, providerID, del(bucketName))
		require.ErrorIs(t, err, bucketsvc.ErrBucketNotEmpty)
		_, err = buckets.GetByName(ctx, bucketName)
		require.NoError(t, err)
	})

	t.Run("propagates a SpaceEmpty error", func(t *testing.T) {
		svc, _, _ := setup(t, []string{"s3:DeleteBucket"}, &fakeSprue{emptyErr: errors.New("sprue unavailable")})
		_, err := svc.Delete(ctx, providerID, del(bucketName))
		require.Error(t, err)
	})
}

func TestList(t *testing.T) {
	ctx := t.Context()
	const region = "us-west-2"

	signer, err := ed25519.Generate()
	require.NoError(t, err)
	akDID := signer.KeyDID()
	providerID := testutil.RandomDID(t)

	setup := func(t *testing.T, perms []string) (*bucketsvc.Service, *bucketmemory.Store, did.DID) {
		t.Helper()
		accessKeys, tenants, buckets := accesskeymemory.New(), tenantmemory.New(), bucketmemory.New()
		providers, secrets, delegations := providermemory.New(), vaultmemory.New(), delegationmemory.New()
		require.NoError(t, providers.Add(ctx, providerID, region))
		tenantID := testutil.RandomDID(t)
		require.NoError(t, tenants.Add(ctx, tenantID, "tenant-1", providerID, tenant.Active))
		require.NoError(t, accessKeys.Add(ctx, akDID, tenantID, "k1", nil, perms, nil))
		require.NoError(t, secrets.Write(ctx, vault.AccessKeyPath(tenantID, akDID), signer.Bytes()))
		az := auth.NewAuthorizer(zap.NewNop(), accessKeys, tenants, providers, buckets, secrets)
		return bucketsvc.New(zap.NewNop(), az, buckets, delegations, accessKeys, &fakeSprue{}), buckets, tenantID
	}

	// listArgs presigns a ListBuckets request; extra ListBuckets query params
	// (prefix, max-buckets, continuation-token) are appended before signing so
	// the signature covers them.
	listArgs := func(params ...string) *s3bkt.ListArguments {
		url := strings.Join(append([]string{"https://" + region + ".s3.fil.one/?x-id=ListBuckets"}, params...), "&")
		return &s3bkt.ListArguments{Request: presign(t, signer, "GET", url, region)}
	}

	bucketNames := func(ok *s3bkt.ListOK) []string {
		names := make([]string, 0, len(ok.Buckets))
		for _, b := range ok.Buckets {
			names = append(names, b.Name)
		}
		return names
	}

	t.Run("lists the tenant's buckets", func(t *testing.T) {
		svc, buckets, tenantID := setup(t, []string{"s3:ListAllMyBuckets"})
		require.NoError(t, buckets.Add(ctx, testutil.RandomDID(t), tenantID, "alpha"))
		require.NoError(t, buckets.Add(ctx, testutil.RandomDID(t), tenantID, "bravo"))
		ok, err := svc.List(ctx, providerID, listArgs())
		require.NoError(t, err)
		require.Equal(t, []string{"alpha", "bravo"}, bucketNames(ok))
		require.Empty(t, ok.ContinuationToken)
		require.Empty(t, ok.Prefix)
	})

	t.Run("filters by prefix and echoes it", func(t *testing.T) {
		svc, buckets, tenantID := setup(t, []string{"s3:ListAllMyBuckets"})
		require.NoError(t, buckets.Add(ctx, testutil.RandomDID(t), tenantID, "alpha"))
		require.NoError(t, buckets.Add(ctx, testutil.RandomDID(t), tenantID, "apple"))
		require.NoError(t, buckets.Add(ctx, testutil.RandomDID(t), tenantID, "bravo"))
		ok, err := svc.List(ctx, providerID, listArgs("prefix=a"))
		require.NoError(t, err)
		require.Equal(t, []string{"alpha", "apple"}, bucketNames(ok))
		require.Equal(t, "a", ok.Prefix)
		require.Empty(t, ok.ContinuationToken)
	})

	t.Run("paginates with max-buckets and continuation-token", func(t *testing.T) {
		svc, buckets, tenantID := setup(t, []string{"s3:ListAllMyBuckets"})
		for _, name := range []string{"charlie", "alpha", "bravo"} {
			require.NoError(t, buckets.Add(ctx, testutil.RandomDID(t), tenantID, name))
		}

		ok, err := svc.List(ctx, providerID, listArgs("max-buckets=2"))
		require.NoError(t, err)
		require.Equal(t, []string{"alpha", "bravo"}, bucketNames(ok))
		require.Equal(t, "bravo", ok.ContinuationToken)

		ok, err = svc.List(ctx, providerID, listArgs("max-buckets=2", "continuation-token="+ok.ContinuationToken))
		require.NoError(t, err)
		require.Equal(t, []string{"charlie"}, bucketNames(ok))
		require.Empty(t, ok.ContinuationToken)
	})

	t.Run("rejects an invalid max-buckets", func(t *testing.T) {
		svc, _, _ := setup(t, []string{"s3:ListAllMyBuckets"})
		for _, param := range []string{"max-buckets=abc", "max-buckets=0", "max-buckets=-1", "max-buckets=10001"} {
			_, err := svc.List(ctx, providerID, listArgs(param))
			require.ErrorIs(t, err, bucketsvc.ErrInvalidArgument, "param %q", param)
		}
	})

	t.Run("rejects a key without the list permission", func(t *testing.T) {
		svc, _, _ := setup(t, []string{"s3:GetObject"})
		_, err := svc.List(ctx, providerID, listArgs())
		require.ErrorIs(t, err, auth.ErrOperationNotPermitted)
	})

	t.Run("rejects a validly-signed request for a different operation", func(t *testing.T) {
		// A GetObject request the key IS permitted for passes Authorize, but List
		// rejects it as not a ListBuckets operation.
		svc, buckets, tenantID := setup(t, []string{"s3:GetObject"})
		require.NoError(t, buckets.Add(ctx, testutil.RandomDID(t), tenantID, "bucket-a"))
		args := &s3bkt.ListArguments{Request: presign(t, signer, "GET", "https://"+region+".s3.fil.one/bucket-a/object-key", region)}
		_, err := svc.List(ctx, providerID, args)
		require.ErrorIs(t, err, bucketsvc.ErrOperationMismatch)
	})
}

func TestInfo(t *testing.T) {
	ctx := t.Context()
	const bucketName = "infobucket"

	akSigner, err := ed25519.Generate()
	require.NoError(t, err)
	akDID := akSigner.KeyDID()
	tenantSigner, err := secp256k1.Generate()
	require.NoError(t, err)
	tenantID := tenantSigner.KeyDID()
	bucketSigner, err := ed25519.Generate()
	require.NoError(t, err)
	bucketID := bucketSigner.KeyDID()

	// setup seeds a bucket, an access key, a bucket→tenant root, and a
	// tenant→access-key grant with the given subject (did.DID{} = powerline).
	setup := func(t *testing.T, grantSubject did.DID) *bucketsvc.Service {
		t.Helper()
		accessKeys, buckets, delegations := accesskeymemory.New(), bucketmemory.New(), delegationmemory.New()
		require.NoError(t, accessKeys.Add(ctx, akDID, tenantID, "k1", nil, []string{"s3:GetObject"}, nil))
		require.NoError(t, buckets.Add(ctx, bucketID, tenantID, bucketName))
		root, err := delegation.Delegate(multikey.NewIssuer(bucketID, bucketSigner), tenantID, bucketID, command.Top())
		require.NoError(t, err)
		grant, err := delegation.Delegate(multikey.NewIssuer(tenantID, tenantSigner), akDID, grantSubject, content.Retrieve.Command)
		require.NoError(t, err)
		require.NoError(t, delegations.PutBatch(ctx, []ucan.Delegation{root, grant}))
		// Info does not use the authorizer; a minimal one over empty stores suffices.
		az := auth.NewAuthorizer(zap.NewNop(), accessKeys, tenantmemory.New(), providermemory.New(), buckets, vaultmemory.New())
		return bucketsvc.New(zap.NewNop(), az, buckets, delegations, accessKeys, &fakeSprue{})
	}

	t.Run("returns the bucket, permissions, and delegation chain", func(t *testing.T) {
		svc := setup(t, did.DID{}) // powerline grant reaches the bucket
		ok, blocks, err := svc.Info(ctx, &s3bkt.InfoArguments{Name: bucketName, AccessKey: akDID})
		require.NoError(t, err)
		require.Equal(t, bucketID, ok.ID)
		require.Equal(t, []string{"s3:GetObject"}, ok.Permissions.Entries[akDID])
		require.Len(t, blocks, 2)
	})

	t.Run("rejects an unknown bucket", func(t *testing.T) {
		svc := setup(t, did.DID{})
		_, _, err := svc.Info(ctx, &s3bkt.InfoArguments{Name: "nope", AccessKey: akDID})
		require.ErrorIs(t, err, bucketsvc.ErrUnknownBucket)
	})

	t.Run("rejects an unknown access key", func(t *testing.T) {
		svc := setup(t, did.DID{})
		_, _, err := svc.Info(ctx, &s3bkt.InfoArguments{Name: bucketName, AccessKey: testutil.RandomDID(t)})
		require.ErrorIs(t, err, bucketsvc.ErrUnknownAccessKey)
	})

	t.Run("returns empty delegations when no grant reaches the bucket", func(t *testing.T) {
		svc := setup(t, testutil.RandomDID(t)) // grant scoped to a different bucket
		ok, blocks, err := svc.Info(ctx, &s3bkt.InfoArguments{Name: bucketName, AccessKey: akDID})
		require.NoError(t, err)
		require.Empty(t, ok.Delegations.Entries)
		require.Empty(t, blocks)
	})
}
