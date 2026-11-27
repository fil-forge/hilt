package auth_test

import (
	"context"
	"sync"
	"testing"

	s3bkt "github.com/fil-forge/libforge/commands/s3/bucket"

	htestutil "github.com/fil-forge/hilt/internal/testutil"
	"github.com/fil-forge/hilt/pkg/rpc/service/auth"
	accesskeypostgres "github.com/fil-forge/hilt/pkg/store/accesskey/postgres"
	bucketpostgres "github.com/fil-forge/hilt/pkg/store/bucket/postgres"
	bucketpolicystore "github.com/fil-forge/hilt/pkg/store/bucketpolicy"
	bucketpolicypostgres "github.com/fil-forge/hilt/pkg/store/bucketpolicy/postgres"
	delegationpostgres "github.com/fil-forge/hilt/pkg/store/delegation/postgres"
	"github.com/fil-forge/hilt/pkg/store/pglock"
	principalpostgres "github.com/fil-forge/hilt/pkg/store/principal/postgres"
	providerpostgres "github.com/fil-forge/hilt/pkg/store/provider/postgres"
	"github.com/fil-forge/hilt/pkg/store/tenant"
	tenantpostgres "github.com/fil-forge/hilt/pkg/store/tenant/postgres"
	"github.com/fil-forge/hilt/pkg/tasks/tenantqueue"
	"github.com/fil-forge/hilt/pkg/vault"
	vaultmemory "github.com/fil-forge/hilt/pkg/vault/memory"
	"github.com/fil-forge/libforge/testutil"
	"github.com/fil-forge/ucantone/did"
	"github.com/fil-forge/ucantone/multikey/ed25519"
	"github.com/fil-forge/ucantone/multikey/secp256k1"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

// firstPolicyRead runs then once, when the authorizer reads its first
// policy: after it has read the key, the tenant, the buckets and the
// principal, and before it reads any other policy.
type firstPolicyRead struct {
	bucketpolicystore.Store
	then func()
	once sync.Once
}

func (f *firstPolicyRead) Get(ctx context.Context, bucket did.DID) (bucketpolicystore.Record, error) {
	rec, err := f.Store.Get(ctx, bucket)
	if f.then != nil {
		f.once.Do(f.then)
	}
	return rec, err
}

// TestAuthorizeReadsOneSnapshot commits a principal's removal while the
// authorizer is between two of its reads: after the copy destination's
// policy, before the copy source's. The removal strips the principal from
// both policies, deletes its key and tombstones it. Read in one snapshot,
// the request is decided as it was before the removal; read on their own,
// the two policies are of different states and the answer is neither the
// state before nor the one after.
func TestAuthorizeReadsOneSnapshot(t *testing.T) {
	const region = "us-east-1"
	// statement lets user-1 do the actions on the named bucket's objects.
	statement := func(name string, actions ...string) s3bkt.PolicyDocument {
		return s3bkt.PolicyDocument{Version: s3bkt.Version2012, Statements: []s3bkt.Statement{{
			Effect: s3bkt.Allow, Principal: s3bkt.Only("user-1"), Actions: s3bkt.NewStringSet(actions...),
			Resources: s3bkt.NewStringSet(s3bkt.ObjectsARN(name)),
		}}}
	}

	// setup returns an authorizer, with snapshots or without, whose first
	// policy read is followed by the principal's removal through the real
	// task, and a copy from "source" to "dest" signed by the principal's key.
	setup := func(t *testing.T, snapshots bool) func() error {
		t.Helper()
		ctx := t.Context()
		pool := htestutil.PostgresOrSkip(t)
		accessKeys, tenants := accesskeypostgres.New(pool), tenantpostgres.New(pool)
		providers, buckets, secrets := providerpostgres.New(pool), bucketpostgres.New(pool), vaultmemory.New()
		principals := principalpostgres.New(pool)

		accessKey, err := ed25519.GenerateIssuer()
		require.NoError(t, err)
		tenantSigner, err := secp256k1.Generate()
		require.NoError(t, err)
		providerID, tenantID := testutil.RandomDID(t), tenantSigner.KeyDID()
		require.NoError(t, providers.Add(ctx, providerID, region, nil))
		require.NoError(t, tenants.Add(ctx, tenantID, "tenant-1", tenant.Active))
		require.NoError(t, secrets.Write(ctx, vault.TenantKeyPath(tenantID), tenantSigner.Bytes()))
		dest, source := testutil.RandomDID(t), testutil.RandomDID(t)
		require.NoError(t, buckets.Add(ctx, dest, tenantID, providerID, "dest"))
		require.NoError(t, buckets.Add(ctx, source, tenantID, providerID, "source"))
		require.NoError(t, principals.Add(ctx, tenantID, "user-1"))
		seedKey(t, accessKeys, secrets, delegationpostgres.New(pool), accessKey, tenantID, &setupConfig{principalBound: true})
		htestutil.PutPolicy(t, pool, tenantID, dest, statement("dest", "s3:PutObject"))
		htestutil.PutPolicy(t, pool, tenantID, source, statement("source", "s3:GetObject"))

		runner := htestutil.StartServiceTasks(t, pool, secrets, &htestutil.FakeSwarf{})
		policies := &firstPolicyRead{Store: bucketpolicypostgres.New(pool), then: func() {
			_, err := runner.Run(context.Background(), tenantqueue.RemovePrincipalSpec(tenantID, "user-1"))
			require.NoError(t, err)
		}}
		opts := []auth.Option{auth.WithTenantChanges(runner)}
		if snapshots {
			opts = append(opts, auth.WithSnapshots(pglock.NewSnapshots(pool)))
		}
		az := auth.NewAuthorizer(zap.NewNop(), accessKeys, tenants, providers, buckets, principals, policies, secrets, opts...)
		request := signedCopyRequest(t, accessKey, "dest", "source", region, true)
		return func() error {
			_, err := az.Authorize(context.Background(), providerID, request)
			return err
		}
	}

	t.Run("in one snapshot the answer is the state before the change", func(t *testing.T) {
		authorize := setup(t, true)
		require.NoError(t, authorize(), "authorized as the principal could before its removal")
		require.ErrorIs(t, authorize(), auth.ErrUnknownAccessKey, "the next request is answered from the removal")
	})

	t.Run("read on their own the reads mix the two states", func(t *testing.T) {
		authorize := setup(t, false)
		// The destination was read as before the removal, the source as
		// after it: a bucket the principal no longer reaches. Before, the
		// copy was allowed; after, the key is unknown.
		require.ErrorIs(t, authorize(), auth.ErrUnknownBucket)
	})
}

// TestAuthorizeWaitsForPrincipalRemoval runs the real removal task. A
// request by the principal's key that arrives while the removal is running
// waits for it, and is refused: the removal deleted the key.
func TestAuthorizeWaitsForPrincipalRemoval(t *testing.T) {
	ctx := t.Context()
	const region = "us-east-1"
	pool := htestutil.PostgresOrSkip(t)
	accessKeys, tenants := accesskeypostgres.New(pool), tenantpostgres.New(pool)
	providers, buckets, secrets := providerpostgres.New(pool), bucketpostgres.New(pool), vaultmemory.New()
	principals, policies := principalpostgres.New(pool), bucketpolicypostgres.New(pool)

	accessKey, err := ed25519.GenerateIssuer()
	require.NoError(t, err)
	tenantSigner, err := secp256k1.Generate()
	require.NoError(t, err)
	providerID, tenantID, bucketID := testutil.RandomDID(t), tenantSigner.KeyDID(), testutil.RandomDID(t)
	require.NoError(t, providers.Add(ctx, providerID, region, nil))
	require.NoError(t, tenants.Add(ctx, tenantID, "tenant-1", tenant.Active))
	require.NoError(t, secrets.Write(ctx, vault.TenantKeyPath(tenantID), tenantSigner.Bytes()))
	require.NoError(t, buckets.Add(ctx, bucketID, tenantID, providerID, "bucket"))
	require.NoError(t, principals.Add(ctx, tenantID, "user-1"))
	seedKey(t, accessKeys, secrets, delegationpostgres.New(pool), accessKey, tenantID, &setupConfig{principalBound: true})
	htestutil.PutPolicy(t, pool, tenantID, bucketID, s3bkt.PolicyDocument{Version: s3bkt.Version2012, Statements: []s3bkt.Statement{{
		Effect: s3bkt.Allow, Principal: s3bkt.Only("user-1"), Actions: s3bkt.NewStringSet("s3:GetObject"),
		Resources: s3bkt.NewStringSet(s3bkt.ObjectsARN("bucket")),
	}}})

	// The removal parks once it has read everything for the policy it
	// rewrites, until released.
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	runner := htestutil.StartServiceTasks(t, pool, secrets, &htestutil.FakeSwarf{}, htestutil.BeforePolicyCommit(func() {
		once.Do(func() {
			close(entered)
			select {
			case <-release:
			case <-t.Context().Done():
			}
		})
	}))
	az := auth.NewAuthorizer(zap.NewNop(), accessKeys, tenants, providers, buckets, principals, policies, secrets,
		auth.WithTenantChanges(runner), auth.WithSnapshots(pglock.NewSnapshots(pool)))
	request := signedObjectRequest(t, accessKey, "bucket", region)
	_, err = az.Authorize(ctx, providerID, request)
	require.NoError(t, err, "the principal's key is authorized before the removal")

	removed, answered := htestutil.RequireWaitsForWriter(t,
		func(in chan<- struct{}, out <-chan struct{}) error {
			go func() { <-entered; close(in) }()
			go func() { <-out; close(release) }()
			_, err := runner.Run(context.Background(), tenantqueue.RemovePrincipalSpec(tenantID, "user-1"))
			return err
		},
		func() error {
			_, err := az.Authorize(context.Background(), providerID, request)
			return err
		})
	require.NoError(t, removed)
	require.ErrorIs(t, answered, auth.ErrUnknownAccessKey)
}
