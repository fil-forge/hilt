package principal_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/fil-forge/hilt/internal/testutil"
	principalsvc "github.com/fil-forge/hilt/pkg/api/service/principal"
	"github.com/fil-forge/hilt/pkg/bucketpolicy"
	"github.com/fil-forge/hilt/pkg/store"
	accesskeystore "github.com/fil-forge/hilt/pkg/store/accesskey"
	accesskeymemory "github.com/fil-forge/hilt/pkg/store/accesskey/memory"
	bucketpolicystore "github.com/fil-forge/hilt/pkg/store/bucketpolicy"
	bucketpolicymemory "github.com/fil-forge/hilt/pkg/store/bucketpolicy/memory"
	principalstore "github.com/fil-forge/hilt/pkg/store/principal"
	principalmemory "github.com/fil-forge/hilt/pkg/store/principal/memory"
	"github.com/fil-forge/hilt/pkg/store/tenant"
	tenantmemory "github.com/fil-forge/hilt/pkg/store/tenant/memory"
	"github.com/fil-forge/hilt/pkg/vault"
	vaultmemory "github.com/fil-forge/hilt/pkg/vault/memory"
	"github.com/fil-forge/ucantone/did"
	"github.com/fil-forge/ucantone/multikey/ed25519"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

// fakeInvalidations is a stub of the principal invalidation publisher,
// recording the principals it was asked to invalidate.
type fakeInvalidations struct {
	err        error
	principals []string
}

func (f *fakeInvalidations) Invalidate(_ context.Context, _ did.DID, principal string) error {
	if f.err != nil {
		return f.err
	}
	f.principals = append(f.principals, principal)
	return nil
}

type deps struct {
	svc           *principalsvc.Service
	tenants       *tenantmemory.Store
	principals    *principalmemory.Store
	policies      *bucketpolicymemory.Store
	accessKeys    *accesskeymemory.Store
	secrets       *vaultmemory.Store
	invalidations *fakeInvalidations
	tenantID      did.DID
	otherTenant   did.DID
}

// setup wires the service over memory stores with two tenants, "tenant-1" and
// the foreign "tenant-2".
func setup(t *testing.T) deps {
	t.Helper()
	ctx := t.Context()
	tenants := tenantmemory.New()
	tenantID, otherTenant := testutil.RandomDID(t), testutil.RandomDID(t)
	require.NoError(t, tenants.Add(ctx, tenantID, "tenant-1", testutil.RandomDID(t), tenant.Active))
	require.NoError(t, tenants.Add(ctx, otherTenant, "tenant-2", testutil.RandomDID(t), tenant.Active))

	d := deps{
		tenants:       tenants,
		principals:    principalmemory.New(),
		policies:      bucketpolicymemory.New(),
		accessKeys:    accesskeymemory.New(),
		secrets:       vaultmemory.New(),
		invalidations: &fakeInvalidations{},
		tenantID:      tenantID,
		otherTenant:   otherTenant,
	}
	d.svc = principalsvc.New(zap.NewNop(), d.tenants, d.principals, d.policies, d.accessKeys, d.secrets, d.invalidations)
	return d
}

// putPolicy stores a bucket policy for the tenant and returns the bucket and
// the stored ETag.
func (d deps) putPolicy(t *testing.T, tenantID did.DID, doc bucketpolicy.Policy) (did.DID, string) {
	t.Helper()
	bucket := testutil.RandomDID(t)
	etag, err := d.policies.Put(t.Context(), bucketpolicystore.Input{Bucket: bucket, Tenant: tenantID, Policy: doc}, nil)
	require.NoError(t, err)
	return bucket, etag
}

// addKey stores a principal-bound access key and its vault entry the way the
// access-key service's create route does, so the removal path has one to find.
func (d deps) addKey(t *testing.T, tenantID did.DID, userID, name string) did.DID {
	t.Helper()
	ctx := t.Context()
	signer, err := ed25519.Generate()
	require.NoError(t, err)
	id := signer.KeyDID()
	require.NoError(t, d.accessKeys.Add(ctx, accesskeystore.Input{
		ID: id, Tenant: tenantID, Name: name, Principal: &userID,
	}))
	require.NoError(t, d.secrets.Write(ctx, vault.AccessKeyPath(tenantID, id), signer.Bytes()))
	return id
}

func TestCreate(t *testing.T) {
	ctx := t.Context()

	t.Run("records the principal and repeats idempotently", func(t *testing.T) {
		d := setup(t)
		rec, created, err := d.svc.Create(ctx, "tenant-1", "user-1")
		require.NoError(t, err)
		require.True(t, created)
		require.Equal(t, "user-1", rec.ExternalID)
		require.Equal(t, d.tenantID, rec.Tenant)

		again, created, err := d.svc.Create(ctx, "tenant-1", "user-1")
		require.NoError(t, err)
		require.False(t, created, "an existing principal is not created again")
		require.Equal(t, rec.CreatedAt, again.CreatedAt)
	})

	t.Run("the same userId in another tenant is a separate principal", func(t *testing.T) {
		d := setup(t)
		_, created, err := d.svc.Create(ctx, "tenant-1", "user-1")
		require.NoError(t, err)
		require.True(t, created)
		rec, created, err := d.svc.Create(ctx, "tenant-2", "user-1")
		require.NoError(t, err)
		require.True(t, created)
		require.Equal(t, d.otherTenant, rec.Tenant)
	})

	t.Run("rejects an unknown tenant", func(t *testing.T) {
		d := setup(t)
		_, _, err := d.svc.Create(ctx, "missing", "user-1")
		require.ErrorIs(t, err, principalsvc.ErrTenantNotFound)
	})

	t.Run("rejects an empty or oversized userId", func(t *testing.T) {
		d := setup(t)
		_, _, err := d.svc.Create(ctx, "tenant-1", "")
		require.ErrorIs(t, err, principalsvc.ErrInvalidUserID)
		_, _, err = d.svc.Create(ctx, "tenant-1", strings.Repeat("u", 256))
		require.ErrorIs(t, err, principalsvc.ErrInvalidUserID)
	})

	t.Run("rejects the reserved policy wildcard", func(t *testing.T) {
		d := setup(t)
		_, _, err := d.svc.Create(ctx, "tenant-1", bucketpolicy.Wildcard)
		require.ErrorIs(t, err, principalsvc.ErrInvalidUserID)
		recs, err := d.principals.ListByTenant(ctx, d.tenantID)
		require.NoError(t, err)
		require.Empty(t, recs)
	})
}

func TestListGet(t *testing.T) {
	ctx := t.Context()

	t.Run("lists the tenant's principals by userId", func(t *testing.T) {
		d := setup(t)
		for _, id := range []string{"user-2", "user-1"} {
			_, _, err := d.svc.Create(ctx, "tenant-1", id)
			require.NoError(t, err)
		}
		_, _, err := d.svc.Create(ctx, "tenant-2", "user-3")
		require.NoError(t, err)

		recs, err := d.svc.List(ctx, "tenant-1")
		require.NoError(t, err)
		var ids []string
		for _, rec := range recs {
			ids = append(ids, rec.ExternalID)
		}
		require.Equal(t, []string{"user-1", "user-2"}, ids)
	})

	t.Run("gets one principal", func(t *testing.T) {
		d := setup(t)
		_, _, err := d.svc.Create(ctx, "tenant-1", "user-1")
		require.NoError(t, err)
		rec, err := d.svc.Get(ctx, "tenant-1", "user-1")
		require.NoError(t, err)
		require.Equal(t, "user-1", rec.ExternalID)
	})

	t.Run("another tenant's principal is not found", func(t *testing.T) {
		d := setup(t)
		_, _, err := d.svc.Create(ctx, "tenant-2", "user-1")
		require.NoError(t, err)
		_, err = d.svc.Get(ctx, "tenant-1", "user-1")
		require.ErrorIs(t, err, principalsvc.ErrPrincipalNotFound)
	})

	t.Run("rejects an unknown tenant", func(t *testing.T) {
		d := setup(t)
		_, err := d.svc.List(ctx, "missing")
		require.ErrorIs(t, err, principalsvc.ErrTenantNotFound)
		_, err = d.svc.Get(ctx, "missing", "user-1")
		require.ErrorIs(t, err, principalsvc.ErrTenantNotFound)
	})
}

func TestListAccessKeys(t *testing.T) {
	ctx := t.Context()

	t.Run("lists the principal's keys and no other principal's", func(t *testing.T) {
		d := setup(t)
		for _, id := range []string{"user-1", "user-2"} {
			_, _, err := d.svc.Create(ctx, "tenant-1", id)
			require.NoError(t, err)
			d.addKey(t, d.tenantID, id, "laptop-"+id)
		}

		recs, err := d.svc.ListAccessKeys(ctx, "tenant-1", "user-1")
		require.NoError(t, err)
		require.Len(t, recs, 1)
		require.Equal(t, "user-1", *recs[0].Principal)

		_, err = d.svc.ListAccessKeys(ctx, "tenant-1", "user-3")
		require.ErrorIs(t, err, principalsvc.ErrPrincipalNotFound)
	})

	t.Run("rejects an unknown tenant", func(t *testing.T) {
		d := setup(t)
		_, err := d.svc.ListAccessKeys(ctx, "missing", "user-1")
		require.ErrorIs(t, err, principalsvc.ErrTenantNotFound)
	})
}

func TestDelete(t *testing.T) {
	ctx := t.Context()

	t.Run("invalidates once, strips the principal from policies, and deletes its keys", func(t *testing.T) {
		d := setup(t)
		for _, id := range []string{"user-1", "user-2"} {
			_, _, err := d.svc.Create(ctx, "tenant-1", id)
			require.NoError(t, err)
		}
		key := d.addKey(t, d.tenantID, "user-1", "laptop")
		kept := d.addKey(t, d.tenantID, "user-2", "desktop")

		// A policy the principal shares, one it holds alone, and one that reaches
		// it only through the wildcard.
		shared, _ := d.putPolicy(t, d.tenantID, bucketpolicy.Policy{Statements: []bucketpolicy.Statement{
			{Effect: bucketpolicy.Allow, Principals: []string{"user-1", "user-2"}, Actions: []string{"s3:GetObject"}},
			{Effect: bucketpolicy.Deny, Principals: []string{"user-1"}, Actions: []string{"s3:DeleteObject"}},
		}})
		alone, _ := d.putPolicy(t, d.tenantID, bucketpolicy.Policy{Statements: []bucketpolicy.Statement{
			{Effect: bucketpolicy.Allow, Principals: []string{"user-1"}, Actions: []string{"s3:PutObject"}},
		}})
		everyone, everyoneETag := d.putPolicy(t, d.tenantID, bucketpolicy.Policy{Statements: []bucketpolicy.Statement{
			{Effect: bucketpolicy.Allow, Principals: []string{bucketpolicy.Wildcard}, Actions: []string{"s3:ListBucket"}},
		}})

		require.NoError(t, d.svc.Delete(ctx, "tenant-1", "user-1"))

		require.Equal(t, []string{"user-1"}, d.invalidations.principals, "one invalidation covers the whole removal")

		_, err := d.svc.Get(ctx, "tenant-1", "user-1")
		require.ErrorIs(t, err, principalsvc.ErrPrincipalNotFound)

		// Its keys and their vault entries are gone; another principal's are not.
		_, err = d.accessKeys.Get(ctx, key)
		require.ErrorIs(t, err, store.ErrRecordNotFound)
		_, err = d.secrets.Read(ctx, vault.AccessKeyPath(d.tenantID, key))
		require.ErrorIs(t, err, vault.ErrNotFound)
		_, err = d.accessKeys.Get(ctx, kept)
		require.NoError(t, err)

		// The shared policy keeps the other principal and loses the statement the
		// removed one held alone.
		rec, err := d.policies.Get(ctx, shared)
		require.NoError(t, err)
		require.Equal(t, bucketpolicy.Policy{Statements: []bucketpolicy.Statement{
			{Effect: bucketpolicy.Allow, Principals: []string{"user-2"}, Actions: []string{"s3:GetObject"}},
		}}, rec.Policy)

		// The policy naming it alone is deleted with its last statement.
		_, err = d.policies.Get(ctx, alone)
		require.ErrorIs(t, err, store.ErrRecordNotFound)

		// The wildcard policy is untouched: it names the tenant's principals, and
		// this one is no longer among them.
		rec, err = d.policies.Get(ctx, everyone)
		require.NoError(t, err)
		require.Equal(t, everyoneETag, rec.ETag)
	})

	t.Run("a principal that is already gone is a no-op", func(t *testing.T) {
		d := setup(t)
		require.NoError(t, d.svc.Delete(ctx, "tenant-1", "user-1"))
		require.Empty(t, d.invalidations.principals, "nothing to invalidate")
	})

	t.Run("a publish failure leaves the principal, its keys and its policies intact", func(t *testing.T) {
		d := setup(t)
		_, _, err := d.svc.Create(ctx, "tenant-1", "user-1")
		require.NoError(t, err)
		key := d.addKey(t, d.tenantID, "user-1", "laptop")
		bucket, etag := d.putPolicy(t, d.tenantID, bucketpolicy.Policy{Statements: []bucketpolicy.Statement{
			{Effect: bucketpolicy.Allow, Principals: []string{"user-1"}, Actions: []string{"s3:GetObject"}},
		}})
		d.invalidations.err = errors.New("swarf unreachable")

		err = d.svc.Delete(ctx, "tenant-1", "user-1")
		require.ErrorContains(t, err, "swarf unreachable")

		rec, err := d.svc.Get(ctx, "tenant-1", "user-1")
		require.NoError(t, err, "the principal row must survive")
		require.Equal(t, "user-1", rec.ExternalID)

		keys, err := d.svc.ListAccessKeys(ctx, "tenant-1", "user-1")
		require.NoError(t, err)
		require.Len(t, keys, 1, "its keys must survive")
		require.Equal(t, key, keys[0].ID)
		_, err = d.secrets.Read(ctx, vault.AccessKeyPath(d.tenantID, key))
		require.NoError(t, err, "its vault entry must survive so the key still signs")

		policyRec, err := d.policies.Get(ctx, bucket)
		require.NoError(t, err)
		require.Equal(t, etag, policyRec.ETag, "its access must be unchanged")
	})

	t.Run("rejects an unknown tenant", func(t *testing.T) {
		d := setup(t)
		require.ErrorIs(t, d.svc.Delete(ctx, "missing", "user-1"), principalsvc.ErrTenantNotFound)
	})

	t.Run("a key created after the removal fails is deleted by the retry", func(t *testing.T) {
		d := setup(t)
		_, _, err := d.svc.Create(ctx, "tenant-1", "user-1")
		require.NoError(t, err)
		d.addKey(t, d.tenantID, "user-1", "laptop")
		d.invalidations.err = errors.New("swarf unreachable")
		require.Error(t, d.svc.Delete(ctx, "tenant-1", "user-1"))

		d.invalidations.err = nil
		require.NoError(t, d.svc.Delete(ctx, "tenant-1", "user-1"))
		require.Equal(t, []string{"user-1"}, d.invalidations.principals)
		recs, err := d.accessKeys.ListByTenant(ctx, d.tenantID, accesskeystore.WithPrincipal("user-1"))
		require.NoError(t, err)
		require.Empty(t, recs)
	})
}

// flakyPolicies fails the first Put with err, standing in for a policy edited
// between the removal's listing and its rewrite.
type flakyPolicies struct {
	bucketpolicystore.Store
	err error
}

func (f *flakyPolicies) Put(ctx context.Context, in bucketpolicystore.Input, beforeCommit func(context.Context, *bucketpolicystore.Record) error) (string, error) {
	if f.err != nil {
		err := f.err
		f.err = nil
		return "", err
	}
	return f.Store.Put(ctx, in, beforeCommit)
}

// lockedPrincipals fails Delete with err, standing in for the store giving up
// on a row another write holds.
type lockedPrincipals struct {
	principalstore.Store
	err error
}

func (l *lockedPrincipals) Delete(ctx context.Context, tenant did.DID, externalID string, beforeCommit func(context.Context) error) error {
	return l.err
}

func TestDeleteConcurrentChange(t *testing.T) {
	ctx := t.Context()

	t.Run("a policy edited during the removal is a retryable conflict", func(t *testing.T) {
		d := setup(t)
		_, _, err := d.svc.Create(ctx, "tenant-1", "user-1")
		require.NoError(t, err)
		// Two principals, so stripping one rewrites the policy rather than
		// deleting it.
		_, _, err = d.svc.Create(ctx, "tenant-1", "user-2")
		require.NoError(t, err)
		d.putPolicy(t, d.tenantID, bucketpolicy.Policy{Statements: []bucketpolicy.Statement{
			{Effect: bucketpolicy.Allow, Principals: []string{"user-1", "user-2"}, Actions: []string{"s3:GetObject"}},
		}})

		policies := &flakyPolicies{Store: d.policies, err: store.ErrPreconditionFailed}
		svc := principalsvc.New(zap.NewNop(), d.tenants, d.principals, policies, d.accessKeys, d.secrets, d.invalidations)
		require.ErrorIs(t, svc.Delete(ctx, "tenant-1", "user-1"), principalsvc.ErrConcurrentChange)

		rec, err := d.svc.Get(ctx, "tenant-1", "user-1")
		require.NoError(t, err, "the principal row must survive")
		require.Equal(t, "user-1", rec.ExternalID)
	})

	t.Run("a lock the store gave up on is a retryable conflict", func(t *testing.T) {
		d := setup(t)
		principals := &lockedPrincipals{Store: d.principals, err: store.ErrLockTimeout}
		svc := principalsvc.New(zap.NewNop(), d.tenants, principals, d.policies, d.accessKeys, d.secrets, d.invalidations)
		require.ErrorIs(t, svc.Delete(ctx, "tenant-1", "user-1"), principalsvc.ErrConcurrentChange)
	})
}
