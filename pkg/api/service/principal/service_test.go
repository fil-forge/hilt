package principal_test

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/fil-forge/hilt/internal/testutil"
	accesskeysvc "github.com/fil-forge/hilt/pkg/api/service/accesskey"
	principalsvc "github.com/fil-forge/hilt/pkg/api/service/principal"
	"github.com/fil-forge/hilt/pkg/bucketpolicy"
	"github.com/fil-forge/hilt/pkg/grant"
	"github.com/fil-forge/hilt/pkg/store"
	accesskeystore "github.com/fil-forge/hilt/pkg/store/accesskey"
	accesskeymemory "github.com/fil-forge/hilt/pkg/store/accesskey/memory"
	accesskeypostgres "github.com/fil-forge/hilt/pkg/store/accesskey/postgres"
	bucketmemory "github.com/fil-forge/hilt/pkg/store/bucket/memory"
	bucketpostgres "github.com/fil-forge/hilt/pkg/store/bucket/postgres"
	bucketpolicystore "github.com/fil-forge/hilt/pkg/store/bucketpolicy"
	bucketpolicymemory "github.com/fil-forge/hilt/pkg/store/bucketpolicy/memory"
	bucketpolicypostgres "github.com/fil-forge/hilt/pkg/store/bucketpolicy/postgres"
	delegationstore "github.com/fil-forge/hilt/pkg/store/delegation"
	delegationmemory "github.com/fil-forge/hilt/pkg/store/delegation/memory"
	delegationpostgres "github.com/fil-forge/hilt/pkg/store/delegation/postgres"
	principalstore "github.com/fil-forge/hilt/pkg/store/principal"
	principalmemory "github.com/fil-forge/hilt/pkg/store/principal/memory"
	principalpostgres "github.com/fil-forge/hilt/pkg/store/principal/postgres"
	providerpostgres "github.com/fil-forge/hilt/pkg/store/provider/postgres"
	"github.com/fil-forge/hilt/pkg/store/tenant"
	tenantmemory "github.com/fil-forge/hilt/pkg/store/tenant/memory"
	tenantpostgres "github.com/fil-forge/hilt/pkg/store/tenant/postgres"
	"github.com/fil-forge/hilt/pkg/vault"
	vaultmemory "github.com/fil-forge/hilt/pkg/vault/memory"
	"github.com/fil-forge/ucantone/did"
	"github.com/fil-forge/ucantone/multikey"
	"github.com/fil-forge/ucantone/multikey/ed25519"
	"github.com/fil-forge/ucantone/multikey/secp256k1"
	"github.com/fil-forge/ucantone/ucan"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

type deps struct {
	svc         *principalsvc.Service
	tenants     *tenantmemory.Store
	principals  *principalmemory.Store
	policies    *bucketpolicymemory.Store
	accessKeys  *accesskeymemory.Store
	secrets     *vaultmemory.Store
	delegations *delegationmemory.Store
	swarf       *testutil.FakeSwarf
	grants      *grant.Rotator
	tenantID    did.DID
	tenant      ucan.Issuer
	otherTenant did.DID
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

	principals := principalmemory.New()
	d := deps{
		tenants:     tenants,
		principals:  principals,
		policies:    bucketpolicymemory.New(),
		accessKeys:  accesskeymemory.New(accesskeymemory.WithPrincipals(principals.WithLive)),
		secrets:     vaultmemory.New(),
		delegations: delegationmemory.New(),
		swarf:       &testutil.FakeSwarf{},
		tenantID:    tenantID,
		otherTenant: otherTenant,
	}
	// tenant-1's key is in the vault: the grant rotator signs revocations as
	// the tenant.
	signer, err := secp256k1.Generate()
	require.NoError(t, err)
	require.NoError(t, d.secrets.Write(ctx, vault.TenantKeyPath(tenantID), signer.Bytes()))
	d.tenant = multikey.NewIssuer(tenantID, signer)
	d.grants = grant.NewRotator(zap.NewNop(), d.delegations, d.accessKeys, d.secrets, d.swarf)
	d.svc = principalsvc.New(zap.NewNop(), d.tenants, d.principals, d.policies, d.accessKeys, d.delegations, d.secrets, d.swarf, d.grants)
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

// addKey stores a principal-bound access key, its vault entry and, for
// tenant-1, one delegation over a bucket the way the access-key service's
// create route does, so the removal path has one to revoke.
func (d deps) addKey(t *testing.T, tenantID did.DID, principalID, name string) did.DID {
	t.Helper()
	ctx := t.Context()
	signer, err := ed25519.Generate()
	require.NoError(t, err)
	id := signer.KeyDID()
	require.NoError(t, d.accessKeys.Add(ctx, accesskeystore.Input{
		ID: id, Tenant: tenantID, Name: name, Principal: &principalID,
	}))
	require.NoError(t, d.secrets.Write(ctx, vault.AccessKeyPath(tenantID, id), signer.Bytes()))
	if tenantID == d.tenantID {
		dels, err := grant.Issue(d.tenant, id, []did.DID{testutil.RandomDID(t)}, []string{"s3:GetObject"}, nil)
		require.NoError(t, err)
		require.NoError(t, d.delegations.PutBatch(ctx, dels))
	}
	return id
}

// held returns the delegations the key holds.
func (d deps) held(t *testing.T, key did.DID) []ucan.Delegation {
	t.Helper()
	page, err := d.delegations.ListByAudience(t.Context(), key)
	require.NoError(t, err)
	return page.Results
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

	t.Run("the same principalId in another tenant is a separate principal", func(t *testing.T) {
		d := setup(t)
		_, created, err := d.svc.Create(ctx, "tenant-1", "user-1")
		require.NoError(t, err)
		require.True(t, created)
		rec, created, err := d.svc.Create(ctx, "tenant-2", "user-1")
		require.NoError(t, err)
		require.True(t, created)
		require.Equal(t, d.otherTenant, rec.Tenant)
	})

	t.Run("a lock timeout recording the principal is a retryable conflict", func(t *testing.T) {
		d := setup(t)
		svc := principalsvc.New(zap.NewNop(), d.tenants, &lockTimeoutPrincipals{Store: d.principals}, d.policies, d.accessKeys, d.delegations, d.secrets, d.swarf, d.grants)
		_, _, err := svc.Create(ctx, "tenant-1", "user-1")
		require.ErrorIs(t, err, principalsvc.ErrConcurrentChange)
	})

	t.Run("rejects an unknown tenant", func(t *testing.T) {
		d := setup(t)
		_, _, err := d.svc.Create(ctx, "missing", "user-1")
		require.ErrorIs(t, err, principalsvc.ErrTenantNotFound)
	})

	t.Run("rejects an empty or oversized principalId", func(t *testing.T) {
		d := setup(t)
		_, _, err := d.svc.Create(ctx, "tenant-1", "")
		require.ErrorIs(t, err, principalsvc.ErrInvalidPrincipalID)
		_, _, err = d.svc.Create(ctx, "tenant-1", strings.Repeat("u", 256))
		require.ErrorIs(t, err, principalsvc.ErrInvalidPrincipalID)
		// The limit is bytes, and the refusal says so.
		_, _, err = d.svc.Create(ctx, "tenant-1", strings.Repeat("é", 128))
		require.ErrorIs(t, err, principalsvc.ErrInvalidPrincipalID)
		require.Contains(t, err.Error(), "255 bytes")
	})

	t.Run("rejects a principalId that is not valid UTF-8 or holds a NUL", func(t *testing.T) {
		d := setup(t)
		for _, id := range []string{"a\x00b", "\xff"} {
			_, _, err := d.svc.Create(ctx, "tenant-1", id)
			require.ErrorIs(t, err, principalsvc.ErrInvalidPrincipalID, "%q", id)
		}
	})

	t.Run("a removal landing between the record and its read is a retryable conflict", func(t *testing.T) {
		d := setup(t)
		principals := &vanishingPrincipals{Store: d.principals, remove: func() {
			require.NoError(t, d.svc.Delete(ctx, "tenant-1", "user-1"))
		}}
		svc := principalsvc.New(zap.NewNop(), d.tenants, principals, d.policies, d.accessKeys, d.delegations, d.secrets, d.swarf, d.grants)
		_, _, err := svc.Create(ctx, "tenant-1", "user-1")
		require.ErrorIs(t, err, principalsvc.ErrConcurrentChange)
	})

	t.Run("rejects the reserved policy wildcard", func(t *testing.T) {
		d := setup(t)
		_, _, err := d.svc.Create(ctx, "tenant-1", bucketpolicy.Wildcard)
		require.ErrorIs(t, err, principalsvc.ErrInvalidPrincipalID)
		recs, err := d.principals.ListByTenant(ctx, d.tenantID)
		require.NoError(t, err)
		require.Empty(t, recs)
	})
}

func TestListGet(t *testing.T) {
	ctx := t.Context()

	t.Run("lists the tenant's principals by principalId", func(t *testing.T) {
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

func TestDelete(t *testing.T) {
	ctx := t.Context()

	t.Run("revokes its keys' delegations, strips the principal from policies, and deletes its keys", func(t *testing.T) {
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
			{Effect: bucketpolicy.Allow, Principal: bucketpolicy.Only("user-1", "user-2"), Actions: []string{"s3:GetObject"}},
			{Effect: bucketpolicy.Deny, Principal: bucketpolicy.Only("user-1"), Actions: []string{"s3:DeleteObject"}},
		}})
		alone, _ := d.putPolicy(t, d.tenantID, bucketpolicy.Policy{Statements: []bucketpolicy.Statement{
			{Effect: bucketpolicy.Allow, Principal: bucketpolicy.Only("user-1"), Actions: []string{"s3:PutObject"}},
		}})
		everyone, everyoneETag := d.putPolicy(t, d.tenantID, bucketpolicy.Policy{Statements: []bucketpolicy.Statement{
			{Effect: bucketpolicy.Allow, Principal: bucketpolicy.Everyone(), Actions: []string{"s3:ListBucket"}},
		}})

		require.NoError(t, d.svc.Delete(ctx, "tenant-1", "user-1"))

		require.Len(t, d.swarf.Revoked(), 1, "one revocation per key of the principal")

		_, err := d.svc.Get(ctx, "tenant-1", "user-1")
		require.ErrorIs(t, err, principalsvc.ErrPrincipalNotFound)

		// Its keys, their delegations and their vault entries are gone; another
		// principal's are not.
		_, err = d.accessKeys.Get(ctx, key)
		require.ErrorIs(t, err, store.ErrRecordNotFound)
		require.Empty(t, d.held(t, key))
		require.Len(t, d.held(t, kept), 1)
		_, err = d.secrets.Read(ctx, vault.AccessKeyPath(d.tenantID, key))
		require.ErrorIs(t, err, vault.ErrNotFound)
		_, err = d.accessKeys.Get(ctx, kept)
		require.NoError(t, err)

		// The shared policy keeps the other principal and loses the statement the
		// removed one held alone.
		rec, err := d.policies.Get(ctx, shared)
		require.NoError(t, err)
		require.Equal(t, bucketpolicy.Policy{Statements: []bucketpolicy.Statement{
			{Effect: bucketpolicy.Allow, Principal: bucketpolicy.Only("user-2"), Actions: []string{"s3:GetObject"}},
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

	t.Run("a removed principal is revived by Create with nothing attached", func(t *testing.T) {
		d := setup(t)
		_, _, err := d.svc.Create(ctx, "tenant-1", "user-1")
		require.NoError(t, err)
		d.addKey(t, d.tenantID, "user-1", "laptop")
		alone, _ := d.putPolicy(t, d.tenantID, bucketpolicy.Policy{Statements: []bucketpolicy.Statement{
			{Effect: bucketpolicy.Allow, Principal: bucketpolicy.Only("user-1"), Actions: []string{"s3:GetObject"}},
		}})
		require.NoError(t, d.svc.Delete(ctx, "tenant-1", "user-1"))

		rec, created, err := d.svc.Create(ctx, "tenant-1", "user-1")
		require.NoError(t, err)
		require.True(t, created, "a revive is reported as a create")
		require.Equal(t, "user-1", rec.ExternalID)

		keys, err := d.accessKeys.ListByTenant(ctx, d.tenantID, accesskeystore.WithPrincipal("user-1"))
		require.NoError(t, err)
		require.Empty(t, keys, "the old keys are gone")
		_, err = d.policies.Get(ctx, alone)
		require.ErrorIs(t, err, store.ErrRecordNotFound, "no statement survives to restore the old access")
	})

	t.Run("a principal that is already gone is a no-op", func(t *testing.T) {
		d := setup(t)
		require.NoError(t, d.svc.Delete(ctx, "tenant-1", "user-1"))
		require.Empty(t, d.swarf.Revoked(), "nothing to revoke")
	})

	t.Run("a publish failure leaves the principal, its keys and its policies intact", func(t *testing.T) {
		d := setup(t)
		_, _, err := d.svc.Create(ctx, "tenant-1", "user-1")
		require.NoError(t, err)
		key := d.addKey(t, d.tenantID, "user-1", "laptop")
		bucket, etag := d.putPolicy(t, d.tenantID, bucketpolicy.Policy{Statements: []bucketpolicy.Statement{
			{Effect: bucketpolicy.Allow, Principal: bucketpolicy.Only("user-1"), Actions: []string{"s3:GetObject"}},
		}})
		d.swarf.Err = errors.New("swarf unreachable")

		err = d.svc.Delete(ctx, "tenant-1", "user-1")
		require.ErrorContains(t, err, "swarf unreachable")

		rec, err := d.svc.Get(ctx, "tenant-1", "user-1")
		require.NoError(t, err, "the principal row must survive")
		require.Equal(t, "user-1", rec.ExternalID)

		keys, err := d.accessKeys.ListByTenant(ctx, d.tenantID, accesskeystore.WithPrincipal("user-1"))
		require.NoError(t, err)
		require.Len(t, keys, 1, "its keys must survive")
		require.Equal(t, key, keys[0].ID)
		require.Len(t, d.held(t, key), 1, "its delegation must survive")
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
		d.swarf.Err = errors.New("swarf unreachable")
		require.Error(t, d.svc.Delete(ctx, "tenant-1", "user-1"))

		d.swarf.Err = nil
		require.NoError(t, d.svc.Delete(ctx, "tenant-1", "user-1"))
		require.Len(t, d.swarf.Revoked(), 1)
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

// vanishingPrincipals runs remove before the first Get, standing in for a
// removal that commits between a create's record and its read.
type vanishingPrincipals struct {
	principalstore.Store
	remove func()
}

func (v *vanishingPrincipals) Get(ctx context.Context, tenant did.DID, externalID string, opts ...store.ReadOption) (principalstore.Record, error) {
	if v.remove != nil {
		remove := v.remove
		v.remove = nil
		remove()
	}
	return v.Store.Get(ctx, tenant, externalID, opts...)
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

// lockTimeoutPrincipals answers Add with the store's lock timeout.
type lockTimeoutPrincipals struct {
	principalstore.Store
}

func (l *lockTimeoutPrincipals) Add(context.Context, did.DID, string) error {
	return fmt.Errorf("adding principal: %w", store.ErrLockTimeout)
}

// renamingPrincipals runs write before Delete locks the row, standing in for a
// policy write that names the principal between the strip and the lock.
type renamingPrincipals struct {
	principalstore.Store
	write func()
}

func (r *renamingPrincipals) Delete(ctx context.Context, tenant did.DID, externalID string, beforeCommit func(context.Context) error) error {
	r.write()
	return r.Store.Delete(ctx, tenant, externalID, beforeCommit)
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
			{Effect: bucketpolicy.Allow, Principal: bucketpolicy.Only("user-1", "user-2"), Actions: []string{"s3:GetObject"}},
		}})

		policies := &flakyPolicies{Store: d.policies, err: store.ErrPreconditionFailed}
		svc := principalsvc.New(zap.NewNop(), d.tenants, d.principals, policies, d.accessKeys, d.delegations, d.secrets, d.swarf, d.grants)
		require.ErrorIs(t, svc.Delete(ctx, "tenant-1", "user-1"), principalsvc.ErrConcurrentChange)

		rec, err := d.svc.Get(ctx, "tenant-1", "user-1")
		require.NoError(t, err, "the principal row must survive")
		require.Equal(t, "user-1", rec.ExternalID)
	})

	t.Run("the batch deadline hit while waiting is a retryable conflict", func(t *testing.T) {
		d := setup(t)
		_, _, err := d.svc.Create(ctx, "tenant-1", "user-1")
		require.NoError(t, err)
		_, _, err = d.svc.Create(ctx, "tenant-1", "user-2")
		require.NoError(t, err)
		d.putPolicy(t, d.tenantID, bucketpolicy.Policy{Statements: []bucketpolicy.Statement{
			{Effect: bucketpolicy.Allow, Principal: bucketpolicy.Only("user-1", "user-2"), Actions: []string{"s3:GetObject"}},
		}})

		// The removal's deadline is below the stores' lock timeout, so a wait
		// long enough reaches the caller as the context error.
		policies := &flakyPolicies{Store: d.policies, err: context.DeadlineExceeded}
		svc := principalsvc.New(zap.NewNop(), d.tenants, d.principals, policies, d.accessKeys, d.delegations, d.secrets, d.swarf, d.grants)
		require.ErrorIs(t, svc.Delete(ctx, "tenant-1", "user-1"), principalsvc.ErrConcurrentChange)

		rec, err := d.svc.Get(ctx, "tenant-1", "user-1")
		require.NoError(t, err, "the principal row must survive")
		require.Equal(t, "user-1", rec.ExternalID)
	})

	t.Run("a policy naming the principal again before its row is locked is a retryable conflict", func(t *testing.T) {
		d := setup(t)
		_, _, err := d.svc.Create(ctx, "tenant-1", "user-1")
		require.NoError(t, err)
		principals := &renamingPrincipals{Store: d.principals, write: func() {
			d.putPolicy(t, d.tenantID, bucketpolicy.Policy{Statements: []bucketpolicy.Statement{
				{Effect: bucketpolicy.Allow, Principal: bucketpolicy.Only("user-1"), Actions: []string{"s3:GetObject"}},
			}})
		}}
		svc := principalsvc.New(zap.NewNop(), d.tenants, principals, d.policies, d.accessKeys, d.delegations, d.secrets, d.swarf, d.grants)
		require.ErrorIs(t, svc.Delete(ctx, "tenant-1", "user-1"), principalsvc.ErrConcurrentChange)

		rec, err := d.svc.Get(ctx, "tenant-1", "user-1")
		require.NoError(t, err, "the principal row must survive")
		require.Equal(t, "user-1", rec.ExternalID)
	})

	t.Run("a lock the store gave up on is a retryable conflict", func(t *testing.T) {
		d := setup(t)
		principals := &lockedPrincipals{Store: d.principals, err: store.ErrLockTimeout}
		svc := principalsvc.New(zap.NewNop(), d.tenants, principals, d.policies, d.accessKeys, d.delegations, d.secrets, d.swarf, d.grants)
		require.ErrorIs(t, svc.Delete(ctx, "tenant-1", "user-1"), principalsvc.ErrConcurrentChange)
	})
}

// racingKeys runs race once, after the first Add commits, standing in for a
// removal of the key's principal that starts as the key's creation goes on to
// store its grants.
type racingKeys struct {
	accesskeystore.Store
	race  func()
	added did.DID
}

func (r *racingKeys) Add(ctx context.Context, in accesskeystore.Input) error {
	err := r.Store.Add(ctx, in)
	if err == nil && r.race != nil {
		r.added = in.ID
		race := r.race
		r.race = nil
		race()
	}
	return err
}

// removeBeforeAdd runs remove once, before the first Add, standing in for a
// removal that lists the principal's keys after the creation's principal
// lookup and before its key row is stored.
type removeBeforeAdd struct {
	accesskeystore.Store
	remove func()
}

func (r *removeBeforeAdd) Add(ctx context.Context, in accesskeystore.Input) error {
	if r.remove != nil {
		remove := r.remove
		r.remove = nil
		remove()
	}
	return r.Store.Add(ctx, in)
}

// pausingDelegations closes revoked once the first Replace made while armed
// returns, and parks there until released: a removal that has revoked under
// the principal's row lock and has not yet deleted the key rows.
type pausingDelegations struct {
	delegationstore.Store
	armed    bool
	revoked  chan struct{}
	released chan struct{}
}

func (p *pausingDelegations) Replace(ctx context.Context, audiences []did.DID, next func(context.Context, map[did.DID][]ucan.Delegation) (map[did.DID][]ucan.Delegation, error)) error {
	err := p.Store.Replace(ctx, audiences, next)
	if p.armed {
		p.armed = false
		close(p.revoked)
		<-p.released
	}
	return err
}

func TestDeleteDuringKeyCreate(t *testing.T) {
	ctx := t.Context()

	t.Run("a key created as the principal is removed is left no delegations", func(t *testing.T) {
		d := setup(t)
		_, _, err := d.svc.Create(ctx, "tenant-1", "user-1")
		require.NoError(t, err)
		// The wildcard policy survives the removal, so the creation has grants
		// to store.
		d.putPolicy(t, d.tenantID, bucketpolicy.Policy{Statements: []bucketpolicy.Statement{
			{Effect: bucketpolicy.Allow, Principal: bucketpolicy.Everyone(), Actions: []string{"s3:GetObject"}},
		}})

		// The removal starts once the key row is committed, and the creation
		// stores the key's grants while the removal, having revoked under the
		// principal's row lock, has not yet deleted the row.
		delegations := &pausingDelegations{Store: d.delegations, revoked: make(chan struct{}), released: make(chan struct{})}
		principals := &renamingPrincipals{Store: d.principals, write: func() { delegations.armed = true }}
		grants := grant.NewRotator(zap.NewNop(), delegations, d.accessKeys, d.secrets, d.swarf)
		removal := principalsvc.New(zap.NewNop(), d.tenants, principals, d.policies, d.accessKeys, delegations, d.secrets, d.swarf, grants)
		removed := make(chan error, 1)
		keys := &racingKeys{Store: d.accessKeys, race: func() {
			go func() { removed <- removal.Delete(ctx, "tenant-1", "user-1") }()
			<-delegations.revoked
		}}
		creator := accesskeysvc.New(zap.NewNop(), d.tenants, keys, d.principals, bucketmemory.New(), d.policies, delegations, d.secrets, d.swarf)

		_, _, _ = creator.Create(ctx, "tenant-1", "laptop", nil, nil, "user-1", nil)
		close(delegations.released)
		require.NoError(t, <-removed)

		_, err = d.accessKeys.Get(ctx, keys.added)
		require.ErrorIs(t, err, store.ErrRecordNotFound, "the key row is gone")
		require.Empty(t, d.held(t, keys.added), "no delegation outlives the key")
	})

	t.Run("a key stored after the removal listed the principal's keys is refused", func(t *testing.T) {
		d := setup(t)
		_, _, err := d.svc.Create(ctx, "tenant-1", "user-1")
		require.NoError(t, err)

		keys := &removeBeforeAdd{Store: d.accessKeys, remove: func() {
			require.NoError(t, d.svc.Delete(ctx, "tenant-1", "user-1"))
		}}
		creator := accesskeysvc.New(zap.NewNop(), d.tenants, keys, d.principals, bucketmemory.New(), d.policies, d.delegations, d.secrets, d.swarf)
		_, _, err = creator.Create(ctx, "tenant-1", "laptop", nil, nil, "user-1", nil)
		require.ErrorIs(t, err, accesskeysvc.ErrUnknownPrincipal)

		// The revived principal has no keys.
		_, _, err = d.svc.Create(ctx, "tenant-1", "user-1")
		require.NoError(t, err)
		recs, err := d.accessKeys.ListByTenant(ctx, d.tenantID, accesskeystore.WithPrincipal("user-1"))
		require.NoError(t, err)
		require.Empty(t, recs)
	})
}

// TestDeleteDuringPolicyWritePostgres removes a principal while a policy write
// that drops it is in flight, on Postgres. The write holds the bucket and then
// locks the principal, as its delegation rotation does. The removal rewrites
// the bucket's policy before it locks the principal, so neither waits on the
// other: the removal returns at once when the write commits, with the work
// done or a conflict the caller repeats.
func TestDeleteDuringPolicyWritePostgres(t *testing.T) {
	pool := testutil.PostgresOrSkip(t)
	ctx := t.Context()
	tenants, principals, policies := tenantpostgres.New(pool), principalpostgres.New(pool), bucketpolicypostgres.New(pool)
	accessKeys, secrets, swarf := accesskeypostgres.New(pool), vaultmemory.New(), &testutil.FakeSwarf{}

	tenantID, providerID, bucketID := testutil.RandomDID(t), testutil.RandomDID(t), testutil.RandomDID(t)
	require.NoError(t, providerpostgres.New(pool).Add(ctx, providerID, tenantID.String(), nil))
	require.NoError(t, tenants.Add(ctx, tenantID, "tenant-pg", providerID, tenant.Active))
	require.NoError(t, bucketpostgres.New(pool).Add(ctx, bucketID, tenantID, "principal-removal"))
	signer, err := secp256k1.Generate()
	require.NoError(t, err)
	require.NoError(t, secrets.Write(ctx, vault.TenantKeyPath(tenantID), signer.Bytes()))
	delegations := delegationpostgres.New(pool)
	grants := grant.NewRotator(zap.NewNop(), delegations, accessKeys, secrets, swarf)
	svc := principalsvc.New(zap.NewNop(), tenants, principals, policies, accessKeys, delegations, secrets, swarf, grants)

	_, _, err = svc.Create(ctx, "tenant-pg", "alice")
	require.NoError(t, err)
	_, _, err = svc.Create(ctx, "tenant-pg", "bob")
	require.NoError(t, err)
	statement := func(ids ...string) bucketpolicy.Policy {
		return bucketpolicy.Policy{Statements: []bucketpolicy.Statement{{Effect: bucketpolicy.Allow, Principal: bucketpolicy.Only(ids...), Actions: []string{"s3:GetObject"}}}}
	}
	etag, err := policies.Put(ctx, bucketpolicystore.Input{Bucket: bucketID, Tenant: tenantID, Policy: statement("alice", "bob")}, nil)
	require.NoError(t, err)

	var released, returned time.Time
	written, removed := testutil.RequireWaitsForWriter(t,
		func(entered chan<- struct{}, release <-chan struct{}) error {
			_, err := policies.Put(context.Background(), bucketpolicystore.Input{
				Bucket: bucketID, Tenant: tenantID, Policy: statement("bob"), IfMatch: &etag,
			}, func(ctx context.Context, _ *bucketpolicystore.Record) error {
				close(entered)
				<-release
				released = time.Now()
				return principals.Lock(ctx, tenantID, []string{"alice"}, func(context.Context) error { return nil })
			})
			return err
		},
		func() error {
			err := svc.Delete(context.Background(), "tenant-pg", "alice")
			returned = time.Now()
			return err
		})
	require.NoError(t, written)
	if removed != nil {
		require.ErrorIs(t, removed, principalsvc.ErrConcurrentChange)
	}
	require.Less(t, returned.Sub(released), grant.BatchTimeout/2, "the removal must not wait out the write")

	require.NoError(t, svc.Delete(ctx, "tenant-pg", "alice"), "a repeat finishes the removal")
	_, err = svc.Get(ctx, "tenant-pg", "alice")
	require.ErrorIs(t, err, principalsvc.ErrPrincipalNotFound)
	rec, err := policies.Get(ctx, bucketID)
	require.NoError(t, err)
	require.Equal(t, statement("bob"), rec.Policy)
}
