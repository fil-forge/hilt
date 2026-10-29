package principal_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	s3bkt "github.com/fil-forge/libforge/commands/s3/bucket"

	"github.com/fil-forge/hilt/internal/testutil"
	accesskeysvc "github.com/fil-forge/hilt/pkg/api/service/accesskey"
	principalsvc "github.com/fil-forge/hilt/pkg/api/service/principal"
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
	"github.com/ipfs/go-cid"
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
	d.svc = principalsvc.New(zap.NewNop(), d.tenants, d.principals, d.policies, d.accessKeys, d.delegations, d.secrets, d.grants)
	return d
}

// putPolicy stores a bucket policy for the tenant and returns the bucket.
func (d deps) putPolicy(t *testing.T, tenantID did.DID, doc s3bkt.PolicyDocument) did.DID {
	t.Helper()
	bucket := testutil.RandomDID(t)
	require.NoError(t, d.policies.Put(t.Context(), bucketpolicystore.Input{Bucket: bucket, Tenant: tenantID, Policy: doc}, nil))
	return bucket
}

// policyOf builds a policy of one statement over the "photos" bucket.
func policyOf(effect s3bkt.Effect, principal s3bkt.Principal, action string) s3bkt.PolicyDocument {
	return s3bkt.PolicyDocument{Version: s3bkt.Version2012, Statements: []s3bkt.Statement{
		{Effect: effect, Principal: principal, Actions: s3bkt.NewStringSet(action), Resources: s3bkt.NewStringSet(s3bkt.BucketARN("photos"), s3bkt.ObjectsARN("photos"))},
	}}
}

// links returns the CID of each delegation.
func links(dels []ucan.Delegation) []cid.Cid {
	out := make([]cid.Cid, len(dels))
	for i, d := range dels {
		out[i] = d.Link()
	}
	return out
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

	t.Run("returns not found when a removal commits between the record and its read", func(t *testing.T) {
		d := setup(t)
		principals := &vanishingPrincipals{Store: d.principals, remove: func() {
			require.NoError(t, d.svc.Delete(ctx, "tenant-1", "user-1"))
		}}
		svc := principalsvc.New(zap.NewNop(), d.tenants, principals, d.policies, d.accessKeys, d.delegations, d.secrets, d.grants)
		_, _, err := svc.Create(ctx, "tenant-1", "user-1")
		require.ErrorIs(t, err, store.ErrRecordNotFound)
	})

	t.Run("rejects the reserved policy wildcard", func(t *testing.T) {
		d := setup(t)
		_, _, err := d.svc.Create(ctx, "tenant-1", s3bkt.Wildcard)
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

	t.Run("strips the principal from policies and deletes its keys, leaving other principals' alone", func(t *testing.T) {
		d := setup(t)
		for _, id := range []string{"user-1", "user-2"} {
			_, _, err := d.svc.Create(ctx, "tenant-1", id)
			require.NoError(t, err)
		}
		key := d.addKey(t, d.tenantID, "user-1", "laptop")
		kept := d.addKey(t, d.tenantID, "user-2", "desktop")
		keptHeld := d.held(t, kept)

		// A policy the principal shares, one it holds alone, and one that reaches
		// it only through the wildcard.
		shared := d.putPolicy(t, d.tenantID, s3bkt.PolicyDocument{Version: s3bkt.Version2012, Statements: []s3bkt.Statement{
			policyOf(s3bkt.Allow, s3bkt.Only("user-1", "user-2"), "s3:GetObject").Statements[0],
			policyOf(s3bkt.Deny, s3bkt.Only("user-1"), "s3:DeleteObject").Statements[0],
		}})
		alone := d.putPolicy(t, d.tenantID, policyOf(s3bkt.Allow, s3bkt.Only("user-1"), "s3:PutObject"))
		everyone := d.putPolicy(t, d.tenantID, policyOf(s3bkt.Allow, s3bkt.Everyone(), "s3:ListBucket"))

		require.NoError(t, d.svc.Delete(ctx, "tenant-1", "user-1"))

		_, err := d.svc.Get(ctx, "tenant-1", "user-1")
		require.ErrorIs(t, err, principalsvc.ErrPrincipalNotFound)

		// Its key, its delegations and its vault entry are gone; another
		// principal's are not.
		_, err = d.accessKeys.Get(ctx, key)
		require.ErrorIs(t, err, store.ErrRecordNotFound)
		require.Empty(t, d.held(t, key))
		_, err = d.secrets.Read(ctx, vault.AccessKeyPath(d.tenantID, key))
		require.ErrorIs(t, err, vault.ErrNotFound)
		_, err = d.accessKeys.Get(ctx, kept)
		require.NoError(t, err)
		require.Equal(t, keptHeld, d.held(t, kept))

		// The shared policy keeps the other principal and loses the statement the
		// removed one held alone.
		rec, err := d.policies.Get(ctx, shared)
		require.NoError(t, err)
		require.Equal(t, policyOf(s3bkt.Allow, s3bkt.Only("user-2"), "s3:GetObject"), rec.Policy)

		// The policy naming it alone is deleted with its last statement.
		_, err = d.policies.Get(ctx, alone)
		require.ErrorIs(t, err, store.ErrRecordNotFound)

		// The wildcard policy is untouched: it names the tenant's principals, and
		// this one is no longer among them.
		rec, err = d.policies.Get(ctx, everyone)
		require.NoError(t, err)
		require.Equal(t, policyOf(s3bkt.Allow, s3bkt.Everyone(), "s3:ListBucket"), rec.Policy)
	})

	t.Run("revokes every delegation of the principal's keys once, while the store still holds them", func(t *testing.T) {
		d := setup(t)
		_, _, err := d.svc.Create(ctx, "tenant-1", "user-1")
		require.NoError(t, err)
		first := d.addKey(t, d.tenantID, "user-1", "key-a")
		second := d.addKey(t, d.tenantID, "user-1", "key-b")
		want := links(append(d.held(t, first), d.held(t, second)...))

		var heldAtPublish []ucan.Delegation
		d.swarf.OnPublish = func() {
			heldAtPublish = append(d.held(t, first), d.held(t, second)...)
		}
		require.NoError(t, d.svc.Delete(ctx, "tenant-1", "user-1"))

		require.ElementsMatch(t, want, d.swarf.Revoked())
		require.ElementsMatch(t, want, links(heldAtPublish), "the revocations go out before the delegations are removed")
	})

	t.Run("a removed principal is revived by Create with nothing attached", func(t *testing.T) {
		d := setup(t)
		_, _, err := d.svc.Create(ctx, "tenant-1", "user-1")
		require.NoError(t, err)
		d.addKey(t, d.tenantID, "user-1", "laptop")
		alone := d.putPolicy(t, d.tenantID, policyOf(s3bkt.Allow, s3bkt.Only("user-1"), "s3:GetObject"))
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

	t.Run("returns the publish error and leaves the principal, its keys and its policies unchanged when publishing their revocations fails", func(t *testing.T) {
		d := setup(t)
		_, _, err := d.svc.Create(ctx, "tenant-1", "user-1")
		require.NoError(t, err)
		key := d.addKey(t, d.tenantID, "user-1", "laptop")
		keyHeld := d.held(t, key)
		bucket := d.putPolicy(t, d.tenantID, policyOf(s3bkt.Allow, s3bkt.Only("user-1"), "s3:GetObject"))
		unreachable := errors.New("swarf unreachable")
		d.swarf.Err = unreachable

		require.ErrorIs(t, d.svc.Delete(ctx, "tenant-1", "user-1"), unreachable)

		require.Equal(t, keyHeld, d.held(t, key), "the revoke rolled back with its publish")
		_, err = d.svc.Get(ctx, "tenant-1", "user-1")
		require.NoError(t, err)
		_, err = d.accessKeys.Get(ctx, key)
		require.NoError(t, err)
		_, err = d.secrets.Read(ctx, vault.AccessKeyPath(d.tenantID, key))
		require.NoError(t, err, "the key still signs")
		rec, err := d.policies.Get(ctx, bucket)
		require.NoError(t, err)
		require.Equal(t, policyOf(s3bkt.Allow, s3bkt.Only("user-1"), "s3:GetObject"), rec.Policy)
	})

	t.Run("returns the publish error and keeps the principal and its keys when publishing what its keys gained fails", func(t *testing.T) {
		d := setup(t)
		_, _, err := d.svc.Create(ctx, "tenant-1", "user-1")
		require.NoError(t, err)
		key := d.addKey(t, d.tenantID, "user-1", "laptop")
		revokedFirst := links(d.held(t, key))
		unreachable := errors.New("swarf unreachable")
		// After the first revocation went out, the key gains a delegation, and
		// Swarf becomes unreachable before the removal publishes its revocation.
		var gained []ucan.Delegation
		principals := &renamingPrincipals{Store: d.principals, write: func() {
			gained, err = grant.Issue(d.tenant, key, []did.DID{testutil.RandomDID(t)}, []string{"s3:GetObject"}, nil)
			require.NoError(t, err)
			require.NoError(t, d.delegations.PutBatch(ctx, gained))
			d.swarf.Err = unreachable
		}}
		svc := principalsvc.New(zap.NewNop(), d.tenants, principals, d.policies, d.accessKeys, d.delegations, d.secrets, d.grants)

		require.ErrorIs(t, svc.Delete(ctx, "tenant-1", "user-1"), unreachable)

		_, err = d.svc.Get(ctx, "tenant-1", "user-1")
		require.NoError(t, err)
		_, err = d.accessKeys.Get(ctx, key)
		require.NoError(t, err)
		require.Equal(t, links(gained), links(d.held(t, key)), "the gained delegation is neither revoked nor removed")
		require.Equal(t, revokedFirst, d.swarf.Revoked())
	})

	t.Run("rejects an unknown tenant", func(t *testing.T) {
		d := setup(t)
		require.ErrorIs(t, d.svc.Delete(ctx, "missing", "user-1"), principalsvc.ErrTenantNotFound)
	})

	t.Run("revokes and deletes every key, including one created since, when repeated after a failed publish", func(t *testing.T) {
		d := setup(t)
		_, _, err := d.svc.Create(ctx, "tenant-1", "user-1")
		require.NoError(t, err)
		first := d.addKey(t, d.tenantID, "user-1", "laptop")
		firstHeld := d.held(t, first)
		unreachable := errors.New("swarf unreachable")
		d.swarf.Err = unreachable
		require.ErrorIs(t, d.svc.Delete(ctx, "tenant-1", "user-1"), unreachable)

		d.swarf.Err = nil
		later := d.addKey(t, d.tenantID, "user-1", "desktop")
		want := links(append(firstHeld, d.held(t, later)...))
		require.NoError(t, d.svc.Delete(ctx, "tenant-1", "user-1"))

		require.ElementsMatch(t, want, d.swarf.Revoked())
		recs, err := d.accessKeys.ListByTenant(ctx, d.tenantID, accesskeystore.WithPrincipal("user-1"))
		require.NoError(t, err)
		require.Empty(t, recs)
	})
}

// vanishingPrincipals runs remove before the first Get, standing in for a
// removal that commits between a create's record and its read.
type vanishingPrincipals struct {
	principalstore.Store
	remove func()
}

func (v *vanishingPrincipals) Get(ctx context.Context, tenant did.DID, externalID string) (principalstore.Record, error) {
	if v.remove != nil {
		remove := v.remove
		v.remove = nil
		remove()
	}
	return v.Store.Get(ctx, tenant, externalID)
}

// renamingPrincipals runs write before Tombstone, standing in for a write that
// lands between the removal's revoke and its tombstone.
type renamingPrincipals struct {
	principalstore.Store
	write func()
}

func (r *renamingPrincipals) Tombstone(ctx context.Context, tenant did.DID, externalID string, fn func(context.Context) error) error {
	r.write()
	return r.Store.Tombstone(ctx, tenant, externalID, fn)
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
// returns, and parks there until released: a removal that has deleted the
// key rows and their delegations inside its tombstone write, which has not
// yet committed.
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
		d.putPolicy(t, d.tenantID, s3bkt.PolicyDocument{Version: s3bkt.Version2012, Statements: []s3bkt.Statement{
			{Effect: s3bkt.Allow, Principal: s3bkt.Everyone(), Actions: s3bkt.NewStringSet("s3:GetObject"), Resources: s3bkt.NewStringSet(s3bkt.BucketARN("photos"), s3bkt.ObjectsARN("photos"))},
		}})

		// The removal starts once the key row is committed, and the creation
		// stores the key's grants while the removal's tombstone write, having
		// deleted the key, has not yet returned.
		delegations := &pausingDelegations{Store: d.delegations, revoked: make(chan struct{}), released: make(chan struct{})}
		principals := &renamingPrincipals{Store: d.principals, write: func() { delegations.armed = true }}
		grants := grant.NewRotator(zap.NewNop(), delegations, d.accessKeys, d.secrets, d.swarf)
		removal := principalsvc.New(zap.NewNop(), d.tenants, principals, d.policies, d.accessKeys, delegations, d.secrets, grants)
		removed := make(chan error, 1)
		keys := &racingKeys{Store: d.accessKeys, race: func() {
			go func() { removed <- removal.Delete(ctx, "tenant-1", "user-1") }()
			<-delegations.revoked
		}}
		creator := accesskeysvc.New(zap.NewNop(), d.tenants, keys, d.principals, bucketmemory.New(), d.policies, delegations, d.secrets, d.swarf)

		_, _, _ = creator.Create(ctx, "tenant-1", "laptop", nil, nil, new("user-1"), nil)
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
		_, _, err = creator.Create(ctx, "tenant-1", "laptop", nil, nil, new("user-1"), nil)
		require.ErrorIs(t, err, accesskeysvc.ErrUnknownPrincipal)

		// The revived principal has no keys.
		_, _, err = d.svc.Create(ctx, "tenant-1", "user-1")
		require.NoError(t, err)
		recs, err := d.accessKeys.ListByTenant(ctx, d.tenantID, accesskeystore.WithPrincipal("user-1"))
		require.NoError(t, err)
		require.Empty(t, recs)
	})
}

// TestDeletePostgres removes a principal on Postgres.
func TestDeletePostgres(t *testing.T) {
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
	issuer := multikey.NewIssuer(tenantID, signer)
	delegations := delegationpostgres.New(pool)
	grants := grant.NewRotator(zap.NewNop(), delegations, accessKeys, secrets, swarf)
	svc := principalsvc.New(zap.NewNop(), tenants, principals, policies, accessKeys, delegations, secrets, grants)

	for _, id := range []string{"any-user", "other-user"} {
		_, _, err = svc.Create(ctx, "tenant-pg", id)
		require.NoError(t, err)
	}
	require.NoError(t, policies.Put(ctx, bucketpolicystore.Input{Bucket: bucketID, Tenant: tenantID, Policy: policyOf(s3bkt.Allow, s3bkt.Only("any-user", "other-user"), "s3:GetObject")}, nil))
	keySigner, err := ed25519.Generate()
	require.NoError(t, err)
	key := keySigner.KeyDID()
	require.NoError(t, accessKeys.Add(ctx, accesskeystore.Input{ID: key, Tenant: tenantID, Name: "laptop", Principal: new("any-user")}))
	dels, err := grant.Issue(issuer, key, []did.DID{bucketID}, []string{"s3:GetObject"}, nil)
	require.NoError(t, err)
	require.NoError(t, delegations.PutBatch(ctx, dels))

	require.NoError(t, svc.Delete(ctx, "tenant-pg", "any-user"))

	_, err = svc.Get(ctx, "tenant-pg", "any-user")
	require.ErrorIs(t, err, principalsvc.ErrPrincipalNotFound)
	_, err = accessKeys.Get(ctx, key)
	require.ErrorIs(t, err, store.ErrRecordNotFound)
	page, err := delegations.ListByAudience(ctx, key)
	require.NoError(t, err)
	require.Empty(t, page.Results)
	require.ElementsMatch(t, links(dels), swarf.Revoked())
	rec, err := policies.Get(ctx, bucketID)
	require.NoError(t, err)
	require.Equal(t, policyOf(s3bkt.Allow, s3bkt.Only("other-user"), "s3:GetObject"), rec.Policy)
}
