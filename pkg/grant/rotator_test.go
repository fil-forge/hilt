package grant_test

import (
	"context"
	"errors"
	htestutil "github.com/fil-forge/hilt/internal/testutil"
	"github.com/fil-forge/libforge/testutil"
	"testing"
	"time"

	"github.com/fil-forge/hilt/pkg/grant"
	"github.com/fil-forge/hilt/pkg/s3perm"
	accesskeystore "github.com/fil-forge/hilt/pkg/store/accesskey"
	accesskeymemory "github.com/fil-forge/hilt/pkg/store/accesskey/memory"
	delegationstore "github.com/fil-forge/hilt/pkg/store/delegation"
	delegationmemory "github.com/fil-forge/hilt/pkg/store/delegation/memory"
	"github.com/fil-forge/hilt/pkg/vault"
	vaultmemory "github.com/fil-forge/hilt/pkg/vault/memory"
	"github.com/fil-forge/ucantone/did"
	"github.com/fil-forge/ucantone/multikey"
	"github.com/fil-forge/ucantone/multikey/secp256k1"
	"github.com/fil-forge/ucantone/ucan"
	"github.com/ipfs/go-cid"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

type deps struct {
	rotator     *grant.Rotator
	delegations *delegationmemory.Store
	accessKeys  *accesskeymemory.Store
	secrets     *vaultmemory.Store
	swarf       *htestutil.FakeSwarf
	tenant      ucan.Issuer
	// photos and backups are the tenant's buckets.
	photos, backups did.DID
	// alice holds two keys, bob one. Every key holds s3:GetObject over photos
	// and s3:GetObject over backups at setup.
	alice, bob []did.DID
}

func setup(t *testing.T, expiresAt *time.Time) deps {
	t.Helper()
	ctx := t.Context()
	accessKeys, delegations, secrets := accesskeymemory.New(), delegationmemory.New(), vaultmemory.New()

	signer, err := secp256k1.Generate()
	require.NoError(t, err)
	tenantID := signer.KeyDID()
	tenant := multikey.NewIssuer(tenantID, signer)
	require.NoError(t, secrets.Write(ctx, vault.TenantKeyPath(tenantID), signer.Bytes()))

	d := deps{
		delegations: delegations,
		accessKeys:  accessKeys,
		secrets:     secrets,
		swarf:       &htestutil.FakeSwarf{},
		tenant:      tenant,
		photos:      testutil.RandomDID(t),
		backups:     testutil.RandomDID(t),
	}
	addKey := func(principal, name string) did.DID {
		id := testutil.RandomDID(t)
		require.NoError(t, accessKeys.Add(ctx, accesskeystore.Input{
			ID: id, Tenant: tenantID, Name: name, Principal: &principal, ExpiresAt: expiresAt,
		}))
		dels, err := grant.Issue(tenant, id, []did.DID{d.photos, d.backups}, []string{"s3:GetObject"}, expiresAt)
		require.NoError(t, err)
		require.NoError(t, delegations.PutBatch(ctx, dels))
		return id
	}
	d.alice = []did.DID{addKey("alice", "laptop"), addKey("alice", "phone")}
	d.bob = []did.DID{addKey("bob", "laptop")}
	d.rotator = grant.NewRotator(zap.NewNop(), delegations, accessKeys, secrets, d.swarf)
	return d
}

// deleteOnReplace runs del once the audiences are locked, before the callback.
type deleteOnReplace struct {
	delegationstore.Store
	del func(context.Context) error
}

func (s *deleteOnReplace) Replace(ctx context.Context, audiences []did.DID, next func(context.Context, map[did.DID][]ucan.Delegation) (map[did.DID][]ucan.Delegation, error)) error {
	return s.Store.Replace(ctx, audiences, func(ctx context.Context, current map[did.DID][]ucan.Delegation) (map[did.DID][]ucan.Delegation, error) {
		if err := s.del(ctx); err != nil {
			return nil, err
		}
		return next(ctx, current)
	})
}

// held returns the key's delegations over the bucket.
func (d deps) held(t *testing.T, key, bucket did.DID) []ucan.Delegation {
	t.Helper()
	page, err := d.delegations.ListByAudience(t.Context(), key)
	require.NoError(t, err)
	var out []ucan.Delegation
	for _, dlg := range page.Results {
		if dlg.Subject() == bucket {
			out = append(out, dlg)
		}
	}
	return out
}

func commands(dels []ucan.Delegation) []string {
	var out []string
	for _, d := range dels {
		out = append(out, d.Command().String())
	}
	return out
}

func commandsFor(actions ...string) []string {
	var out []string
	for _, c := range s3perm.CommandsFor(actions...) {
		out = append(out, c.String())
	}
	return out
}

func links(dels []ucan.Delegation) []cid.Cid {
	var out []cid.Cid
	for _, d := range dels {
		out = append(out, d.Link())
	}
	return out
}

func TestRotate(t *testing.T) {
	ctx := t.Context()

	t.Run("rewrites each key's delegations over the bucket and revokes the old ones in one request", func(t *testing.T) {
		d := setup(t, nil)
		var old []ucan.Delegation
		for _, key := range d.alice {
			old = append(old, d.held(t, key, d.photos)...)
		}
		require.NoError(t, d.rotator.Rotate(ctx, d.tenant.DID(), d.photos, map[string][]string{"alice": {"s3:PutObject"}}))

		require.Len(t, d.swarf.Batches(), 1, "every revocation of the write goes in one request")
		require.Equal(t, d.tenant.DID(), d.swarf.Batches()[0][0].Revoker)
		require.ElementsMatch(t, links(old), d.swarf.Revoked())
		for _, key := range d.alice {
			held := d.held(t, key, d.photos)
			require.ElementsMatch(t, commandsFor("s3:PutObject"), commands(held))
			for _, m := range held {
				require.Equal(t, d.tenant.DID(), m.Issuer())
				require.Equal(t, key, m.Audience())
				require.Nil(t, m.Expiration())
			}
			require.ElementsMatch(t, commandsFor("s3:GetObject"), commands(d.held(t, key, d.backups)), "other buckets are untouched")
		}
		require.ElementsMatch(t, commandsFor("s3:GetObject"), commands(d.held(t, d.bob[0], d.photos)), "bob's key is untouched")
	})

	t.Run("the fresh delegations expire with the key", func(t *testing.T) {
		exp := time.Now().Add(time.Hour).UTC().Truncate(time.Second)
		d := setup(t, &exp)
		require.NoError(t, d.rotator.Rotate(ctx, d.tenant.DID(), d.photos, map[string][]string{"bob": {"s3:PutObject"}}))

		held := d.held(t, d.bob[0], d.photos)
		require.NotEmpty(t, held)
		for _, m := range held {
			require.NotNil(t, m.Expiration())
			require.Equal(t, ucan.UnixTimestamp(exp.Unix()), *m.Expiration())
		}
	})

	t.Run("a first grant over a bucket publishes nothing", func(t *testing.T) {
		d := setup(t, nil)
		videos := testutil.RandomDID(t)
		require.NoError(t, d.rotator.Rotate(ctx, d.tenant.DID(), videos, map[string][]string{"alice": {"s3:GetObject"}, "bob": {"s3:GetObject"}}))

		require.Empty(t, d.swarf.Batches())
		for _, key := range append(d.alice, d.bob...) {
			require.ElementsMatch(t, commandsFor("s3:GetObject"), commands(d.held(t, key, videos)))
		}
	})

	t.Run("an empty action set leaves the key with nothing over the bucket", func(t *testing.T) {
		d := setup(t, nil)
		old := d.held(t, d.bob[0], d.photos)
		require.NoError(t, d.rotator.Rotate(ctx, d.tenant.DID(), d.photos, map[string][]string{"bob": nil}))

		require.ElementsMatch(t, links(old), d.swarf.Revoked())
		require.Empty(t, d.held(t, d.bob[0], d.photos))
		require.NotEmpty(t, d.held(t, d.bob[0], d.backups))
	})

	t.Run("a publish failure leaves every key unchanged", func(t *testing.T) {
		d := setup(t, nil)
		d.swarf.Err = errors.New("swarf is down")
		before := map[did.DID][]cid.Cid{}
		for _, key := range append(d.alice, d.bob...) {
			before[key] = links(d.held(t, key, d.photos))
		}

		err := d.rotator.Rotate(ctx, d.tenant.DID(), d.photos, map[string][]string{"alice": {"s3:PutObject"}, "bob": nil})
		require.ErrorContains(t, err, "swarf is down")
		for key, want := range before {
			require.Equal(t, want, links(d.held(t, key, d.photos)))
		}
	})

	t.Run("an expired delegation is replaced without a revocation", func(t *testing.T) {
		exp := time.Now().Add(-time.Hour)
		d := setup(t, &exp)
		require.NoError(t, d.rotator.Rotate(ctx, d.tenant.DID(), d.photos, map[string][]string{"bob": {"s3:PutObject"}}))

		require.Empty(t, d.swarf.Batches())
		require.ElementsMatch(t, commandsFor("s3:PutObject"), commands(d.held(t, d.bob[0], d.photos)))
	})

	t.Run("a key deleted while the rotation waited on the lock gets nothing", func(t *testing.T) {
		d := setup(t, nil)
		gone, kept := d.alice[0], d.alice[1]
		// The key goes between the rotation's listing and its lock, as a
		// concurrent removal holding the lock first would have it.
		dels := &deleteOnReplace{Store: d.delegations, del: func(ctx context.Context) error { return d.accessKeys.Delete(ctx, gone) }}
		rotator := grant.NewRotator(zap.NewNop(), dels, d.accessKeys, d.secrets, d.swarf)
		require.NoError(t, rotator.Rotate(ctx, d.tenant.DID(), d.photos, map[string][]string{"alice": {"s3:PutObject"}}))

		require.Empty(t, d.held(t, gone, d.photos))
		require.ElementsMatch(t, commandsFor("s3:PutObject"), commands(d.held(t, kept, d.photos)))
	})

	t.Run("a principal without keys is a no-op", func(t *testing.T) {
		d := setup(t, nil)
		require.NoError(t, d.rotator.Rotate(ctx, d.tenant.DID(), d.photos, map[string][]string{"ghost": {"s3:GetObject"}}))
		require.Empty(t, d.swarf.Batches())
	})
}

func TestRevoke(t *testing.T) {
	ctx := t.Context()

	t.Run("revokes every delegation of each key in one request and leaves the keys with none", func(t *testing.T) {
		d := setup(t, nil)
		var old []ucan.Delegation
		for _, key := range d.alice {
			page, err := d.delegations.ListByAudience(ctx, key)
			require.NoError(t, err)
			old = append(old, page.Results...)
		}
		require.NoError(t, d.rotator.Revoke(ctx, d.tenant.DID(), "alice"))

		require.Len(t, d.swarf.Batches(), 1)
		require.Equal(t, d.tenant.DID(), d.swarf.Batches()[0][0].Revoker)
		require.ElementsMatch(t, links(old), d.swarf.Revoked())
		for _, key := range d.alice {
			page, err := d.delegations.ListByAudience(ctx, key)
			require.NoError(t, err)
			require.Empty(t, page.Results)
		}
		require.NotEmpty(t, d.held(t, d.bob[0], d.photos))
	})

	t.Run("a publish failure leaves the delegations in place", func(t *testing.T) {
		d := setup(t, nil)
		d.swarf.Err = errors.New("swarf is down")

		require.ErrorContains(t, d.rotator.Revoke(ctx, d.tenant.DID(), "alice"), "swarf is down")
		for _, key := range d.alice {
			require.NotEmpty(t, d.held(t, key, d.photos))
		}
	})
}
