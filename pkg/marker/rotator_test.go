package marker_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/fil-forge/hilt/pkg/marker"
	accesskeystore "github.com/fil-forge/hilt/pkg/store/accesskey"
	accesskeymemory "github.com/fil-forge/hilt/pkg/store/accesskey/memory"
	delegationmemory "github.com/fil-forge/hilt/pkg/store/delegation/memory"
	"github.com/fil-forge/hilt/pkg/vault"
	vaultmemory "github.com/fil-forge/hilt/pkg/vault/memory"
	"github.com/fil-forge/libforge/commands/s3/key"
	swarfclient "github.com/fil-forge/swarf/pkg/client"
	"github.com/fil-forge/ucantone/did"
	"github.com/fil-forge/ucantone/multikey"
	"github.com/fil-forge/ucantone/multikey/ed25519"
	"github.com/fil-forge/ucantone/multikey/secp256k1"
	"github.com/fil-forge/ucantone/ucan"
	"github.com/ipfs/go-cid"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

// revocation records one published revocation. options counts the
// [swarfclient.PublishOption]s it was published with: Swarf's publishConfig is
// unexported, so the count is how the nonce option being sent is detected.
type revocation struct {
	revoker did.DID
	revoked cid.Cid
	options int
}

type fakeSwarf struct {
	err         error
	revocations []revocation
}

func (f *fakeSwarf) Publish(_ context.Context, revoker ucan.Issuer, revoked ucan.Delegation, opts ...swarfclient.PublishOption) error {
	if f.err != nil {
		return f.err
	}
	f.revocations = append(f.revocations, revocation{revoker: revoker.DID(), revoked: revoked.Link(), options: len(opts)})
	return nil
}

type deps struct {
	rotator     *marker.Rotator
	delegations *delegationmemory.Store
	swarf       *fakeSwarf
	tenant      ucan.Issuer
	// keys holds each key's marker at setup, by key DID.
	keys map[did.DID]ucan.Delegation
	// alice holds two keys, bob one.
	alice, bob []did.DID
}

// setup wires a rotator over memory stores with one tenant whose key is in the
// vault, two principals ("alice" with two keys, "bob" with one), and a marker
// stored for each key. expiresAt, when given, is every key's expiry.
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
		swarf:       &fakeSwarf{},
		tenant:      tenant,
		keys:        map[did.DID]ucan.Delegation{},
	}
	addKey := func(principal, name string) did.DID {
		keySigner, err := ed25519.Generate()
		require.NoError(t, err)
		id := keySigner.KeyDID()
		require.NoError(t, accessKeys.Add(ctx, accesskeystore.Input{
			ID: id, Tenant: tenantID, Name: name, Principal: &principal, ExpiresAt: expiresAt,
		}))
		m, err := marker.Issue(tenant, id, tenantID, expiresAt)
		require.NoError(t, err)
		require.NoError(t, delegations.PutBatch(ctx, []ucan.Delegation{m}))
		d.keys[id] = m
		return id
	}
	d.alice = []did.DID{addKey("alice", "laptop"), addKey("alice", "phone")}
	d.bob = []did.DID{addKey("bob", "laptop")}
	d.rotator = marker.NewRotator(zap.NewNop(), delegations, accessKeys, secrets, d.swarf)
	return d
}

func (d deps) held(t *testing.T, key did.DID) []ucan.Delegation {
	t.Helper()
	page, err := d.delegations.ListByAudience(t.Context(), key)
	require.NoError(t, err)
	return page.Results
}

func TestRotate(t *testing.T) {
	ctx := t.Context()

	t.Run("replaces the marker of each of the principal's keys", func(t *testing.T) {
		d := setup(t, nil)
		require.NoError(t, d.rotator.Rotate(ctx, d.tenant.DID(), []string{"alice"}))

		revoked := map[cid.Cid]bool{}
		for _, r := range d.swarf.revocations {
			require.Equal(t, d.tenant.DID(), r.revoker)
			require.Equal(t, 1, r.options, "the revocation carries a nonce")
			revoked[r.revoked] = true
		}
		require.Len(t, revoked, 2)
		for _, keyID := range d.alice {
			old := d.keys[keyID]
			require.True(t, revoked[old.Link()], "the old marker of %s is revoked", keyID)
			held := d.held(t, keyID)
			require.Len(t, held, 1)
			m := held[0]
			require.NotEqual(t, old.Link(), m.Link(), "the marker is a fresh delegation")
			require.Equal(t, d.tenant.DID(), m.Issuer())
			require.Equal(t, keyID, m.Audience())
			require.Equal(t, d.tenant.DID(), m.Subject())
			require.Equal(t, key.Marker.Command, m.Command())
			require.Nil(t, m.Expiration())
		}
		// bob's key is untouched.
		held := d.held(t, d.bob[0])
		require.Len(t, held, 1)
		require.Equal(t, d.keys[d.bob[0]].Link(), held[0].Link())
	})

	t.Run("the fresh marker expires with the key", func(t *testing.T) {
		exp := time.Now().Add(time.Hour).UTC().Truncate(time.Second)
		d := setup(t, &exp)
		require.NoError(t, d.rotator.Rotate(ctx, d.tenant.DID(), []string{"bob"}))

		held := d.held(t, d.bob[0])
		require.Len(t, held, 1)
		require.NotNil(t, held[0].Expiration())
		require.Equal(t, ucan.UnixTimestamp(exp.Unix()), *held[0].Expiration())
	})

	t.Run("rotates every listed principal", func(t *testing.T) {
		d := setup(t, nil)
		require.NoError(t, d.rotator.Rotate(ctx, d.tenant.DID(), []string{"alice", "bob"}))
		require.Len(t, d.swarf.revocations, 3)
		for key, old := range d.keys {
			held := d.held(t, key)
			require.Len(t, held, 1)
			require.NotEqual(t, old.Link(), held[0].Link())
		}
	})

	t.Run("a publish failure leaves the marker unchanged", func(t *testing.T) {
		d := setup(t, nil)
		d.swarf.err = errors.New("swarf is down")

		err := d.rotator.Rotate(ctx, d.tenant.DID(), []string{"alice"})
		require.ErrorContains(t, err, "swarf is down")

		for key, old := range d.keys {
			held := d.held(t, key)
			require.Len(t, held, 1)
			require.Equal(t, old.Link(), held[0].Link())
		}
	})

	t.Run("a key holding no marker is left with none", func(t *testing.T) {
		d := setup(t, nil)
		// The key was deleted between the caller's read and the rotation.
		require.NoError(t, d.delegations.DeleteByAudience(ctx, d.alice[0]))

		require.NoError(t, d.rotator.Rotate(ctx, d.tenant.DID(), []string{"alice"}))

		require.Empty(t, d.held(t, d.alice[0]))
		require.Len(t, d.held(t, d.alice[1]), 1)
		require.Len(t, d.swarf.revocations, 1)
	})

	t.Run("an expired marker is replaced without a revocation", func(t *testing.T) {
		exp := time.Now().Add(-time.Hour)
		d := setup(t, &exp)

		require.NoError(t, d.rotator.Rotate(ctx, d.tenant.DID(), []string{"bob"}))

		require.Empty(t, d.swarf.revocations)
		held := d.held(t, d.bob[0])
		require.Len(t, held, 1)
		require.NotEqual(t, d.keys[d.bob[0]].Link(), held[0].Link())
	})

	t.Run("a principal without keys is a no-op", func(t *testing.T) {
		d := setup(t, nil)
		require.NoError(t, d.rotator.Rotate(ctx, d.tenant.DID(), []string{"ghost"}))
		require.Empty(t, d.swarf.revocations)
	})
}

func TestRevoke(t *testing.T) {
	ctx := t.Context()

	t.Run("revokes each key's marker and leaves the keys with none", func(t *testing.T) {
		d := setup(t, nil)
		require.NoError(t, d.rotator.Revoke(ctx, d.tenant.DID(), "alice"))

		require.Len(t, d.swarf.revocations, 2)
		revoked := map[cid.Cid]bool{}
		for _, r := range d.swarf.revocations {
			require.Equal(t, d.tenant.DID(), r.revoker)
			require.Equal(t, 1, r.options, "the revocation carries a nonce")
			revoked[r.revoked] = true
		}
		for _, key := range d.alice {
			require.True(t, revoked[d.keys[key].Link()])
			require.Empty(t, d.held(t, key))
		}
		require.Len(t, d.held(t, d.bob[0]), 1)
	})

	t.Run("a publish failure leaves the markers in place", func(t *testing.T) {
		d := setup(t, nil)
		d.swarf.err = errors.New("swarf is down")

		require.ErrorContains(t, d.rotator.Revoke(ctx, d.tenant.DID(), "alice"), "swarf is down")
		for _, key := range d.alice {
			require.Len(t, d.held(t, key), 1)
		}
	})
}
