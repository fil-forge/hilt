package grant_test

import (
	"context"
	"errors"
	"slices"
	"testing"
	"time"

	htestutil "github.com/fil-forge/hilt/internal/testutil"
	"github.com/fil-forge/libforge/testutil"

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

// deadlinePublisher records how long each publish had left on its deadline,
// zero when it had none.
type deadlinePublisher struct {
	*htestutil.FakeSwarf
	remaining []time.Duration
}

func (p *deadlinePublisher) PublishBatch(ctx context.Context, revoker ucan.Issuer, revoked []ucan.Delegation) error {
	var left time.Duration
	if deadline, ok := ctx.Deadline(); ok {
		left = time.Until(deadline)
	}
	p.remaining = append(p.remaining, left)
	return p.FakeSwarf.PublishBatch(ctx, revoker, revoked)
}

// deleteOnReplace runs del inside the replacement, before the callback, as a
// key removal committing between the rotation's listing and its read would.
type deleteOnReplace struct {
	delegationstore.Store
	del func(context.Context) error
}

func (s *deleteOnReplace) ReplaceBySubject(ctx context.Context, subject did.DID, audiences []did.DID, next func(context.Context, map[did.DID][]ucan.Delegation) (map[did.DID][]ucan.Delegation, error)) error {
	return s.Store.ReplaceBySubject(ctx, subject, audiences, func(ctx context.Context, current map[did.DID][]ucan.Delegation) (map[did.DID][]ucan.Delegation, error) {
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

	t.Run("revokes the delegations over the bucket it replaces in one request", func(t *testing.T) {
		d := setup(t, nil)
		var old []ucan.Delegation
		for _, key := range d.alice {
			old = append(old, d.held(t, key, d.photos)...)
		}

		require.NoError(t, d.rotator.Rotate(ctx, d.tenant.DID(), d.photos, map[string][]string{"alice": {"s3:PutObject"}}))
		require.Len(t, d.swarf.Batches(), 1)
		require.ElementsMatch(t, links(old), d.swarf.Revoked())
	})

	t.Run("a publish failure returns the error and leaves every key's delegations unchanged", func(t *testing.T) {
		d := setup(t, nil)
		before := map[did.DID][]cid.Cid{}
		for _, key := range d.alice {
			before[key] = links(d.held(t, key, d.photos))
		}
		swarfDown := errors.New("swarf is down")
		d.swarf.Err = swarfDown

		require.ErrorIs(t, d.rotator.Rotate(ctx, d.tenant.DID(), d.photos, map[string][]string{"alice": {"s3:PutObject"}}), swarfDown)
		after := map[did.DID][]cid.Cid{}
		for _, key := range d.alice {
			after[key] = links(d.held(t, key, d.photos))
		}
		require.Equal(t, before, after)
	})

	t.Run("stores each key's delegations for the new actions over the bucket", func(t *testing.T) {
		d := setup(t, nil)

		require.NoError(t, d.rotator.Rotate(ctx, d.tenant.DID(), d.photos, map[string][]string{"alice": {"s3:PutObject"}}))
		for _, key := range d.alice {
			held := d.held(t, key, d.photos)
			require.ElementsMatch(t, commandsFor("s3:PutObject"), commands(held))
			for _, m := range held {
				require.Equal(t, d.tenant.DID(), m.Issuer())
				require.Equal(t, key, m.Audience())
				require.Nil(t, m.Expiration())
			}
		}
	})

	t.Run("leaves a key's delegations over other buckets and other principals' keys untouched", func(t *testing.T) {
		d := setup(t, nil)
		untouched := map[did.DID][]cid.Cid{}
		for _, key := range d.alice {
			untouched[key] = links(d.held(t, key, d.backups))
		}
		untouched[d.bob[0]] = links(append(d.held(t, d.bob[0], d.photos), d.held(t, d.bob[0], d.backups)...))

		require.NoError(t, d.rotator.Rotate(ctx, d.tenant.DID(), d.photos, map[string][]string{"alice": {"s3:PutObject"}}))
		got := map[did.DID][]cid.Cid{}
		for _, key := range d.alice {
			got[key] = links(d.held(t, key, d.backups))
		}
		got[d.bob[0]] = links(append(d.held(t, d.bob[0], d.photos), d.held(t, d.bob[0], d.backups)...))
		require.Equal(t, untouched, got)
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

	t.Run("revokes nothing for a first grant over a bucket", func(t *testing.T) {
		d := setup(t, nil)
		videos := testutil.RandomDID(t)
		require.NoError(t, d.rotator.Rotate(ctx, d.tenant.DID(), videos, map[string][]string{"alice": {"s3:GetObject"}, "bob": {"s3:GetObject"}}))

		require.Empty(t, d.swarf.Revoked())
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

	t.Run("a key deleted after the rotation listed it gets nothing", func(t *testing.T) {
		d := setup(t, nil)
		gone, kept := d.alice[0], d.alice[1]
		dels := &deleteOnReplace{Store: d.delegations, del: func(ctx context.Context) error { return d.accessKeys.Delete(ctx, gone) }}
		rotator := grant.NewRotator(zap.NewNop(), dels, d.accessKeys, d.secrets, d.swarf)
		require.NoError(t, rotator.Rotate(ctx, d.tenant.DID(), d.photos, map[string][]string{"alice": {"s3:PutObject"}}))

		require.Empty(t, d.held(t, gone, d.photos))
		require.ElementsMatch(t, commandsFor("s3:PutObject"), commands(d.held(t, kept, d.photos)))
	})

	t.Run("revokes nothing for a principal without keys", func(t *testing.T) {
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
		require.ElementsMatch(t, links(old), d.swarf.Revoked())
		for _, key := range d.alice {
			page, err := d.delegations.ListByAudience(ctx, key)
			require.NoError(t, err)
			require.Empty(t, page.Results, key)
		}
		require.NotEmpty(t, d.held(t, d.bob[0], d.photos))
	})

	t.Run("a publish failure returns the error and leaves the keys' delegations in place", func(t *testing.T) {
		d := setup(t, nil)
		before := map[did.DID][]cid.Cid{}
		for _, key := range d.alice {
			page, err := d.delegations.ListByAudience(ctx, key)
			require.NoError(t, err)
			before[key] = links(page.Results)
		}
		swarfDown := errors.New("swarf is down")
		d.swarf.Err = swarfDown

		require.ErrorIs(t, d.rotator.Revoke(ctx, d.tenant.DID(), "alice"), swarfDown)
		after := map[did.DID][]cid.Cid{}
		for _, key := range d.alice {
			page, err := d.delegations.ListByAudience(ctx, key)
			require.NoError(t, err)
			after[key] = links(page.Results)
		}
		require.Equal(t, before, after)
	})
}

func TestPublish(t *testing.T) {
	ctx := t.Context()

	t.Run("revokes the delegations in one request signed by the tenant", func(t *testing.T) {
		d := setup(t, nil)
		dels := append(d.held(t, d.alice[0], d.photos), d.held(t, d.bob[0], d.backups)...)

		require.NoError(t, d.rotator.Publish(ctx, d.tenant.DID(), dels))
		require.Len(t, d.swarf.Batches(), 1)
		var revokers []did.DID
		for _, r := range d.swarf.Revocations() {
			revokers = append(revokers, r.Revoker)
		}
		require.Equal(t, slices.Repeat([]did.DID{d.tenant.DID()}, len(dels)), revokers)
		require.ElementsMatch(t, links(dels), d.swarf.Revoked())
	})

	t.Run("skips expired delegations", func(t *testing.T) {
		exp := time.Now().Add(-time.Hour)
		d := setup(t, &exp)

		require.NoError(t, d.rotator.Publish(ctx, d.tenant.DID(), d.held(t, d.bob[0], d.photos)))
		require.Empty(t, d.swarf.Batches())
	})

	t.Run("returns the revocation service's error", func(t *testing.T) {
		d := setup(t, nil)
		down := errors.New("swarf is down")
		d.swarf.Err = down

		require.ErrorIs(t, d.rotator.Publish(ctx, d.tenant.DID(), d.held(t, d.bob[0], d.photos)), down)
	})
}

// Publish bounds its request at BatchTimeout itself, so a caller without a
// deadline cannot hang behind a stalled revocation service.
func TestPublishUnderBatchTimeout(t *testing.T) {
	d := setup(t, nil)
	pub := &deadlinePublisher{FakeSwarf: d.swarf}
	rotator := grant.NewRotator(zap.NewNop(), d.delegations, d.accessKeys, d.secrets, pub)

	require.NoError(t, rotator.Publish(context.Background(), d.tenant.DID(), d.held(t, d.alice[0], d.photos)))
	require.Len(t, pub.remaining, 1)
	require.Greater(t, pub.remaining[0], time.Duration(0))
	require.LessOrEqual(t, pub.remaining[0], grant.BatchTimeout)
}

// PublishRevocations bounds its own publish, so a caller with no deadline of
// its own still gives up at BatchTimeout.
func TestPublishRevocationsUnderBatchTimeout(t *testing.T) {
	d := setup(t, nil)
	pub := &deadlinePublisher{FakeSwarf: d.swarf}
	held := d.held(t, d.alice[0], d.photos)
	require.NotEmpty(t, held)
	require.NoError(t, grant.PublishRevocations(context.Background(), zap.NewNop(), pub, d.tenant, held))
	require.Len(t, pub.remaining, 1)
	require.Greater(t, pub.remaining[0], time.Duration(0))
	require.LessOrEqual(t, pub.remaining[0], grant.BatchTimeout)
}
