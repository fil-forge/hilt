package grant_test

import (
	"context"
	"errors"
	"testing"
	"time"

	htestutil "github.com/fil-forge/hilt/internal/testutil"
	"github.com/fil-forge/libforge/testutil"

	"github.com/fil-forge/hilt/pkg/grant"
	accesskeystore "github.com/fil-forge/hilt/pkg/store/accesskey"
	accesskeypostgres "github.com/fil-forge/hilt/pkg/store/accesskey/postgres"
	delegationpostgres "github.com/fil-forge/hilt/pkg/store/delegation/postgres"
	principalpostgres "github.com/fil-forge/hilt/pkg/store/principal/postgres"
	tenantstore "github.com/fil-forge/hilt/pkg/store/tenant"
	tenantpostgres "github.com/fil-forge/hilt/pkg/store/tenant/postgres"
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
	delegations *delegationpostgres.Store
	accessKeys  *accesskeypostgres.Store
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
	pool := htestutil.PostgresOrSkip(t)
	accessKeys, delegations, secrets := accesskeypostgres.New(pool), delegationpostgres.New(pool), vaultmemory.New()

	signer, err := secp256k1.Generate()
	require.NoError(t, err)
	tenantID := signer.KeyDID()
	tenant := multikey.NewIssuer(tenantID, signer)
	require.NoError(t, secrets.Write(ctx, vault.TenantKeyPath(tenantID), signer.Bytes()))
	// A key's tenant and principal must exist.
	require.NoError(t, tenantpostgres.New(pool).Add(ctx, tenantID, "tenant-1", tenantstore.Active))
	for _, principal := range []string{"alice", "bob"} {
		require.NoError(t, principalpostgres.New(pool).Add(ctx, tenantID, principal))
	}

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

func links(dels []ucan.Delegation) []cid.Cid {
	var out []cid.Cid
	for _, d := range dels {
		out = append(out, d.Link())
	}
	return out
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

// The rotator bounds each revocation at BatchTimeout itself, so a caller
// without a deadline cannot hold the delegation locks behind a stalled
// publish.
func TestRotatorPublishesUnderBatchTimeout(t *testing.T) {
	d := setup(t, nil)
	pub := &deadlinePublisher{FakeSwarf: d.swarf}
	rotator := grant.NewRotator(zap.NewNop(), d.delegations, d.accessKeys, d.secrets, pub)

	require.NoError(t, rotator.Revoke(context.Background(), d.tenant.DID(), "bob"))
	require.Len(t, pub.remaining, 1)
	require.Greater(t, pub.remaining[0], time.Duration(0))
	require.LessOrEqual(t, pub.remaining[0], grant.BatchTimeout)
}

// PublishRevocations bounds its own publish, so a caller that holds a
// delegation lock with no deadline of its own still releases it at BatchTimeout.
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
