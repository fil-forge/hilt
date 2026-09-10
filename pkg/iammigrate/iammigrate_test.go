package iammigrate_test

import (
	"context"
	"errors"
	"runtime"
	"testing"
	"time"

	htestutil "github.com/fil-forge/hilt/internal/testutil"
	"github.com/fil-forge/hilt/pkg/iammigrate"
	accesskeypostgres "github.com/fil-forge/hilt/pkg/store/accesskey/postgres"
	delegationpostgres "github.com/fil-forge/hilt/pkg/store/delegation/postgres"
	providerpostgres "github.com/fil-forge/hilt/pkg/store/provider/postgres"
	"github.com/fil-forge/hilt/pkg/store/tenant"
	tenantpostgres "github.com/fil-forge/hilt/pkg/store/tenant/postgres"
	"github.com/fil-forge/hilt/pkg/vault"
	vaultmemory "github.com/fil-forge/hilt/pkg/vault/memory"
	"github.com/fil-forge/libforge/commands/content"
	"github.com/fil-forge/libforge/testutil"
	swarfclient "github.com/fil-forge/swarf/pkg/client"
	"github.com/fil-forge/ucantone/did"
	"github.com/fil-forge/ucantone/multikey"
	"github.com/fil-forge/ucantone/multikey/ed25519"
	"github.com/fil-forge/ucantone/multikey/secp256k1"
	"github.com/fil-forge/ucantone/ucan"
	"github.com/fil-forge/ucantone/ucan/delegation"
	"github.com/ipfs/go-cid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

// revocation records one published revocation.
type revocation struct {
	revoker did.DID
	revoked cid.Cid
	options int
}

// fakeSwarf is a stub of the revocation service, recording what it was asked to
// publish and failing every publish once err is set.
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

func createPostgresPool(t *testing.T) *pgxpool.Pool {
	if htestutil.IsRunningInCI(t) && runtime.GOOS == "linux" {
		if !htestutil.IsDockerAvailable(t) {
			t.Fatalf("docker is expected in CI linux testing environments, but wasn't found")
		}
	}
	if !htestutil.IsDockerAvailable(t) {
		t.SkipNow()
	}
	return htestutil.CreatePostgres(t)
}

// world is one Postgres database with the stores the migration reads and
// writes, a memory vault, and a fake revocation service.
type world struct {
	pool        *pgxpool.Pool
	accessKeys  *accesskeypostgres.Store
	delegations *delegationpostgres.Store
	secrets     *vaultmemory.Store
	swarf       *fakeSwarf
	migrator    *iammigrate.Migrator
}

func newWorld(t *testing.T) *world {
	t.Helper()
	pool := createPostgresPool(t)
	w := &world{
		pool:        pool,
		accessKeys:  accesskeypostgres.New(pool),
		delegations: delegationpostgres.New(pool),
		secrets:     vaultmemory.New(),
		swarf:       &fakeSwarf{},
	}
	w.migrator = iammigrate.New(zap.NewNop(), pool, w.delegations, w.secrets, w.swarf)
	return w
}

// tenant is a seeded tenant whose secp256k1 signing key is in the vault.
type seededTenant struct {
	id     did.DID
	issuer ucan.Issuer
}

func (w *world) addTenant(t *testing.T) seededTenant {
	t.Helper()
	ctx := t.Context()
	signer, err := secp256k1.Generate()
	require.NoError(t, err)
	tenantID := signer.KeyDID()
	providerID := testutil.RandomDID(t)
	require.NoError(t, providerpostgres.New(w.pool).Add(ctx, providerID, tenantID.String(), nil))
	require.NoError(t, tenantpostgres.New(w.pool).Add(ctx, tenantID, "ext-"+tenantID.String(), providerID, tenant.Active))
	require.NoError(t, w.secrets.Write(ctx, vault.TenantKeyPath(tenantID), signer.Bytes()))
	return seededTenant{id: tenantID, issuer: multikey.NewIssuer(tenantID, signer)}
}

// addKey seeds an access key of the tenant as the pre-IAM API created it: a
// row, a vault entry, and one powerline delegation per option set, issued by
// the tenant to the key.
func (w *world) addKey(t *testing.T, owner seededTenant, name string, delegationOpts ...[]delegation.Option) (did.DID, []ucan.Delegation) {
	t.Helper()
	ctx := t.Context()
	signer, err := ed25519.Generate()
	require.NoError(t, err)
	keyID := signer.KeyDID()
	require.NoError(t, w.accessKeys.Add(ctx, keyID, owner.id, name, nil, []string{"s3:GetObject"}, nil))
	require.NoError(t, w.secrets.Write(ctx, vault.AccessKeyPath(owner.id, keyID), signer.Bytes()))

	var dels []ucan.Delegation
	for _, opts := range delegationOpts {
		d, err := delegation.Delegate(owner.issuer, keyID, did.Undef, content.Retrieve.Command, opts...)
		require.NoError(t, err)
		dels = append(dels, d)
	}
	if len(dels) > 0 {
		require.NoError(t, w.delegations.PutBatch(ctx, dels))
	}
	return keyID, dels
}

func (w *world) keyExists(t *testing.T, keyID did.DID) bool {
	t.Helper()
	var exists bool
	require.NoError(t, w.pool.QueryRow(t.Context(),
		`SELECT EXISTS (SELECT 1 FROM access_key WHERE id = $1)`, keyID.String()).Scan(&exists))
	return exists
}

func (w *world) delegationCount(t *testing.T, keyID did.DID) int {
	t.Helper()
	page, err := w.delegations.ListByAudience(t.Context(), keyID)
	require.NoError(t, err)
	return len(page.Results)
}

var (
	noExpiry = []delegation.Option{delegation.WithNoExpiration()}
	expired  = []delegation.Option{delegation.WithExpiration(ucan.UnixTimestamp(time.Now().Add(-time.Hour).Unix()))}
)

func TestRun(t *testing.T) {
	t.Run("removes every key and revokes its live delegations", func(t *testing.T) {
		w := newWorld(t)
		tenantA, tenantB := w.addTenant(t), w.addTenant(t)
		keyA, delsA := w.addKey(t, tenantA, "a", noExpiry, noExpiry)
		keyB, delsB := w.addKey(t, tenantB, "b", noExpiry)

		report, err := w.migrator.Run(t.Context())
		require.NoError(t, err)
		require.Equal(t, iammigrate.Report{Keys: 2, Revocations: 3}, report)

		// Each revocation is signed by the tenant that issued the delegation, with
		// no witness path.
		want := map[cid.Cid]did.DID{}
		for _, d := range delsA {
			want[d.Link()] = tenantA.id
		}
		for _, d := range delsB {
			want[d.Link()] = tenantB.id
		}
		require.Len(t, w.swarf.revocations, len(want))
		for _, r := range w.swarf.revocations {
			require.Equal(t, want[r.revoked], r.revoker)
			require.Zero(t, r.options)
		}

		for _, key := range []did.DID{keyA, keyB} {
			require.False(t, w.keyExists(t, key), "the row should be gone")
			require.Zero(t, w.delegationCount(t, key), "the delegations should be gone")
			_, err := w.secrets.Read(t.Context(), vault.AccessKeyPath(tenantA.id, key))
			require.ErrorIs(t, err, vault.ErrNotFound)
			_, err = w.secrets.Read(t.Context(), vault.AccessKeyPath(tenantB.id, key))
			require.ErrorIs(t, err, vault.ErrNotFound)
		}
		// The tenants' own keys are untouched.
		_, err = w.secrets.Read(t.Context(), vault.TenantKeyPath(tenantA.id))
		require.NoError(t, err)
	})

	t.Run("skips expired delegations and needs no tenant key without live ones", func(t *testing.T) {
		w := newWorld(t)
		owner := w.addTenant(t)
		stale, _ := w.addKey(t, owner, "stale", expired)
		bare, _ := w.addKey(t, owner, "bare")
		// Neither key holds a live delegation, so the tenant key is never read.
		require.NoError(t, w.secrets.Delete(t.Context(), vault.TenantKeyPath(owner.id)))

		report, err := w.migrator.Run(t.Context())
		require.NoError(t, err)
		require.Equal(t, iammigrate.Report{Keys: 2, Revocations: 0}, report)
		require.Empty(t, w.swarf.revocations)
		for _, key := range []did.DID{stale, bare} {
			require.False(t, w.keyExists(t, key))
			require.Zero(t, w.delegationCount(t, key))
		}
	})

	t.Run("a revocation failure leaves the key intact", func(t *testing.T) {
		w := newWorld(t)
		owner := w.addTenant(t)
		keyID, _ := w.addKey(t, owner, "kept", noExpiry)
		w.swarf.err = errors.New("swarf is down")

		report, err := w.migrator.Run(t.Context())
		require.ErrorContains(t, err, "publishing revocation")
		require.Equal(t, iammigrate.Report{}, report)

		require.True(t, w.keyExists(t, keyID), "the row must survive a failed publish")
		require.Equal(t, 1, w.delegationCount(t, keyID), "the delegations must survive a failed publish")
		_, err = w.secrets.Read(t.Context(), vault.AccessKeyPath(owner.id, keyID))
		require.NoError(t, err, "the vault entry must survive a failed publish")

		// Once the revocation service is back the rerun finishes the job.
		w.swarf.err = nil
		report, err = w.migrator.Run(t.Context())
		require.NoError(t, err)
		require.Equal(t, iammigrate.Report{Keys: 1, Revocations: 1}, report)
		require.False(t, w.keyExists(t, keyID))
	})

	t.Run("a missing tenant key fails before anything is removed", func(t *testing.T) {
		w := newWorld(t)
		owner := w.addTenant(t)
		keyID, _ := w.addKey(t, owner, "orphaned", noExpiry)
		require.NoError(t, w.secrets.Delete(t.Context(), vault.TenantKeyPath(owner.id)))

		_, err := w.migrator.Run(t.Context())
		require.ErrorContains(t, err, "reading tenant key")
		require.Empty(t, w.swarf.revocations)
		require.True(t, w.keyExists(t, keyID))
		require.Equal(t, 1, w.delegationCount(t, keyID))
	})

	t.Run("is a no-op without keys", func(t *testing.T) {
		w := newWorld(t)
		w.addTenant(t)
		report, err := w.migrator.Run(t.Context())
		require.NoError(t, err)
		require.Equal(t, iammigrate.Report{}, report)
		require.Empty(t, w.swarf.revocations)
	})
}
