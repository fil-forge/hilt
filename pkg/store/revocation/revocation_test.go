package revocation_test

import (
	"testing"
	"time"

	htestutil "github.com/fil-forge/hilt/internal/testutil"
	"github.com/fil-forge/hilt/pkg/grant"
	"github.com/fil-forge/hilt/pkg/store"
	"github.com/fil-forge/hilt/pkg/store/pglock"
	"github.com/fil-forge/hilt/pkg/store/revocation"
	revocationpostgres "github.com/fil-forge/hilt/pkg/store/revocation/postgres"
	tenantstore "github.com/fil-forge/hilt/pkg/store/tenant"
	tenantpostgres "github.com/fil-forge/hilt/pkg/store/tenant/postgres"
	"github.com/fil-forge/libforge/testutil"
	"github.com/fil-forge/ucantone/did"
	"github.com/fil-forge/ucantone/ucan"
	"github.com/ipfs/go-cid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"
)

type deps struct {
	store revocation.Store
	pool  *pgxpool.Pool
	// tenant has a row in the tenant table.
	tenant ucan.Issuer
}

func setup(t *testing.T) deps {
	t.Helper()
	pool := htestutil.PostgresOrSkip(t)
	d := deps{store: revocationpostgres.New(pool), pool: pool, tenant: addTenant(t, pool, "tenant-1")}
	return d
}

func addTenant(t *testing.T, pool *pgxpool.Pool, externalID string) ucan.Issuer {
	t.Helper()
	tenant := testutil.RandomIssuer(t)
	require.NoError(t, tenantpostgres.New(pool).Add(t.Context(), tenant.DID(), externalID, tenantstore.Active))
	return tenant
}

// issue returns n delegations issued by the tenant, each to a different key.
func issue(t *testing.T, tenant ucan.Issuer, n int) []ucan.Delegation {
	t.Helper()
	var out []ucan.Delegation
	for len(out) < n {
		dels, err := grant.Issue(tenant, testutil.RandomDID(t), []did.DID{testutil.RandomDID(t)}, []string{"s3:GetObject"}, nil)
		require.NoError(t, err)
		require.NotEmpty(t, dels)
		out = append(out, dels...)
	}
	return out[:n]
}

func links(dels []ucan.Delegation) []cid.Cid {
	out := make([]cid.Cid, len(dels))
	for i, d := range dels {
		out[i] = d.Link()
	}
	return out
}

// backdate moves the rows of the delegations to age ago.
func backdate(t *testing.T, pool *pgxpool.Pool, dels []ucan.Delegation, age time.Duration) {
	t.Helper()
	ids := make([]string, len(dels))
	for i, d := range dels {
		ids[i] = d.Link().String()
	}
	_, err := pool.Exec(t.Context(), `UPDATE revocation_owed SET recorded_at = NOW() - $2::interval WHERE id = ANY($1)`, ids, age.String())
	require.NoError(t, err)
}

func TestRevocationStore(t *testing.T) {
	t.Run("records a batch and reads it back", func(t *testing.T) {
		d := setup(t)
		dels := issue(t, d.tenant, 3)
		require.NoError(t, d.store.Add(t.Context(), d.tenant.DID(), dels))

		got, err := d.store.Oldest(t.Context(), d.tenant.DID(), 10)
		require.NoError(t, err)
		require.ElementsMatch(t, links(dels), links(got))
		// What comes back is the delegation itself, fit to be revoked.
		for _, g := range got {
			require.Equal(t, d.tenant.DID(), g.Issuer())
		}
	})

	t.Run("an empty batch records nothing", func(t *testing.T) {
		d := setup(t)
		require.NoError(t, d.store.Add(t.Context(), d.tenant.DID(), nil))
		stats, err := d.store.Stats(t.Context())
		require.NoError(t, err)
		require.Zero(t, stats.Count)
	})

	t.Run("recording a delegation twice keeps one row and its time", func(t *testing.T) {
		d := setup(t)
		dels := issue(t, d.tenant, 2)
		require.NoError(t, d.store.Add(t.Context(), d.tenant.DID(), dels))
		backdate(t, d.pool, dels, time.Hour)
		require.NoError(t, d.store.Add(t.Context(), d.tenant.DID(), dels))

		stats, err := d.store.Stats(t.Context())
		require.NoError(t, err)
		require.EqualValues(t, 2, stats.Count)
		require.GreaterOrEqual(t, stats.OldestAge, time.Hour)
	})

	t.Run("refuses invalid arguments and records none of the batch", func(t *testing.T) {
		d := setup(t)
		good := issue(t, d.tenant, 1)
		foreign := issue(t, testutil.RandomIssuer(t), 1)

		err := d.store.Add(t.Context(), did.Undef, good)
		require.ErrorIs(t, err, store.ErrInvalidArgument)
		err = d.store.Add(t.Context(), d.tenant.DID(), []ucan.Delegation{good[0], nil})
		require.ErrorIs(t, err, store.ErrInvalidArgument)
		// Only the issuer can sign a delegation's revocation.
		err = d.store.Add(t.Context(), d.tenant.DID(), []ucan.Delegation{good[0], foreign[0]})
		require.ErrorIs(t, err, store.ErrInvalidArgument)

		stats, err := d.store.Stats(t.Context())
		require.NoError(t, err)
		require.Zero(t, stats.Count)
	})

	t.Run("refuses a tenant that does not exist", func(t *testing.T) {
		d := setup(t)
		stranger := testutil.RandomIssuer(t)
		require.Error(t, d.store.Add(t.Context(), stranger.DID(), issue(t, stranger, 1)))
	})

	t.Run("Oldest returns a tenant's rows oldest first, up to the limit", func(t *testing.T) {
		d := setup(t)
		other := addTenant(t, d.pool, "tenant-2")
		old, mid, recent := issue(t, d.tenant, 2), issue(t, d.tenant, 2), issue(t, d.tenant, 2)
		theirs := issue(t, other, 1)
		// Recorded newest first, so the order read back is the rows' age and
		// not the order they were written in.
		for _, batch := range [][]ucan.Delegation{recent, mid, old} {
			require.NoError(t, d.store.Add(t.Context(), d.tenant.DID(), batch))
		}
		require.NoError(t, d.store.Add(t.Context(), other.DID(), theirs))
		backdate(t, d.pool, mid, time.Hour)
		backdate(t, d.pool, old, 2*time.Hour)
		backdate(t, d.pool, theirs, 3*time.Hour)

		got, err := d.store.Oldest(t.Context(), d.tenant.DID(), 4)
		require.NoError(t, err)
		require.Len(t, got, 4)
		require.ElementsMatch(t, links(old), links(got[:2]))
		require.ElementsMatch(t, links(mid), links(got[2:]))

		all, err := d.store.Oldest(t.Context(), d.tenant.DID(), 100)
		require.NoError(t, err)
		require.Len(t, all, 6, "another tenant's rows are not this tenant's")

		none, err := d.store.Oldest(t.Context(), testutil.RandomDID(t), 100)
		require.NoError(t, err)
		require.Empty(t, none)
	})

	t.Run("Delete removes the named rows and ignores an unknown CID", func(t *testing.T) {
		d := setup(t)
		dels := issue(t, d.tenant, 3)
		require.NoError(t, d.store.Add(t.Context(), d.tenant.DID(), dels))

		require.NoError(t, d.store.Delete(t.Context(), append(links(dels[:2]), testutil.RandomCID(t))))
		got, err := d.store.Oldest(t.Context(), d.tenant.DID(), 10)
		require.NoError(t, err)
		require.Equal(t, links(dels[2:]), links(got))

		require.NoError(t, d.store.Delete(t.Context(), nil))
	})

	t.Run("the statements make the writes Add and Delete make", func(t *testing.T) {
		d := setup(t)
		dels := issue(t, d.tenant, 2)
		st, err := d.store.AddStatement(d.tenant.DID(), dels)
		require.NoError(t, err)
		_, err = d.pool.Exec(t.Context(), st.SQL, st.Args...)
		require.NoError(t, err)
		got, err := d.store.Oldest(t.Context(), d.tenant.DID(), 10)
		require.NoError(t, err)
		require.ElementsMatch(t, links(dels), links(got))

		st = d.store.DeleteStatement(links(dels))
		_, err = d.pool.Exec(t.Context(), st.SQL, st.Args...)
		require.NoError(t, err)
		got, err = d.store.Oldest(t.Context(), d.tenant.DID(), 10)
		require.NoError(t, err)
		require.Empty(t, got)

		_, err = d.store.AddStatement(d.tenant.DID(), issue(t, testutil.RandomIssuer(t), 1))
		require.ErrorIs(t, err, store.ErrInvalidArgument)
	})

	t.Run("Add and Delete commit with the caller's transaction", func(t *testing.T) {
		d := setup(t)
		dels := issue(t, d.tenant, 2)
		count := func() int64 {
			stats, err := d.store.Stats(t.Context())
			require.NoError(t, err)
			return stats.Count
		}

		tx, err := d.pool.Begin(t.Context())
		require.NoError(t, err)
		require.NoError(t, d.store.Add(pglock.WithTx(t.Context(), tx), d.tenant.DID(), dels))
		require.Zero(t, count(), "the rows are not visible before the caller commits")
		require.NoError(t, tx.Rollback(t.Context()))
		require.Zero(t, count(), "a rolled back caller records nothing")

		tx, err = d.pool.Begin(t.Context())
		require.NoError(t, err)
		require.NoError(t, d.store.Add(pglock.WithTx(t.Context(), tx), d.tenant.DID(), dels))
		require.NoError(t, tx.Commit(t.Context()))
		require.EqualValues(t, 2, count())

		tx, err = d.pool.Begin(t.Context())
		require.NoError(t, err)
		require.NoError(t, d.store.Delete(pglock.WithTx(t.Context(), tx), links(dels)))
		require.EqualValues(t, 2, count(), "the rows stand until the caller commits")
		require.NoError(t, tx.Rollback(t.Context()))
		require.EqualValues(t, 2, count())
	})

	t.Run("Stats counts every tenant's rows and reports the oldest's age", func(t *testing.T) {
		d := setup(t)
		stats, err := d.store.Stats(t.Context())
		require.NoError(t, err)
		require.Equal(t, revocation.Stats{}, stats)

		other := addTenant(t, d.pool, "tenant-2")
		mine, theirs := issue(t, d.tenant, 2), issue(t, other, 1)
		require.NoError(t, d.store.Add(t.Context(), d.tenant.DID(), mine))
		require.NoError(t, d.store.Add(t.Context(), other.DID(), theirs))
		backdate(t, d.pool, theirs, 10*time.Minute)

		stats, err = d.store.Stats(t.Context())
		require.NoError(t, err)
		require.EqualValues(t, 3, stats.Count)
		require.InDelta(t, (10 * time.Minute).Seconds(), stats.OldestAge.Seconds(), 30)
	})

	t.Run("deleting the tenant deletes what it owes", func(t *testing.T) {
		d := setup(t)
		other := addTenant(t, d.pool, "tenant-2")
		require.NoError(t, d.store.Add(t.Context(), d.tenant.DID(), issue(t, d.tenant, 2)))
		require.NoError(t, d.store.Add(t.Context(), other.DID(), issue(t, other, 1)))

		require.NoError(t, tenantpostgres.New(d.pool).Delete(t.Context(), d.tenant.DID()))
		stats, err := d.store.Stats(t.Context())
		require.NoError(t, err)
		require.EqualValues(t, 1, stats.Count)
	})
}
