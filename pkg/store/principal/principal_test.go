package principal_test

import (
	"testing"
	"time"

	htestutil "github.com/fil-forge/hilt/internal/testutil"
	"github.com/fil-forge/hilt/pkg/store"
	"github.com/fil-forge/hilt/pkg/store/principal"
	principalpostgres "github.com/fil-forge/hilt/pkg/store/principal/postgres"
	"github.com/fil-forge/hilt/pkg/store/tenant"
	tenantpostgres "github.com/fil-forge/hilt/pkg/store/tenant/postgres"
	"github.com/fil-forge/libforge/testutil"
	"github.com/fil-forge/ucantone/did"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"
)

// seedFunc creates a tenant, which principal.tenant_id references.
type seedFunc func(t *testing.T, tenantID did.DID)

func seeder(pool *pgxpool.Pool) seedFunc {
	tenants := tenantpostgres.New(pool)
	return func(t *testing.T, tenantID did.DID) {
		require.NoError(t, tenants.Add(t.Context(), tenantID, "ext-"+tenantID.String(), tenant.Active))
	}
}

// tombstone runs the principal's TombstoneStatement on its own and returns
// how many rows it affected.
func tombstone(t *testing.T, pool *pgxpool.Pool, s principal.Store, tenantID did.DID, externalID string) int64 {
	t.Helper()
	st := s.TombstoneStatement(tenantID, externalID)
	tag, err := pool.Exec(t.Context(), st.SQL, st.Args...)
	require.NoError(t, err)
	return tag.RowsAffected()
}

func TestPrincipalStore(t *testing.T) {
	pool := htestutil.PostgresOrSkip(t)
	s, seed := principalpostgres.New(pool), seeder(pool)

	t.Run("adds and retrieves a principal", func(t *testing.T) {
		tenantID := testutil.RandomDID(t)
		seed(t, tenantID)
		require.NoError(t, s.Add(t.Context(), tenantID, "user-1"))

		rec, err := s.Get(t.Context(), tenantID, "user-1")
		require.NoError(t, err)
		require.Equal(t, tenantID, rec.Tenant)
		require.Equal(t, "user-1", rec.ExternalID)
		require.False(t, rec.CreatedAt.IsZero())
	})

	t.Run("Get returns ErrRecordNotFound for an unknown principal", func(t *testing.T) {
		tenantID := testutil.RandomDID(t)
		seed(t, tenantID)
		_, err := s.Get(t.Context(), tenantID, "nobody")
		require.ErrorIs(t, err, store.ErrRecordNotFound)
	})

	t.Run("Get isolates by tenant", func(t *testing.T) {
		tenantID := testutil.RandomDID(t)
		other := testutil.RandomDID(t)
		seed(t, tenantID)
		seed(t, other)
		require.NoError(t, s.Add(t.Context(), tenantID, "shared-id"))

		_, err := s.Get(t.Context(), other, "shared-id")
		require.ErrorIs(t, err, store.ErrRecordNotFound)
	})

	t.Run("Add returns ErrRecordExists for a duplicate (tenant, external ID)", func(t *testing.T) {
		tenantID := testutil.RandomDID(t)
		other := testutil.RandomDID(t)
		seed(t, tenantID)
		seed(t, other)
		require.NoError(t, s.Add(t.Context(), tenantID, "dup"))
		require.ErrorIs(t, s.Add(t.Context(), tenantID, "dup"), store.ErrRecordExists)
		// The same external ID under a different tenant is a different principal.
		require.NoError(t, s.Add(t.Context(), other, "dup"))
	})

	t.Run("Add returns ErrInvalidArgument for an undef tenant", func(t *testing.T) {
		require.ErrorIs(t, s.Add(t.Context(), did.Undef, "user-1"), store.ErrInvalidArgument)
	})

	t.Run("Add returns ErrInvalidArgument for an empty external ID", func(t *testing.T) {
		tenantID := testutil.RandomDID(t)
		seed(t, tenantID)
		require.ErrorIs(t, s.Add(t.Context(), tenantID, ""), store.ErrInvalidArgument)
	})

	t.Run("ListByTenant isolates by tenant and orders by external ID", func(t *testing.T) {
		tenantID := testutil.RandomDID(t)
		other := testutil.RandomDID(t)
		seed(t, tenantID)
		seed(t, other)
		for _, id := range []string{"c", "a", "b"} {
			require.NoError(t, s.Add(t.Context(), tenantID, id))
		}
		require.NoError(t, s.Add(t.Context(), other, "a"))

		recs, err := s.ListByTenant(t.Context(), tenantID)
		require.NoError(t, err)
		require.Len(t, recs, 3)
		var ids []string
		for _, r := range recs {
			require.Equal(t, tenantID, r.Tenant)
			ids = append(ids, r.ExternalID)
		}
		require.Equal(t, []string{"a", "b", "c"}, ids)

		recs, err = s.ListByTenant(t.Context(), testutil.RandomDID(t))
		require.NoError(t, err)
		require.Empty(t, recs)
	})

	t.Run("ListIDsByTenant lists live external IDs by tenant in order", func(t *testing.T) {
		tenantID := testutil.RandomDID(t)
		other := testutil.RandomDID(t)
		seed(t, tenantID)
		seed(t, other)
		for _, id := range []string{"c", "a", "gone", "b"} {
			require.NoError(t, s.Add(t.Context(), tenantID, id))
		}
		tombstone(t, pool, s, tenantID, "gone")
		require.NoError(t, s.Add(t.Context(), other, "z"))

		ids, err := s.ListIDsByTenant(t.Context(), tenantID)
		require.NoError(t, err)
		require.Equal(t, []string{"a", "b", "c"}, ids)

		ids, err = s.ListIDsByTenant(t.Context(), testutil.RandomDID(t))
		require.NoError(t, err)
		require.Empty(t, ids)
	})

	t.Run("Add revives a removed principal with a fresh CreatedAt", func(t *testing.T) {
		tenantID := testutil.RandomDID(t)
		seed(t, tenantID)
		require.NoError(t, s.Add(t.Context(), tenantID, "again"))
		first, err := s.Get(t.Context(), tenantID, "again")
		require.NoError(t, err)
		tombstone(t, pool, s, tenantID, "again")

		recs, err := s.ListByTenant(t.Context(), tenantID)
		require.NoError(t, err)
		require.Empty(t, recs, "a removed principal is not listed")

		time.Sleep(2 * time.Millisecond)
		require.NoError(t, s.Add(t.Context(), tenantID, "again"), "revive is not a duplicate")
		revived, err := s.Get(t.Context(), tenantID, "again")
		require.NoError(t, err)
		require.True(t, revived.CreatedAt.After(first.CreatedAt))
		require.ErrorIs(t, s.Add(t.Context(), tenantID, "again"), store.ErrRecordExists)
	})

	t.Run("TombstoneStatement removes the principal once, leaving its row to revive", func(t *testing.T) {
		tenantID := testutil.RandomDID(t)
		seed(t, tenantID)
		require.NoError(t, s.Add(t.Context(), tenantID, "del"))
		require.NoError(t, s.Add(t.Context(), tenantID, "kept"))

		require.EqualValues(t, 1, tombstone(t, pool, s, tenantID, "del"))
		_, err := s.Get(t.Context(), tenantID, "del")
		require.ErrorIs(t, err, store.ErrRecordNotFound)
		ids, err := s.ListIDsByTenant(t.Context(), tenantID)
		require.NoError(t, err)
		require.Equal(t, []string{"kept"}, ids)

		require.Zero(t, tombstone(t, pool, s, tenantID, "del"), "a removed principal is not removed again")
		require.Zero(t, tombstone(t, pool, s, tenantID, "missing"))
	})

	t.Run("DeleteByTenantStatement removes every principal of the tenant and no other", func(t *testing.T) {
		tenantID := testutil.RandomDID(t)
		other := testutil.RandomDID(t)
		seed(t, tenantID)
		seed(t, other)
		require.NoError(t, s.Add(t.Context(), tenantID, "a"))
		require.NoError(t, s.Add(t.Context(), tenantID, "b"))
		require.NoError(t, s.Add(t.Context(), other, "a"))

		require.Zero(t, tombstone(t, pool, s, tenantID, "missing"))
		require.EqualValues(t, 1, tombstone(t, pool, s, tenantID, "b"))
		require.Equal(t, []int64{2}, htestutil.Exec(t, pool, s.DeleteByTenantStatement(tenantID)), "the tombstoned row goes too")
		recs, err := s.ListByTenant(t.Context(), tenantID)
		require.NoError(t, err)
		require.Empty(t, recs)
		recs, err = s.ListByTenant(t.Context(), other)
		require.NoError(t, err)
		require.Len(t, recs, 1)
	})
}
