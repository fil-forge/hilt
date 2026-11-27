package tenant_test

import (
	"testing"

	htestutil "github.com/fil-forge/hilt/internal/testutil"
	"github.com/fil-forge/hilt/pkg/store"
	"github.com/fil-forge/hilt/pkg/store/tenant"
	tenantpostgres "github.com/fil-forge/hilt/pkg/store/tenant/postgres"
	"github.com/fil-forge/libforge/testutil"
	"github.com/fil-forge/ucantone/did"
	"github.com/stretchr/testify/require"
)

func makeStore(t *testing.T) tenant.Store {
	return tenantpostgres.New(htestutil.PostgresOrSkip(t))
}

func TestTenantStore(t *testing.T) {
	s := makeStore(t)

	t.Run("adds and retrieves a tenant", func(t *testing.T) {
		id := testutil.RandomDID(t)
		require.NoError(t, s.Add(t.Context(), id, "ext-acme", tenant.Active))

		rec, err := s.Get(t.Context(), id)
		require.NoError(t, err)
		require.Equal(t, id, rec.ID)
		require.Equal(t, "ext-acme", rec.ExternalID)
		require.Equal(t, tenant.Active, rec.Status)
		require.False(t, rec.CreatedAt.IsZero())
		require.Equal(t, rec.CreatedAt, rec.UpdatedAt)
	})

	t.Run("Get returns ErrRecordNotFound for unknown id", func(t *testing.T) {
		_, err := s.Get(t.Context(), testutil.RandomDID(t))
		require.ErrorIs(t, err, store.ErrRecordNotFound)
	})

	t.Run("GetByExternalID retrieves a tenant", func(t *testing.T) {
		id := testutil.RandomDID(t)
		require.NoError(t, s.Add(t.Context(), id, "ext-lookup", tenant.Active))

		rec, err := s.GetByExternalID(t.Context(), "ext-lookup")
		require.NoError(t, err)
		require.Equal(t, id, rec.ID)
		require.Equal(t, "ext-lookup", rec.ExternalID)
	})

	t.Run("GetByExternalID returns ErrRecordNotFound for unknown external id", func(t *testing.T) {
		_, err := s.GetByExternalID(t.Context(), "ext-missing")
		require.ErrorIs(t, err, store.ErrRecordNotFound)
	})

	t.Run("Add returns ErrRecordExists for duplicate id", func(t *testing.T) {
		id := testutil.RandomDID(t)
		require.NoError(t, s.Add(t.Context(), id, "ext-dup-1", tenant.Active))
		err := s.Add(t.Context(), id, "ext-dup-2", tenant.Active)
		require.ErrorIs(t, err, store.ErrRecordExists)
	})

	t.Run("Add returns ErrRecordExists for duplicate external id", func(t *testing.T) {
		require.NoError(t, s.Add(t.Context(), testutil.RandomDID(t), "ext-shared", tenant.Active))
		err := s.Add(t.Context(), testutil.RandomDID(t), "ext-shared", tenant.Active)
		require.ErrorIs(t, err, store.ErrRecordExists)
	})

	t.Run("Add returns ErrInvalidArgument for undef tenant ID", func(t *testing.T) {
		err := s.Add(t.Context(), did.Undef, "ext-undef-id", tenant.Active)
		require.ErrorIs(t, err, store.ErrInvalidArgument)
	})

	t.Run("Add returns ErrInvalidArgument for invalid status", func(t *testing.T) {
		err := s.Add(t.Context(), testutil.RandomDID(t), "ext-bad-status", tenant.Status("bogus"))
		require.ErrorIs(t, err, store.ErrInvalidArgument)
	})

	t.Run("SetStatus updates status", func(t *testing.T) {
		id := testutil.RandomDID(t)
		require.NoError(t, s.Add(t.Context(), id, "ext-switcher", tenant.Active))

		require.NoError(t, s.SetStatus(t.Context(), id, tenant.WriteLocked))

		rec, err := s.Get(t.Context(), id)
		require.NoError(t, err)
		require.Equal(t, tenant.WriteLocked, rec.Status)
		require.False(t, rec.UpdatedAt.IsZero())
	})

	t.Run("SetStatus returns ErrRecordNotFound for unknown id", func(t *testing.T) {
		err := s.SetStatus(t.Context(), testutil.RandomDID(t), tenant.Disabled)
		require.ErrorIs(t, err, store.ErrRecordNotFound)
	})

	t.Run("SetStatus returns ErrInvalidArgument for invalid status", func(t *testing.T) {
		id := testutil.RandomDID(t)
		require.NoError(t, s.Add(t.Context(), id, "ext-bad-set-status", tenant.Active))

		err := s.SetStatus(t.Context(), id, tenant.Status(""))
		require.ErrorIs(t, err, store.ErrInvalidArgument)
	})

	t.Run("SetStatusStatement moves the tenant only from the status named", func(t *testing.T) {
		pool := htestutil.PostgresOrSkip(t)
		s := tenantpostgres.New(pool)
		id := testutil.RandomDID(t)
		require.NoError(t, s.Add(t.Context(), id, "ext-statement", tenant.Active))
		exec := func(from, to tenant.Status) int64 {
			st, err := s.SetStatusStatement(id, from, to)
			require.NoError(t, err)
			tag, err := pool.Exec(t.Context(), st.SQL, st.Args...)
			require.NoError(t, err)
			return tag.RowsAffected()
		}

		require.EqualValues(t, 1, exec(tenant.Active, tenant.Disabled))
		rec, err := s.Get(t.Context(), id)
		require.NoError(t, err)
		require.Equal(t, tenant.Disabled, rec.Status)

		require.Zero(t, exec(tenant.Active, tenant.WriteLocked), "the tenant is no longer active")
		rec, err = s.Get(t.Context(), id)
		require.NoError(t, err)
		require.Equal(t, tenant.Disabled, rec.Status)

		_, err = s.SetStatusStatement(id, tenant.Active, tenant.Status("paused"))
		require.ErrorIs(t, err, store.ErrInvalidArgument)
		_, err = s.SetStatusStatement(id, tenant.Status(""), tenant.Active)
		require.ErrorIs(t, err, store.ErrInvalidArgument)
	})

	t.Run("DeleteStatement removes the tenant, and nothing once it is gone", func(t *testing.T) {
		pool := htestutil.PostgresOrSkip(t)
		s := tenantpostgres.New(pool)
		id, kept := testutil.RandomDID(t), testutil.RandomDID(t)
		require.NoError(t, s.Add(t.Context(), id, "ext-del", tenant.Active))
		require.NoError(t, s.Add(t.Context(), kept, "ext-kept", tenant.Active))

		require.Equal(t, []int64{1}, htestutil.Exec(t, pool, s.DeleteStatement(id)))
		_, err := s.Get(t.Context(), id)
		require.ErrorIs(t, err, store.ErrRecordNotFound)
		_, err = s.Get(t.Context(), kept)
		require.NoError(t, err)

		require.Equal(t, []int64{0}, htestutil.Exec(t, pool, s.DeleteStatement(id)))
	})
}
