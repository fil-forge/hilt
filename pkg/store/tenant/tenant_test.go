package tenant_test

import (
	"runtime"
	"testing"

	"github.com/fil-forge/hilt/internal/testutil"
	"github.com/fil-forge/hilt/pkg/store"
	"github.com/fil-forge/hilt/pkg/store/tenant"
	tenantmemory "github.com/fil-forge/hilt/pkg/store/tenant/memory"
	tenantpostgres "github.com/fil-forge/hilt/pkg/store/tenant/postgres"
	"github.com/stretchr/testify/require"
)

type StoreKind string

const (
	Memory   StoreKind = "memory"
	Postgres StoreKind = "postgres"
)

var storeKinds = []StoreKind{Memory, Postgres}

func makeStore(t *testing.T, k StoreKind) tenant.Store {
	switch k {
	case Memory:
		return tenantmemory.New()
	case Postgres:
		return createPostgresStore(t)
	}
	panic("unknown store kind")
}

func createPostgresStore(t *testing.T) tenant.Store {
	if testutil.IsRunningInCI(t) && runtime.GOOS == "linux" {
		if !testutil.IsDockerAvailable(t) {
			t.Fatalf("docker is expected in CI linux testing environments, but wasn't found")
		}
	}
	if !testutil.IsDockerAvailable(t) {
		t.SkipNow()
	}
	pool := testutil.CreatePostgres(t)
	return tenantpostgres.New(pool)
}

func TestTenantStore(t *testing.T) {
	for _, k := range storeKinds {
		t.Run(string(k), func(t *testing.T) {
			s := makeStore(t, k)

			t.Run("adds and retrieves a tenant", func(t *testing.T) {
				id := testutil.RandomDID(t)
				provider := testutil.RandomDID(t)
				require.NoError(t, s.Add(t.Context(), id, "ext-acme", provider, "acme", tenant.Active))

				rec, err := s.Get(t.Context(), id)
				require.NoError(t, err)
				require.Equal(t, id, rec.ID)
				require.Equal(t, "ext-acme", rec.ExternalID)
				require.Equal(t, provider, rec.Provider)
				require.Equal(t, "acme", rec.Name)
				require.Equal(t, tenant.Active, rec.Status)
				require.False(t, rec.CreatedAt.IsZero())
			})

			t.Run("Get returns ErrRecordNotFound for unknown id", func(t *testing.T) {
				_, err := s.Get(t.Context(), testutil.RandomDID(t))
				require.ErrorIs(t, err, store.ErrRecordNotFound)
			})

			t.Run("GetByExternalID retrieves a tenant", func(t *testing.T) {
				id := testutil.RandomDID(t)
				require.NoError(t, s.Add(t.Context(), id, "ext-lookup", testutil.RandomDID(t), "lookup", tenant.Active))

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
				require.NoError(t, s.Add(t.Context(), id, "ext-dup-1", testutil.RandomDID(t), "dup", tenant.Active))
				err := s.Add(t.Context(), id, "ext-dup-2", testutil.RandomDID(t), "dup", tenant.Active)
				require.ErrorIs(t, err, store.ErrRecordExists)
			})

			t.Run("Add returns ErrRecordExists for duplicate external id", func(t *testing.T) {
				require.NoError(t, s.Add(t.Context(), testutil.RandomDID(t), "ext-shared", testutil.RandomDID(t), "a", tenant.Active))
				err := s.Add(t.Context(), testutil.RandomDID(t), "ext-shared", testutil.RandomDID(t), "b", tenant.Active)
				require.ErrorIs(t, err, store.ErrRecordExists)
			})

			t.Run("SetStatus updates status", func(t *testing.T) {
				id := testutil.RandomDID(t)
				require.NoError(t, s.Add(t.Context(), id, "ext-switcher", testutil.RandomDID(t), "switcher", tenant.Active))

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

			t.Run("Delete removes a tenant and is idempotent", func(t *testing.T) {
				id := testutil.RandomDID(t)
				require.NoError(t, s.Add(t.Context(), id, "ext-del", testutil.RandomDID(t), "del", tenant.Active))

				require.NoError(t, s.Delete(t.Context(), id))
				_, err := s.Get(t.Context(), id)
				require.ErrorIs(t, err, store.ErrRecordNotFound)

				// Deleting an absent record is a no-op.
				require.NoError(t, s.Delete(t.Context(), id))
			})
		})
	}
}
