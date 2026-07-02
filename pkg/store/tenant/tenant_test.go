package tenant_test

import (
	"runtime"
	"testing"

	"github.com/fil-forge/hilt/internal/testutil"
	"github.com/fil-forge/hilt/pkg/store"
	providerpostgres "github.com/fil-forge/hilt/pkg/store/provider/postgres"
	"github.com/fil-forge/hilt/pkg/store/tenant"
	tenantmemory "github.com/fil-forge/hilt/pkg/store/tenant/memory"
	tenantpostgres "github.com/fil-forge/hilt/pkg/store/tenant/postgres"
	"github.com/fil-forge/ucantone/did"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"
)

type StoreKind string

const (
	Memory   StoreKind = "memory"
	Postgres StoreKind = "postgres"
)

var storeKinds = []StoreKind{Memory, Postgres}

// seedFunc ensures the parent provider exists so the tenant.provider_id foreign
// key is satisfied. It is a no-op for the memory store, which does not enforce
// referential integrity.
type seedFunc func(t *testing.T, providerID did.DID)

func makeStore(t *testing.T, k StoreKind) (tenant.Store, seedFunc) {
	switch k {
	case Memory:
		return tenantmemory.New(), func(*testing.T, did.DID) {}
	case Postgres:
		pool := createPostgresPool(t)
		providers := providerpostgres.New(pool)
		seed := func(t *testing.T, providerID did.DID) {
			require.NoError(t, providers.Add(t.Context(), providerID, providerID.String()))
		}
		return tenantpostgres.New(pool), seed
	}
	panic("unknown store kind")
}

func createPostgresPool(t *testing.T) *pgxpool.Pool {
	if testutil.IsRunningInCI(t) && runtime.GOOS == "linux" {
		if !testutil.IsDockerAvailable(t) {
			t.Fatalf("docker is expected in CI linux testing environments, but wasn't found")
		}
	}
	if !testutil.IsDockerAvailable(t) {
		t.SkipNow()
	}
	return testutil.CreatePostgres(t)
}

func TestTenantStore(t *testing.T) {
	for _, k := range storeKinds {
		t.Run(string(k), func(t *testing.T) {
			s, seed := makeStore(t, k)

			t.Run("adds and retrieves a tenant", func(t *testing.T) {
				id := testutil.RandomDID(t)
				provider := testutil.RandomDID(t)
				seed(t, provider)
				require.NoError(t, s.Add(t.Context(), id, "ext-acme", provider, tenant.Active))

				rec, err := s.Get(t.Context(), id)
				require.NoError(t, err)
				require.Equal(t, id, rec.ID)
				require.Equal(t, "ext-acme", rec.ExternalID)
				require.Equal(t, provider, rec.Provider)
				require.Equal(t, tenant.Active, rec.Status)
				require.False(t, rec.CreatedAt.IsZero())
			})

			t.Run("Get returns ErrRecordNotFound for unknown id", func(t *testing.T) {
				_, err := s.Get(t.Context(), testutil.RandomDID(t))
				require.ErrorIs(t, err, store.ErrRecordNotFound)
			})

			t.Run("GetByExternalID retrieves a tenant", func(t *testing.T) {
				id := testutil.RandomDID(t)
				provider := testutil.RandomDID(t)
				seed(t, provider)
				require.NoError(t, s.Add(t.Context(), id, "ext-lookup", provider, tenant.Active))

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
				provider := testutil.RandomDID(t)
				seed(t, provider)
				require.NoError(t, s.Add(t.Context(), id, "ext-dup-1", provider, tenant.Active))
				err := s.Add(t.Context(), id, "ext-dup-2", provider, tenant.Active)
				require.ErrorIs(t, err, store.ErrRecordExists)
			})

			t.Run("Add returns ErrRecordExists for duplicate external id", func(t *testing.T) {
				provider := testutil.RandomDID(t)
				seed(t, provider)
				require.NoError(t, s.Add(t.Context(), testutil.RandomDID(t), "ext-shared", provider, tenant.Active))
				err := s.Add(t.Context(), testutil.RandomDID(t), "ext-shared", provider, tenant.Active)
				require.ErrorIs(t, err, store.ErrRecordExists)
			})

			t.Run("SetStatus updates status", func(t *testing.T) {
				id := testutil.RandomDID(t)
				provider := testutil.RandomDID(t)
				seed(t, provider)
				require.NoError(t, s.Add(t.Context(), id, "ext-switcher", provider, tenant.Active))

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
				provider := testutil.RandomDID(t)
				seed(t, provider)
				require.NoError(t, s.Add(t.Context(), id, "ext-del", provider, tenant.Active))

				require.NoError(t, s.Delete(t.Context(), id))
				_, err := s.Get(t.Context(), id)
				require.ErrorIs(t, err, store.ErrRecordNotFound)

				// Deleting an absent record is a no-op.
				require.NoError(t, s.Delete(t.Context(), id))
			})
		})
	}
}
