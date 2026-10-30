package principal_test

import (
	"context"
	"errors"
	"testing"
	"time"

	htestutil "github.com/fil-forge/hilt/internal/testutil"
	"github.com/fil-forge/hilt/pkg/store"
	"github.com/fil-forge/hilt/pkg/store/principal"
	principalmemory "github.com/fil-forge/hilt/pkg/store/principal/memory"
	principalpostgres "github.com/fil-forge/hilt/pkg/store/principal/postgres"
	providerpostgres "github.com/fil-forge/hilt/pkg/store/provider/postgres"
	"github.com/fil-forge/hilt/pkg/store/tenant"
	tenantpostgres "github.com/fil-forge/hilt/pkg/store/tenant/postgres"
	"github.com/fil-forge/libforge/testutil"
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

// seedFunc ensures the parent tenant (and its provider) exist so the
// principal.tenant_id foreign key is satisfied. It is a no-op for the memory
// store, which does not enforce referential integrity.
type seedFunc func(t *testing.T, tenantID did.DID)

func makeStore(t *testing.T, k StoreKind) (principal.Store, seedFunc) {
	switch k {
	case Memory:
		return principalmemory.New(), func(*testing.T, did.DID) {}
	case Postgres:
		pool := htestutil.PostgresOrSkip(t)
		return principalpostgres.New(pool), seeder(pool)
	}
	panic("unknown store kind")
}

func seeder(pool *pgxpool.Pool) seedFunc {
	providers := providerpostgres.New(pool)
	tenants := tenantpostgres.New(pool)
	return func(t *testing.T, tenantID did.DID) {
		providerID := testutil.RandomDID(t)
		require.NoError(t, providers.Add(t.Context(), providerID, tenantID.String(), nil))
		require.NoError(t, tenants.Add(t.Context(), tenantID, "ext-"+tenantID.String(), providerID, tenant.Active))
	}
}

func TestPrincipalStore(t *testing.T) {
	for _, k := range storeKinds {
		t.Run(string(k), func(t *testing.T) {
			s, seed := makeStore(t, k)

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
				require.NoError(t, s.Tombstone(t.Context(), tenantID, "gone", nil))
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
				require.NoError(t, s.Tombstone(t.Context(), tenantID, "again", nil))

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

			t.Run("Tombstone runs the callback once, removes the row and is idempotent", func(t *testing.T) {
				tenantID := testutil.RandomDID(t)
				seed(t, tenantID)
				require.NoError(t, s.Add(t.Context(), tenantID, "del"))

				calls := 0
				require.NoError(t, s.Tombstone(t.Context(), tenantID, "del", func(context.Context) error {
					calls++
					return nil
				}))
				require.Equal(t, 1, calls)
				_, err := s.Get(t.Context(), tenantID, "del")
				require.ErrorIs(t, err, store.ErrRecordNotFound)

				// Deleting an absent principal is a no-op: nothing to publish, so the
				// callback does not run.
				require.NoError(t, s.Tombstone(t.Context(), tenantID, "del", func(context.Context) error {
					calls++
					return nil
				}))
				require.Equal(t, 1, calls)
			})

			t.Run("Tombstone's callback lists the principal being removed as live", func(t *testing.T) {
				// A removal's callback rewrites the tenant's policies, and a policy
				// write lists the tenant's principals; the list answers inside the
				// callback and still holds the principal until the removal commits.
				tenantID := testutil.RandomDID(t)
				seed(t, tenantID)
				require.NoError(t, s.Add(t.Context(), tenantID, "any-user"))

				var listed []string
				require.NoError(t, s.Tombstone(t.Context(), tenantID, "any-user", func(ctx context.Context) error {
					var err error
					listed, err = s.ListIDsByTenant(ctx, tenantID)
					return err
				}))

				require.Equal(t, []string{"any-user"}, listed)
				_, err := s.Get(t.Context(), tenantID, "any-user")
				require.ErrorIs(t, err, store.ErrRecordNotFound)
			})

			t.Run("Tombstone accepts a nil callback", func(t *testing.T) {
				tenantID := testutil.RandomDID(t)
				seed(t, tenantID)
				require.NoError(t, s.Add(t.Context(), tenantID, "nil-cb"))
				require.NoError(t, s.Tombstone(t.Context(), tenantID, "nil-cb", nil))
				_, err := s.Get(t.Context(), tenantID, "nil-cb")
				require.ErrorIs(t, err, store.ErrRecordNotFound)
			})

			t.Run("Tombstone returns the callback error and leaves the row", func(t *testing.T) {
				tenantID := testutil.RandomDID(t)
				seed(t, tenantID)
				require.NoError(t, s.Add(t.Context(), tenantID, "keep"))

				publishFailed := errors.New("publish failed")
				err := s.Tombstone(t.Context(), tenantID, "keep", func(context.Context) error {
					return publishFailed
				})
				require.ErrorIs(t, err, publishFailed)

				rec, err := s.Get(t.Context(), tenantID, "keep")
				require.NoError(t, err)
				require.Equal(t, "keep", rec.ExternalID)

				// A retry after the failure completes the removal.
				require.NoError(t, s.Tombstone(t.Context(), tenantID, "keep", nil))
				_, err = s.Get(t.Context(), tenantID, "keep")
				require.ErrorIs(t, err, store.ErrRecordNotFound)
			})

			t.Run("DeleteByTenant removes every principal of the tenant and is idempotent", func(t *testing.T) {
				tenantID := testutil.RandomDID(t)
				other := testutil.RandomDID(t)
				seed(t, tenantID)
				seed(t, other)
				require.NoError(t, s.Add(t.Context(), tenantID, "a"))
				require.NoError(t, s.Add(t.Context(), tenantID, "b"))
				require.NoError(t, s.Add(t.Context(), other, "a"))

				require.NoError(t, s.DeleteByTenant(t.Context(), tenantID))
				recs, err := s.ListByTenant(t.Context(), tenantID)
				require.NoError(t, err)
				require.Empty(t, recs)
				recs, err = s.ListByTenant(t.Context(), other)
				require.NoError(t, err)
				require.Len(t, recs, 1)

				require.NoError(t, s.DeleteByTenant(t.Context(), tenantID))
			})
		})
	}
}
