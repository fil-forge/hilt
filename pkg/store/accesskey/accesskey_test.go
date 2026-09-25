package accesskey_test

import (
	"context"
	"fmt"
	"runtime"
	"testing"
	"time"

	htestutil "github.com/fil-forge/hilt/internal/testutil"
	"github.com/fil-forge/hilt/pkg/store"
	"github.com/fil-forge/hilt/pkg/store/accesskey"
	accesskeymemory "github.com/fil-forge/hilt/pkg/store/accesskey/memory"
	accesskeypostgres "github.com/fil-forge/hilt/pkg/store/accesskey/postgres"
	providerpostgres "github.com/fil-forge/hilt/pkg/store/provider/postgres"
	"github.com/fil-forge/hilt/pkg/store/tenant"
	tenantmemory "github.com/fil-forge/hilt/pkg/store/tenant/memory"
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

// seedFunc ensures the parent tenant (and, for Postgres, its provider) exists so
// the access_key.tenant_id foreign key is satisfied and Add can check the
// tenant's status.
type seedFunc func(t *testing.T, tenantID did.DID)

// makeStore returns the store, a seed for its tenants, the tenant store it reads
// status from, and the Postgres pool (nil for memory).
func makeStore(t *testing.T, k StoreKind) (accesskey.Store, seedFunc, tenant.Store, *pgxpool.Pool) {
	switch k {
	case Memory:
		tenants := tenantmemory.New()
		seed := func(t *testing.T, tenantID did.DID) {
			require.NoError(t, tenants.Add(t.Context(), tenantID, "ext-"+tenantID.String(), testutil.RandomDID(t), tenant.Active))
		}
		return accesskeymemory.New(tenants), seed, tenants, nil
	case Postgres:
		pool := createPostgresPool(t)
		providers := providerpostgres.New(pool)
		tenants := tenantpostgres.New(pool)
		seed := func(t *testing.T, tenantID did.DID) {
			providerID := testutil.RandomDID(t)
			require.NoError(t, providers.Add(t.Context(), providerID, tenantID.String(), nil))
			require.NoError(t, tenants.Add(t.Context(), tenantID, "ext-"+tenantID.String(), providerID, tenant.Active))
		}
		return accesskeypostgres.New(pool), seed, tenants, pool
	}
	panic("unknown store kind")
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

func TestAccessKeyStore(t *testing.T) {
	for _, k := range storeKinds {
		t.Run(string(k), func(t *testing.T) {
			s, seed, tenants, pool := makeStore(t, k)

			t.Run("adds and retrieves an access key with buckets and permissions", func(t *testing.T) {
				id := testutil.RandomDID(t)
				tenantID := testutil.RandomDID(t)
				seed(t, tenantID)
				buckets := []did.DID{testutil.RandomDID(t), testutil.RandomDID(t)}
				perms := []string{"s3:GetObject", "s3:PutObject"}
				require.NoError(t, s.Add(t.Context(), id, tenantID, "ci-key", buckets, perms, nil))

				rec, err := s.Get(t.Context(), id)
				require.NoError(t, err)
				require.Equal(t, id, rec.ID)
				require.Equal(t, tenantID, rec.Tenant)
				require.Equal(t, "ci-key", rec.Name)
				require.Equal(t, buckets, rec.Buckets)
				require.Equal(t, perms, rec.Permissions)
				require.Nil(t, rec.ExpiresAt)
				require.False(t, rec.CreatedAt.IsZero())
			})

			t.Run("persists an expiry that round-trips", func(t *testing.T) {
				id := testutil.RandomDID(t)
				tenantID := testutil.RandomDID(t)
				seed(t, tenantID)
				expires := time.Date(2027, 1, 2, 3, 4, 5, 0, time.UTC)
				require.NoError(t, s.Add(t.Context(), id, tenantID, "exp", nil, []string{"s3:GetObject"}, &expires))

				rec, err := s.Get(t.Context(), id)
				require.NoError(t, err)
				require.NotNil(t, rec.ExpiresAt)
				require.True(t, expires.Equal(*rec.ExpiresAt))
			})

			t.Run("adds an access key with empty buckets (all-buckets)", func(t *testing.T) {
				id := testutil.RandomDID(t)
				tenantID := testutil.RandomDID(t)
				seed(t, tenantID)
				perms := []string{"s3:ListAllMyBuckets"}
				require.NoError(t, s.Add(t.Context(), id, tenantID, "all", nil, perms, nil))

				rec, err := s.Get(t.Context(), id)
				require.NoError(t, err)
				require.Empty(t, rec.Buckets)
				require.Equal(t, perms, rec.Permissions)
			})

			t.Run("Get returns ErrRecordNotFound for unknown id", func(t *testing.T) {
				_, err := s.Get(t.Context(), testutil.RandomDID(t))
				require.ErrorIs(t, err, store.ErrRecordNotFound)
			})

			t.Run("Add returns ErrRecordExists for duplicate id", func(t *testing.T) {
				id := testutil.RandomDID(t)
				tenantID := testutil.RandomDID(t)
				seed(t, tenantID)
				require.NoError(t, s.Add(t.Context(), id, tenantID, "dup", nil, []string{"s3:GetObject"}, nil))
				err := s.Add(t.Context(), id, tenantID, "dup", nil, []string{"s3:GetObject"}, nil)
				require.ErrorIs(t, err, store.ErrRecordExists)
			})

			t.Run("Add returns ErrRecordExists for duplicate (tenant, name)", func(t *testing.T) {
				tenantID := testutil.RandomDID(t)
				otherTenant := testutil.RandomDID(t)
				seed(t, tenantID)
				seed(t, otherTenant)
				require.NoError(t, s.Add(t.Context(), testutil.RandomDID(t), tenantID, "name-dup", nil, []string{"s3:GetObject"}, nil))
				// Same tenant + name but a different id must be rejected.
				err := s.Add(t.Context(), testutil.RandomDID(t), tenantID, "name-dup", nil, []string{"s3:GetObject"}, nil)
				require.ErrorIs(t, err, store.ErrRecordExists)
				// The same name under a different tenant is allowed.
				require.NoError(t, s.Add(t.Context(), testutil.RandomDID(t), otherTenant, "name-dup", nil, []string{"s3:GetObject"}, nil))
			})

			t.Run("Add returns ErrInvalidArgument for undef access key ID", func(t *testing.T) {
				tenantID := testutil.RandomDID(t)
				seed(t, tenantID)
				err := s.Add(t.Context(), did.Undef, tenantID, "undef-id", nil, []string{"s3:GetObject"}, nil)
				require.ErrorIs(t, err, store.ErrInvalidArgument)
			})

			t.Run("Add returns ErrInvalidArgument for undef tenant", func(t *testing.T) {
				err := s.Add(t.Context(), testutil.RandomDID(t), did.Undef, "undef-tenant", nil, []string{"s3:GetObject"}, nil)
				require.ErrorIs(t, err, store.ErrInvalidArgument)
			})

			t.Run("Add returns ErrInvalidArgument for empty name", func(t *testing.T) {
				tenantID := testutil.RandomDID(t)
				seed(t, tenantID)
				err := s.Add(t.Context(), testutil.RandomDID(t), tenantID, "", nil, []string{"s3:GetObject"}, nil)
				require.ErrorIs(t, err, store.ErrInvalidArgument)
			})

			t.Run("Add returns ErrInvalidArgument for buckets containing an undef DID", func(t *testing.T) {
				tenantID := testutil.RandomDID(t)
				seed(t, tenantID)
				buckets := []did.DID{testutil.RandomDID(t), did.Undef}
				err := s.Add(t.Context(), testutil.RandomDID(t), tenantID, "undef-bucket", buckets, []string{"s3:GetObject"}, nil)
				require.ErrorIs(t, err, store.ErrInvalidArgument)
			})

			t.Run("ListByTenant isolates by tenant", func(t *testing.T) {
				tenantID := testutil.RandomDID(t)
				other := testutil.RandomDID(t)
				seed(t, tenantID)
				seed(t, other)
				for i := range 3 {
					require.NoError(t, s.Add(t.Context(), testutil.RandomDID(t), tenantID, fmt.Sprintf("k%d", i), nil, []string{"s3:GetObject"}, nil))
				}
				require.NoError(t, s.Add(t.Context(), testutil.RandomDID(t), other, "k0", nil, []string{"s3:GetObject"}, nil))

				recs, err := s.ListByTenant(t.Context(), tenantID)
				require.NoError(t, err)
				require.Len(t, recs, 3)
				for _, r := range recs {
					require.Equal(t, tenantID, r.Tenant)
				}
			})

			t.Run("Delete removes an access key and is idempotent", func(t *testing.T) {
				id := testutil.RandomDID(t)
				tenantID := testutil.RandomDID(t)
				seed(t, tenantID)
				require.NoError(t, s.Add(t.Context(), id, tenantID, "del", nil, []string{"s3:GetObject"}, nil))

				require.NoError(t, s.Delete(t.Context(), id))
				_, err := s.Get(t.Context(), id)
				require.ErrorIs(t, err, store.ErrRecordNotFound)

				require.NoError(t, s.Delete(t.Context(), id))
			})

			t.Run("Add returns ErrTenantDisabled for a disabled tenant", func(t *testing.T) {
				tenantID := testutil.RandomDID(t)
				seed(t, tenantID)
				require.NoError(t, tenants.SetStatus(t.Context(), tenantID, tenant.Disabled))

				err := s.Add(t.Context(), testutil.RandomDID(t), tenantID, "k", nil, []string{"s3:GetObject"}, nil)
				require.ErrorIs(t, err, accesskey.ErrTenantDisabled)
				recs, err := s.ListByTenant(t.Context(), tenantID)
				require.NoError(t, err)
				require.Empty(t, recs)
			})

			if pool == nil {
				return
			}
			t.Run("Add waits for a concurrent disable and refuses the key", func(t *testing.T) {
				tenantID := testutil.RandomDID(t)
				seed(t, tenantID)

				// An uncommitted disable holds the tenant row; Add must wait for it
				// and see the committed status, or a tenant deletion's key snapshot
				// could miss the key.
				tx, err := pool.Begin(t.Context())
				require.NoError(t, err)
				defer tx.Rollback(context.Background())
				_, err = tx.Exec(t.Context(), `UPDATE tenant SET status = 'disabled' WHERE id = $1`, tenantID.String())
				require.NoError(t, err)

				done := make(chan error, 1)
				go func() {
					done <- s.Add(t.Context(), testutil.RandomDID(t), tenantID, "k", nil, []string{"s3:GetObject"}, nil)
				}()
				// ponytail: sleep only lets Add reach the lock; a miss makes the test
				// pass vacuously, never flake red.
				time.Sleep(200 * time.Millisecond)
				require.NoError(t, tx.Commit(t.Context()))

				require.ErrorIs(t, <-done, accesskey.ErrTenantDisabled)
			})
		})
	}
}
