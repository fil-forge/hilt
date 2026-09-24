package principal_test

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	htestutil "github.com/fil-forge/hilt/internal/testutil"
	"github.com/fil-forge/hilt/pkg/bucketpolicy"
	"github.com/fil-forge/hilt/pkg/store"
	bucketpostgres "github.com/fil-forge/hilt/pkg/store/bucket/postgres"
	bucketpolicystore "github.com/fil-forge/hilt/pkg/store/bucketpolicy"
	bucketpolicypostgres "github.com/fil-forge/hilt/pkg/store/bucketpolicy/postgres"
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

			t.Run("Get honours the share lock option", func(t *testing.T) {
				tenantID := testutil.RandomDID(t)
				seed(t, tenantID)
				require.NoError(t, s.Add(t.Context(), tenantID, "user-1"))

				rec, err := s.Get(t.Context(), tenantID, "user-1", store.LockShare)
				require.NoError(t, err)
				require.Equal(t, "user-1", rec.ExternalID)
			})

			t.Run("Get returns ErrRecordNotFound for an unknown principal", func(t *testing.T) {
				tenantID := testutil.RandomDID(t)
				seed(t, tenantID)
				_, err := s.Get(t.Context(), tenantID, "nobody")
				require.ErrorIs(t, err, store.ErrRecordNotFound)
				_, err = s.Get(t.Context(), tenantID, "nobody", store.LockShare)
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

			t.Run("Add revives a removed principal with a fresh CreatedAt", func(t *testing.T) {
				tenantID := testutil.RandomDID(t)
				seed(t, tenantID)
				require.NoError(t, s.Add(t.Context(), tenantID, "again"))
				first, err := s.Get(t.Context(), tenantID, "again")
				require.NoError(t, err)
				require.NoError(t, s.Delete(t.Context(), tenantID, "again", nil))

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

			t.Run("Delete runs the callback once, removes the row and is idempotent", func(t *testing.T) {
				tenantID := testutil.RandomDID(t)
				seed(t, tenantID)
				require.NoError(t, s.Add(t.Context(), tenantID, "del"))

				calls := 0
				require.NoError(t, s.Delete(t.Context(), tenantID, "del", func(context.Context) error {
					calls++
					return nil
				}))
				require.Equal(t, 1, calls)
				_, err := s.Get(t.Context(), tenantID, "del")
				require.ErrorIs(t, err, store.ErrRecordNotFound)

				// Deleting an absent principal is a no-op: nothing to publish, so the
				// callback does not run.
				require.NoError(t, s.Delete(t.Context(), tenantID, "del", func(context.Context) error {
					calls++
					return nil
				}))
				require.Equal(t, 1, calls)
			})

			t.Run("Delete holds only the removal: ListByTenant answers, a share-locked Get waits", func(t *testing.T) {
				// The locking both backends owe the two writers that cross here:
				// a policy write lists the tenant's principals from inside its own
				// lock while a removal's callback rewrites that tenant's policies.
				// The list must not wait on the removal, and a share-locked read
				// must.
				tenantID := testutil.RandomDID(t)
				seed(t, tenantID)
				require.NoError(t, s.Add(t.Context(), tenantID, "held"))

				deleted, got := htestutil.RequireWaitsForWriter(t,
					func(entered chan<- struct{}, release <-chan struct{}) error {
						return s.Delete(context.Background(), tenantID, "held", func(ctx context.Context) error {
							recs, err := s.ListByTenant(ctx, tenantID)
							if err != nil {
								return err
							}
							if len(recs) != 1 {
								return fmt.Errorf("listed %d principals during the removal, want the live one", len(recs))
							}
							close(entered)
							<-release
							return nil
						})
					},
					func() error {
						_, err := s.Get(context.Background(), tenantID, "held", store.LockShare)
						return err
					})
				require.NoError(t, deleted)
				require.ErrorIs(t, got, store.ErrRecordNotFound, "the tombstone is visible once the removal commits")
			})

			t.Run("Delete accepts a nil callback", func(t *testing.T) {
				tenantID := testutil.RandomDID(t)
				seed(t, tenantID)
				require.NoError(t, s.Add(t.Context(), tenantID, "nil-cb"))
				require.NoError(t, s.Delete(t.Context(), tenantID, "nil-cb", nil))
				_, err := s.Get(t.Context(), tenantID, "nil-cb")
				require.ErrorIs(t, err, store.ErrRecordNotFound)
			})

			t.Run("Delete returns the callback error and leaves the row", func(t *testing.T) {
				tenantID := testutil.RandomDID(t)
				seed(t, tenantID)
				require.NoError(t, s.Add(t.Context(), tenantID, "keep"))

				publishFailed := errors.New("publish failed")
				err := s.Delete(t.Context(), tenantID, "keep", func(context.Context) error {
					return publishFailed
				})
				require.ErrorIs(t, err, publishFailed)

				rec, err := s.Get(t.Context(), tenantID, "keep")
				require.NoError(t, err)
				require.Equal(t, "keep", rec.ExternalID)

				// A retry after the failure completes the removal.
				require.NoError(t, s.Delete(t.Context(), tenantID, "keep", nil))
				_, err = s.Get(t.Context(), tenantID, "keep")
				require.ErrorIs(t, err, store.ErrRecordNotFound)
			})

			t.Run("Lock runs the callback once and returns its error", func(t *testing.T) {
				tenantID := testutil.RandomDID(t)
				seed(t, tenantID)
				require.NoError(t, s.Add(t.Context(), tenantID, "held"))

				calls := 0
				require.NoError(t, s.Lock(t.Context(), tenantID, []string{"held", "absent"}, func(ctx context.Context) error {
					calls++
					return nil
				}))
				require.Equal(t, 1, calls)

				boom := errors.New("boom")
				err := s.Lock(t.Context(), tenantID, []string{"held"}, func(ctx context.Context) error { return boom })
				require.ErrorIs(t, err, boom)
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

// TestPrincipalStorePostgresLocking pins the locking contract the authorizer
// relies on: a share-locked Get waits for a transaction that holds the row FOR
// UPDATE, and is answered once that transaction commits. Postgres only: the
// memory store cannot hold a row across calls.
func TestPrincipalStorePostgresLocking(t *testing.T) {
	pool := htestutil.PostgresOrSkip(t)
	s := principalpostgres.New(pool)
	seed := seeder(pool)

	t.Run("a FOR UPDATE holder blocks a share-locked Get until commit", func(t *testing.T) {
		tenantID := testutil.RandomDID(t)
		seed(t, tenantID)
		require.NoError(t, s.Add(t.Context(), tenantID, "locked"))

		tx, err := pool.Begin(t.Context())
		require.NoError(t, err)
		defer tx.Rollback(t.Context())

		var rec principal.Record
		committed, got := htestutil.RequireWaitsForWriter(t,
			func(entered chan<- struct{}, release <-chan struct{}) error {
				var found bool
				if err := tx.QueryRow(t.Context(),
					`SELECT TRUE FROM principal WHERE tenant_id = $1 AND external_id = $2 FOR UPDATE`,
					tenantID.String(), "locked").Scan(&found); err != nil {
					return err
				}
				// An unlocked read is answered from the snapshot and never waits.
				if _, err := s.Get(t.Context(), tenantID, "locked"); err != nil {
					return fmt.Errorf("unlocked Get during the hold: %w", err)
				}
				close(entered)
				<-release
				return tx.Commit(t.Context())
			},
			func() error {
				var err error
				rec, err = s.Get(context.Background(), tenantID, "locked", store.LockShare)
				return err
			})
		require.NoError(t, committed)
		require.NoError(t, got)
		require.Equal(t, "locked", rec.ExternalID)
	})

	t.Run("a share-locked Get waits for Lock's callback", func(t *testing.T) {
		tenantID := testutil.RandomDID(t)
		seed(t, tenantID)
		require.NoError(t, s.Add(t.Context(), tenantID, "held"))

		locked, got := htestutil.RequireWaitsForWriter(t,
			func(entered chan<- struct{}, release <-chan struct{}) error {
				return s.Lock(context.Background(), tenantID, []string{"held"}, func(ctx context.Context) error {
					close(entered)
					<-release
					return nil
				})
			},
			func() error {
				_, err := s.Get(context.Background(), tenantID, "held", store.LockShare)
				return err
			})
		require.NoError(t, locked)
		require.NoError(t, got)
	})

	t.Run("a share-locked Get during Delete sees the row once the callback fails", func(t *testing.T) {
		tenantID := testutil.RandomDID(t)
		seed(t, tenantID)
		require.NoError(t, s.Add(t.Context(), tenantID, "rollback"))

		var rec principal.Record
		deleted, got := htestutil.RequireWaitsForWriter(t,
			func(entered chan<- struct{}, release <-chan struct{}) error {
				return s.Delete(context.Background(), tenantID, "rollback", func(context.Context) error {
					close(entered)
					<-release
					return errors.New("publish failed")
				})
			},
			func() error {
				var err error
				rec, err = s.Get(context.Background(), tenantID, "rollback", store.LockShare)
				return err
			})
		require.Error(t, deleted)
		require.NoError(t, got, "the rolled-back delete must leave the row readable")
		require.Equal(t, "rollback", rec.ExternalID)
	})

	t.Run("a share-locked Get during Delete reports the row gone once it commits", func(t *testing.T) {
		tenantID := testutil.RandomDID(t)
		seed(t, tenantID)
		require.NoError(t, s.Add(t.Context(), tenantID, "gone"))

		deleted, got := htestutil.RequireWaitsForWriter(t,
			func(entered chan<- struct{}, release <-chan struct{}) error {
				return s.Delete(context.Background(), tenantID, "gone", func(context.Context) error {
					close(entered)
					<-release
					return nil
				})
			},
			func() error {
				_, err := s.Get(context.Background(), tenantID, "gone", store.LockShare)
				return err
			})
		require.NoError(t, deleted)
		require.ErrorIs(t, got, store.ErrRecordNotFound)
	})
}

// TestPrincipalStorePostgresLockTimeout pins the bounded wait that keeps a
// principal removal and the writes that reach onto its row from hanging on
// each other. Removal holds the principal row FOR UPDATE across a callback
// that rewrites policies in transactions of its own, while a policy write
// reaches back onto the same row through the bucket_policy_principal foreign
// key; re-adding the principal and locking it for a policy write take the
// row itself. Neither edge is visible to Postgres, so the wait is bounded and
// one side is told to retry. Postgres only: the memory stores hold no lock
// across calls.
func TestPrincipalStorePostgresLockTimeout(t *testing.T) {
	pool := htestutil.PostgresOrSkip(t)
	principals := principalpostgres.New(pool)
	seed := seeder(pool)

	// Each case is one statement that waits on the held principal row; op runs
	// it and unwritten checks that its transaction left nothing behind.
	cases := []struct {
		name      string
		op        func(ctx context.Context, tenantID did.DID) error
		unwritten func(t *testing.T, tenantID did.DID)
	}{
		{
			name: "a policy write naming the principal",
			op: func(ctx context.Context, tenantID did.DID) error {
				bucketID := testutil.RandomDID(t)
				if err := bucketpostgres.New(pool).Add(ctx, bucketID, tenantID, "lock-timeout-bucket"); err != nil {
					return err
				}
				_, err := bucketpolicypostgres.New(pool).Put(ctx, bucketpolicystore.Input{
					Bucket: bucketID,
					Tenant: tenantID,
					Policy: bucketpolicy.Policy{Statements: []bucketpolicy.Statement{{
						Effect:    bucketpolicy.Allow,
						Principal: bucketpolicy.Only("held"),
						Actions:   []string{"s3:GetObject"},
					}}},
				}, nil)
				return err
			},
			unwritten: func(t *testing.T, tenantID did.DID) {
				recs, err := bucketpolicypostgres.New(pool).ListByPrincipal(t.Context(), tenantID, "held")
				require.NoError(t, err)
				require.Empty(t, recs)
			},
		},
		{
			name: "re-adding the principal",
			op: func(ctx context.Context, tenantID did.DID) error {
				return principals.Add(ctx, tenantID, "held")
			},
			unwritten: func(t *testing.T, tenantID did.DID) {
				recs, err := principals.ListByTenant(t.Context(), tenantID)
				require.NoError(t, err)
				require.Len(t, recs, 1, "the live row is untouched")
			},
		},
		{
			name: "locking the principal for a policy write",
			op: func(ctx context.Context, tenantID did.DID) error {
				return principals.Lock(ctx, tenantID, []string{"held"}, func(context.Context) error {
					return errors.New("the callback must not run while the row is held")
				})
			},
			unwritten: func(*testing.T, did.DID) {},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tenantID := testutil.RandomDID(t)
			seed(t, tenantID)
			require.NoError(t, principals.Add(t.Context(), tenantID, "held"))

			// Stand in for a removal in progress: hold the principal row FOR UPDATE.
			tx, err := pool.Begin(t.Context())
			require.NoError(t, err)
			defer tx.Rollback(t.Context())
			var found bool
			require.NoError(t, tx.QueryRow(t.Context(),
				`SELECT TRUE FROM principal WHERE tenant_id = $1 AND external_id = $2 FOR UPDATE`,
				tenantID.String(), "held").Scan(&found))

			type result struct {
				err     error
				elapsed time.Duration
			}
			done := make(chan result, 1)
			go func() {
				start := time.Now()
				err := tc.op(context.Background(), tenantID)
				done <- result{err, time.Since(start)}
			}()

			select {
			case res := <-done:
				require.ErrorIs(t, res.err, store.ErrLockTimeout)
				require.Greater(t, res.elapsed, store.LockTimeout/2,
					"the write failed before it could have waited out the lock timeout")
			case <-time.After(store.LockTimeout + 10*time.Second):
				t.Fatal("the write did not give up waiting for the principal row lock")
			}
			// Nothing was written: the transaction rolled back with its failed lock.
			tc.unwritten(t, tenantID)
		})
	}
}
