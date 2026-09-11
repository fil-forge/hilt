package principal_test

import (
	"context"
	"errors"
	"runtime"
	"testing"
	"time"

	htestutil "github.com/fil-forge/hilt/internal/testutil"
	"github.com/fil-forge/hilt/pkg/bucketpolicy"
	"github.com/fil-forge/hilt/pkg/store"
	"github.com/fil-forge/hilt/pkg/store/accesskey"
	accesskeypostgres "github.com/fil-forge/hilt/pkg/store/accesskey/postgres"
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
		pool := createPostgresPool(t)
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

				rec, err := s.Get(t.Context(), tenantID, "user-1", store.WithLock(store.LockShare))
				require.NoError(t, err)
				require.Equal(t, "user-1", rec.ExternalID)
			})

			t.Run("Get returns ErrRecordNotFound for an unknown principal", func(t *testing.T) {
				tenantID := testutil.RandomDID(t)
				seed(t, tenantID)
				_, err := s.Get(t.Context(), tenantID, "nobody")
				require.ErrorIs(t, err, store.ErrRecordNotFound)
				_, err = s.Get(t.Context(), tenantID, "nobody", store.WithLock(store.LockShare))
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
// memory store serializes under a mutex and cannot hold a row across calls.
func TestPrincipalStorePostgresLocking(t *testing.T) {
	pool := createPostgresPool(t)
	s := principalpostgres.New(pool)
	seed := seeder(pool)

	// waitBlocked reports whether get has not returned within a grace period.
	const grace = 300 * time.Millisecond

	t.Run("a FOR UPDATE holder blocks a share-locked Get until commit", func(t *testing.T) {
		tenantID := testutil.RandomDID(t)
		seed(t, tenantID)
		require.NoError(t, s.Add(t.Context(), tenantID, "locked"))

		tx, err := pool.Begin(t.Context())
		require.NoError(t, err)
		defer tx.Rollback(t.Context())
		var found bool
		require.NoError(t, tx.QueryRow(t.Context(),
			`SELECT TRUE FROM principal WHERE tenant_id = $1 AND external_id = $2 FOR UPDATE`,
			tenantID.String(), "locked").Scan(&found))

		// An unlocked read is answered from the snapshot and never waits.
		rec, err := s.Get(t.Context(), tenantID, "locked")
		require.NoError(t, err)
		require.Equal(t, "locked", rec.ExternalID)

		type result struct {
			rec principal.Record
			err error
		}
		done := make(chan result, 1)
		go func() {
			rec, err := s.Get(context.Background(), tenantID, "locked", store.WithLock(store.LockShare))
			done <- result{rec, err}
		}()

		select {
		case <-done:
			t.Fatal("share-locked Get returned while the row was held FOR UPDATE")
		case <-time.After(grace):
		}

		require.NoError(t, tx.Commit(t.Context()))

		select {
		case res := <-done:
			require.NoError(t, res.err)
			require.Equal(t, "locked", res.rec.ExternalID)
		case <-time.After(10 * time.Second):
			t.Fatal("share-locked Get did not return after the holder committed")
		}
	})

	t.Run("a share-locked Get during Delete sees the row once the callback fails", func(t *testing.T) {
		tenantID := testutil.RandomDID(t)
		seed(t, tenantID)
		require.NoError(t, s.Add(t.Context(), tenantID, "rollback"))

		type result struct {
			rec principal.Record
			err error
		}
		inCallback := make(chan struct{})
		release := make(chan struct{})
		got := make(chan result, 1)
		deleted := make(chan error, 1)

		go func() {
			deleted <- s.Delete(context.Background(), tenantID, "rollback", func(context.Context) error {
				close(inCallback)
				<-release
				return errors.New("publish failed")
			})
		}()
		<-inCallback

		go func() {
			rec, err := s.Get(context.Background(), tenantID, "rollback", store.WithLock(store.LockShare))
			got <- result{rec, err}
		}()
		select {
		case <-got:
			t.Fatal("share-locked Get returned while Delete held the row")
		case <-time.After(grace):
		}

		close(release)
		require.Error(t, <-deleted)
		select {
		case res := <-got:
			require.NoError(t, res.err, "the rolled-back delete must leave the row readable")
			require.Equal(t, "rollback", res.rec.ExternalID)
		case <-time.After(10 * time.Second):
			t.Fatal("share-locked Get did not return after the delete rolled back")
		}
	})

	t.Run("a share-locked Get during Delete reports the row gone once it commits", func(t *testing.T) {
		tenantID := testutil.RandomDID(t)
		seed(t, tenantID)
		require.NoError(t, s.Add(t.Context(), tenantID, "gone"))

		inCallback := make(chan struct{})
		release := make(chan struct{})
		got := make(chan error, 1)
		deleted := make(chan error, 1)

		go func() {
			deleted <- s.Delete(context.Background(), tenantID, "gone", func(context.Context) error {
				close(inCallback)
				<-release
				return nil
			})
		}()
		<-inCallback

		go func() {
			_, err := s.Get(context.Background(), tenantID, "gone", store.WithLock(store.LockShare))
			got <- err
		}()
		select {
		case <-got:
			t.Fatal("share-locked Get returned while Delete held the row")
		case <-time.After(grace):
		}

		close(release)
		require.NoError(t, <-deleted)
		select {
		case err := <-got:
			require.ErrorIs(t, err, store.ErrRecordNotFound)
		case <-time.After(10 * time.Second):
			t.Fatal("share-locked Get did not return after the delete committed")
		}
	})
}

// TestPrincipalStorePostgresLockTimeout pins the bounded wait that keeps a
// principal removal and a policy write from hanging on each other. Removal
// holds the principal row FOR UPDATE across a callback that rewrites policies
// in transactions of its own, while a policy write reaches back onto the same
// rows through the bucket_policy_principal foreign key. Neither edge is
// visible to Postgres, so the wait is bounded and one side is told to retry.
// Postgres only: the memory stores hold no lock across calls.
func TestPrincipalStorePostgresLockTimeout(t *testing.T) {
	pool := createPostgresPool(t)
	principals := principalpostgres.New(pool)
	policies := bucketpolicypostgres.New(pool)
	seed := seeder(pool)

	tenantID := testutil.RandomDID(t)
	seed(t, tenantID)
	require.NoError(t, principals.Add(t.Context(), tenantID, "held"))

	bucketID := testutil.RandomDID(t)
	require.NoError(t, bucketpostgres.New(pool).Add(t.Context(), bucketID, tenantID, "lock-timeout-bucket"))

	// Stand in for a removal in progress: hold the principal row FOR UPDATE.
	tx, err := pool.Begin(t.Context())
	require.NoError(t, err)
	defer tx.Rollback(t.Context())
	var found bool
	require.NoError(t, tx.QueryRow(t.Context(),
		`SELECT TRUE FROM principal WHERE tenant_id = $1 AND external_id = $2 FOR UPDATE`,
		tenantID.String(), "held").Scan(&found))

	// The policy write indexes the principal it names, which waits on that row.
	type result struct {
		err     error
		elapsed time.Duration
	}
	done := make(chan result, 1)
	go func() {
		start := time.Now()
		_, err := policies.Put(context.Background(), bucketpolicystore.Input{
			Bucket: bucketID,
			Tenant: tenantID,
			Policy: bucketpolicy.Policy{Statements: []bucketpolicy.Statement{{
				Effect:     bucketpolicy.Allow,
				Principals: []string{"held"},
				Actions:    []string{"s3:GetObject"},
			}}},
		}, nil)
		done <- result{err, time.Since(start)}
	}()

	select {
	case res := <-done:
		require.ErrorIs(t, res.err, store.ErrLockTimeout)
		require.Greater(t, res.elapsed, store.LockTimeout/2,
			"Put failed before it could have waited out the lock timeout")
	case <-time.After(store.LockTimeout + 10*time.Second):
		t.Fatal("Put did not give up waiting for the principal row lock")
	}

	// Nothing was written: the transaction rolled back with its failed lock.
	_, err = policies.Get(t.Context(), bucketID)
	require.ErrorIs(t, err, store.ErrRecordNotFound)
}

// TestPrincipalStorePostgresLockTimeoutOnKeyAdd pins the same bound on the
// other statement that reaches onto a held principal row: adding a key bound
// to the principal takes FOR KEY SHARE on it through the access_key foreign
// key, which a removal holding the row FOR UPDATE blocks. Postgres only.
func TestPrincipalStorePostgresLockTimeoutOnKeyAdd(t *testing.T) {
	pool := createPostgresPool(t)
	principals := principalpostgres.New(pool)
	accessKeys := accesskeypostgres.New(pool)
	seed := seeder(pool)

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

	keyID := testutil.RandomDID(t)
	principal := "held"
	type result struct {
		err     error
		elapsed time.Duration
	}
	done := make(chan result, 1)
	go func() {
		start := time.Now()
		err := accessKeys.Add(context.Background(), accesskey.Input{
			ID:        keyID,
			Tenant:    tenantID,
			Name:      "laptop",
			Principal: &principal,
		})
		done <- result{err, time.Since(start)}
	}()

	select {
	case res := <-done:
		require.ErrorIs(t, res.err, store.ErrLockTimeout)
		require.Greater(t, res.elapsed, store.LockTimeout/2,
			"Add failed before it could have waited out the lock timeout")
	case <-time.After(store.LockTimeout + 10*time.Second):
		t.Fatal("Add did not give up waiting for the principal row lock")
	}

	// Nothing was written: the transaction rolled back with its failed lock.
	_, err = accessKeys.Get(t.Context(), keyID)
	require.ErrorIs(t, err, store.ErrRecordNotFound)
}
