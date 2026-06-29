package bucket_test

import (
	"context"
	"fmt"
	"runtime"
	"testing"

	"github.com/fil-forge/hilt/internal/testutil"
	"github.com/fil-forge/hilt/pkg/store"
	"github.com/fil-forge/hilt/pkg/store/bucket"
	bucketmemory "github.com/fil-forge/hilt/pkg/store/bucket/memory"
	bucketpostgres "github.com/fil-forge/hilt/pkg/store/bucket/postgres"
	"github.com/stretchr/testify/require"
)

type StoreKind string

const (
	Memory   StoreKind = "memory"
	Postgres StoreKind = "postgres"
)

var storeKinds = []StoreKind{Memory, Postgres}

func makeStore(t *testing.T, k StoreKind) bucket.Store {
	switch k {
	case Memory:
		return bucketmemory.New()
	case Postgres:
		return createPostgresStore(t)
	}
	panic("unknown store kind")
}

func createPostgresStore(t *testing.T) bucket.Store {
	if testutil.IsRunningInCI(t) && runtime.GOOS == "linux" {
		if !testutil.IsDockerAvailable(t) {
			t.Fatalf("docker is expected in CI linux testing environments, but wasn't found")
		}
	}
	if !testutil.IsDockerAvailable(t) {
		t.SkipNow()
	}
	pool := testutil.CreatePostgres(t)
	return bucketpostgres.New(pool)
}

func TestBucketStore(t *testing.T) {
	for _, k := range storeKinds {
		t.Run(string(k), func(t *testing.T) {
			s := makeStore(t, k)

			t.Run("adds and retrieves a bucket by name", func(t *testing.T) {
				id := testutil.RandomDID(t)
				tenant := testutil.RandomDID(t)
				require.NoError(t, s.Add(t.Context(), id, tenant, "photos"))

				rec, err := s.GetByName(t.Context(), "photos")
				require.NoError(t, err)
				require.Equal(t, id, rec.ID)
				require.Equal(t, tenant, rec.Tenant)
				require.Equal(t, "photos", rec.Name)
				require.False(t, rec.CreatedAt.IsZero())
			})

			t.Run("GetByName returns ErrRecordNotFound for unknown name", func(t *testing.T) {
				_, err := s.GetByName(t.Context(), "nope")
				require.ErrorIs(t, err, store.ErrRecordNotFound)
			})

			t.Run("Add returns ErrRecordExists for duplicate id", func(t *testing.T) {
				id := testutil.RandomDID(t)
				require.NoError(t, s.Add(t.Context(), id, testutil.RandomDID(t), "dup-id-a"))
				err := s.Add(t.Context(), id, testutil.RandomDID(t), "dup-id-b")
				require.ErrorIs(t, err, store.ErrRecordExists)
			})

			t.Run("Add returns ErrRecordExists for duplicate name", func(t *testing.T) {
				require.NoError(t, s.Add(t.Context(), testutil.RandomDID(t), testutil.RandomDID(t), "shared-name"))
				err := s.Add(t.Context(), testutil.RandomDID(t), testutil.RandomDID(t), "shared-name")
				require.ErrorIs(t, err, store.ErrRecordExists)
			})

			t.Run("ListByTenant isolates and paginates by tenant", func(t *testing.T) {
				tenant := testutil.RandomDID(t)
				other := testutil.RandomDID(t)
				for i := range 5 {
					require.NoError(t, s.Add(t.Context(), testutil.RandomDID(t), tenant, fmt.Sprintf("lbt-%d", i)))
				}
				require.NoError(t, s.Add(t.Context(), testutil.RandomDID(t), other, "lbt-other"))

				all, err := store.Collect(t.Context(), func(ctx context.Context, opts store.PaginationConfig) (store.Page[bucket.Record], error) {
					var listOpts []store.PaginationOption
					if opts.Cursor != nil {
						listOpts = append(listOpts, store.WithCursor(*opts.Cursor))
					}
					listOpts = append(listOpts, store.WithLimit(2))
					return s.ListByTenant(ctx, tenant, listOpts...)
				})
				require.NoError(t, err)
				require.Len(t, all, 5)
				for _, b := range all {
					require.Equal(t, tenant, b.Tenant)
				}
			})

			t.Run("Delete removes a bucket and is idempotent", func(t *testing.T) {
				id := testutil.RandomDID(t)
				require.NoError(t, s.Add(t.Context(), id, testutil.RandomDID(t), "to-delete"))

				require.NoError(t, s.Delete(t.Context(), id))
				_, err := s.GetByName(t.Context(), "to-delete")
				require.ErrorIs(t, err, store.ErrRecordNotFound)

				require.NoError(t, s.Delete(t.Context(), id))
			})
		})
	}
}
