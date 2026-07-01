package bucket_test

import (
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
		})
	}
}
