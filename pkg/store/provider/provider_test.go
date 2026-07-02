package provider_test

import (
	"runtime"
	"testing"

	"github.com/fil-forge/hilt/internal/testutil"
	"github.com/fil-forge/hilt/pkg/store"
	"github.com/fil-forge/hilt/pkg/store/provider"
	providermemory "github.com/fil-forge/hilt/pkg/store/provider/memory"
	providerpostgres "github.com/fil-forge/hilt/pkg/store/provider/postgres"
	"github.com/stretchr/testify/require"
)

type StoreKind string

const (
	Memory   StoreKind = "memory"
	Postgres StoreKind = "postgres"
)

var storeKinds = []StoreKind{Memory, Postgres}

func makeStore(t *testing.T, k StoreKind) provider.Store {
	switch k {
	case Memory:
		return providermemory.New()
	case Postgres:
		return createPostgresStore(t)
	}
	panic("unknown store kind")
}

func createPostgresStore(t *testing.T) provider.Store {
	if testutil.IsRunningInCI(t) && runtime.GOOS == "linux" {
		if !testutil.IsDockerAvailable(t) {
			t.Fatalf("docker is expected in CI linux testing environments, but wasn't found")
		}
	}
	if !testutil.IsDockerAvailable(t) {
		t.SkipNow()
	}
	pool := testutil.CreatePostgres(t)
	return providerpostgres.New(pool)
}

func TestProviderStore(t *testing.T) {
	for _, k := range storeKinds {
		t.Run(string(k), func(t *testing.T) {
			s := makeStore(t, k)

			t.Run("adds and retrieves a provider by region", func(t *testing.T) {
				id := testutil.RandomDID(t)
				require.NoError(t, s.Add(t.Context(), id, "us-east-1"))

				rec, err := s.GetByRegion(t.Context(), "us-east-1")
				require.NoError(t, err)
				require.Equal(t, id, rec.ID)
				require.Equal(t, "us-east-1", rec.Region)
				require.False(t, rec.CreatedAt.IsZero())
			})

			t.Run("GetByRegion returns ErrRecordNotFound for unknown region", func(t *testing.T) {
				_, err := s.GetByRegion(t.Context(), "eu-west-99")
				require.ErrorIs(t, err, store.ErrRecordNotFound)
			})

			t.Run("Add returns ErrRecordExists for duplicate id", func(t *testing.T) {
				id := testutil.RandomDID(t)
				require.NoError(t, s.Add(t.Context(), id, "ap-south-1"))
				err := s.Add(t.Context(), id, "ap-south-2")
				require.ErrorIs(t, err, store.ErrRecordExists)
			})
		})
	}
}
