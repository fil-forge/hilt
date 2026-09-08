package provider_test

import (
	"runtime"
	"testing"

	htestutil "github.com/fil-forge/hilt/internal/testutil"
	"github.com/fil-forge/hilt/pkg/store"
	"github.com/fil-forge/hilt/pkg/store/provider"
	providermemory "github.com/fil-forge/hilt/pkg/store/provider/memory"
	providerpostgres "github.com/fil-forge/hilt/pkg/store/provider/postgres"
	"github.com/fil-forge/libforge/testutil"
	"github.com/fil-forge/ucantone/did"
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
	if htestutil.IsRunningInCI(t) && runtime.GOOS == "linux" {
		if !htestutil.IsDockerAvailable(t) {
			t.Fatalf("docker is expected in CI linux testing environments, but wasn't found")
		}
	}
	if !htestutil.IsDockerAvailable(t) {
		t.SkipNow()
	}
	pool := htestutil.CreatePostgres(t)
	return providerpostgres.New(pool)
}

func TestProviderStore(t *testing.T) {
	for _, k := range storeKinds {
		t.Run(string(k), func(t *testing.T) {
			s := makeStore(t, k)

			t.Run("adds and retrieves a provider by region", func(t *testing.T) {
				id, policy := testutil.RandomDID(t), testutil.RandomDID(t)
				require.NoError(t, s.Add(t.Context(), id, "us-east-1", &policy))

				rec, err := s.GetByRegion(t.Context(), "us-east-1")
				require.NoError(t, err)
				require.Equal(t, id, rec.ID)
				require.Equal(t, "us-east-1", rec.Region)
				require.NotNil(t, rec.Policy)
				require.Equal(t, policy, *rec.Policy)
				require.False(t, rec.CreatedAt.IsZero())
			})

			t.Run("retrieves a provider by ID", func(t *testing.T) {
				id, policy := testutil.RandomDID(t), testutil.RandomDID(t)
				require.NoError(t, s.Add(t.Context(), id, "eu-central-1", &policy))

				rec, err := s.Get(t.Context(), id)
				require.NoError(t, err)
				require.Equal(t, id, rec.ID)
				require.Equal(t, "eu-central-1", rec.Region)
				require.NotNil(t, rec.Policy)
				require.Equal(t, policy, *rec.Policy)
			})

			t.Run("Get returns ErrRecordNotFound for unknown provider", func(t *testing.T) {
				_, err := s.Get(t.Context(), testutil.RandomDID(t))
				require.ErrorIs(t, err, store.ErrRecordNotFound)
			})

			t.Run("stores a provider without a policy", func(t *testing.T) {
				id := testutil.RandomDID(t)
				require.NoError(t, s.Add(t.Context(), id, "us-west-2", nil))

				rec, err := s.Get(t.Context(), id)
				require.NoError(t, err)
				require.Nil(t, rec.Policy)
			})

			t.Run("sets the policy of a provider", func(t *testing.T) {
				id, policy := testutil.RandomDID(t), testutil.RandomDID(t)
				require.NoError(t, s.Add(t.Context(), id, "sa-east-1", nil))

				require.NoError(t, s.SetPolicy(t.Context(), id, policy))

				rec, err := s.Get(t.Context(), id)
				require.NoError(t, err)
				require.NotNil(t, rec.Policy)
				require.Equal(t, policy, *rec.Policy)
				require.False(t, rec.UpdatedAt.IsZero())
			})

			t.Run("SetPolicy returns ErrRecordNotFound for unknown provider", func(t *testing.T) {
				err := s.SetPolicy(t.Context(), testutil.RandomDID(t), testutil.RandomDID(t))
				require.ErrorIs(t, err, store.ErrRecordNotFound)
			})

			t.Run("SetPolicy returns ErrInvalidArgument for undef policy", func(t *testing.T) {
				id := testutil.RandomDID(t)
				require.NoError(t, s.Add(t.Context(), id, "af-south-1", nil))
				err := s.SetPolicy(t.Context(), id, did.Undef)
				require.ErrorIs(t, err, store.ErrInvalidArgument)
			})

			t.Run("GetByRegion returns ErrRecordNotFound for unknown region", func(t *testing.T) {
				_, err := s.GetByRegion(t.Context(), "eu-west-99")
				require.ErrorIs(t, err, store.ErrRecordNotFound)
			})

			t.Run("Add returns ErrInvalidArgument for undef provider ID", func(t *testing.T) {
				err := s.Add(t.Context(), did.Undef, "us-west-1", nil)
				require.ErrorIs(t, err, store.ErrInvalidArgument)
			})

			t.Run("Add returns ErrInvalidArgument for empty region", func(t *testing.T) {
				err := s.Add(t.Context(), testutil.RandomDID(t), "", nil)
				require.ErrorIs(t, err, store.ErrInvalidArgument)
			})

			t.Run("Add returns ErrRecordExists for duplicate id", func(t *testing.T) {
				id := testutil.RandomDID(t)
				require.NoError(t, s.Add(t.Context(), id, "ap-south-1", nil))
				err := s.Add(t.Context(), id, "ap-south-2", nil)
				require.ErrorIs(t, err, store.ErrRecordExists)
			})
		})
	}
}
