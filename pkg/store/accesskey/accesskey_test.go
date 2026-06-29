package accesskey_test

import (
	"runtime"
	"testing"
	"time"

	"github.com/fil-forge/hilt/internal/testutil"
	"github.com/fil-forge/hilt/pkg/store"
	"github.com/fil-forge/hilt/pkg/store/accesskey"
	accesskeymemory "github.com/fil-forge/hilt/pkg/store/accesskey/memory"
	accesskeypostgres "github.com/fil-forge/hilt/pkg/store/accesskey/postgres"
	"github.com/fil-forge/ucantone/did"
	"github.com/stretchr/testify/require"
)

type StoreKind string

const (
	Memory   StoreKind = "memory"
	Postgres StoreKind = "postgres"
)

var storeKinds = []StoreKind{Memory, Postgres}

func makeStore(t *testing.T, k StoreKind) accesskey.Store {
	switch k {
	case Memory:
		return accesskeymemory.New()
	case Postgres:
		return createPostgresStore(t)
	}
	panic("unknown store kind")
}

func createPostgresStore(t *testing.T) accesskey.Store {
	if testutil.IsRunningInCI(t) && runtime.GOOS == "linux" {
		if !testutil.IsDockerAvailable(t) {
			t.Fatalf("docker is expected in CI linux testing environments, but wasn't found")
		}
	}
	if !testutil.IsDockerAvailable(t) {
		t.SkipNow()
	}
	pool := testutil.CreatePostgres(t)
	return accesskeypostgres.New(pool)
}

func TestAccessKeyStore(t *testing.T) {
	for _, k := range storeKinds {
		t.Run(string(k), func(t *testing.T) {
			s := makeStore(t, k)

			t.Run("adds and retrieves an access key with buckets and permissions", func(t *testing.T) {
				id := testutil.RandomDID(t)
				tenant := testutil.RandomDID(t)
				buckets := []did.DID{testutil.RandomDID(t), testutil.RandomDID(t)}
				perms := []string{"s3:GetObject", "s3:PutObject"}
				require.NoError(t, s.Add(t.Context(), id, tenant, "ci-key", buckets, perms, nil))

				rec, err := s.Get(t.Context(), id)
				require.NoError(t, err)
				require.Equal(t, id, rec.ID)
				require.Equal(t, tenant, rec.Tenant)
				require.Equal(t, "ci-key", rec.Name)
				require.Equal(t, buckets, rec.Buckets)
				require.Equal(t, perms, rec.Permissions)
				require.Nil(t, rec.ExpiresAt)
				require.False(t, rec.CreatedAt.IsZero())
			})

			t.Run("persists an expiry that round-trips", func(t *testing.T) {
				id := testutil.RandomDID(t)
				expires := time.Date(2027, 1, 2, 3, 4, 5, 0, time.UTC)
				require.NoError(t, s.Add(t.Context(), id, testutil.RandomDID(t), "exp", nil, []string{"s3:GetObject"}, &expires))

				rec, err := s.Get(t.Context(), id)
				require.NoError(t, err)
				require.NotNil(t, rec.ExpiresAt)
				require.True(t, expires.Equal(*rec.ExpiresAt))
			})

			t.Run("adds an access key with empty buckets (all-buckets)", func(t *testing.T) {
				id := testutil.RandomDID(t)
				perms := []string{"s3:ListAllMyBuckets"}
				require.NoError(t, s.Add(t.Context(), id, testutil.RandomDID(t), "all", nil, perms, nil))

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
				require.NoError(t, s.Add(t.Context(), id, testutil.RandomDID(t), "dup", nil, []string{"s3:GetObject"}, nil))
				err := s.Add(t.Context(), id, testutil.RandomDID(t), "dup", nil, []string{"s3:GetObject"}, nil)
				require.ErrorIs(t, err, store.ErrRecordExists)
			})

			t.Run("ListByTenant isolates by tenant", func(t *testing.T) {
				tenant := testutil.RandomDID(t)
				other := testutil.RandomDID(t)
				for range 3 {
					require.NoError(t, s.Add(t.Context(), testutil.RandomDID(t), tenant, "k", nil, []string{"s3:GetObject"}, nil))
				}
				require.NoError(t, s.Add(t.Context(), testutil.RandomDID(t), other, "k", nil, []string{"s3:GetObject"}, nil))

				recs, err := s.ListByTenant(t.Context(), tenant)
				require.NoError(t, err)
				require.Len(t, recs, 3)
				for _, r := range recs {
					require.Equal(t, tenant, r.Tenant)
				}
			})

			t.Run("Delete removes an access key and is idempotent", func(t *testing.T) {
				id := testutil.RandomDID(t)
				require.NoError(t, s.Add(t.Context(), id, testutil.RandomDID(t), "del", nil, []string{"s3:GetObject"}, nil))

				require.NoError(t, s.Delete(t.Context(), id))
				_, err := s.Get(t.Context(), id)
				require.ErrorIs(t, err, store.ErrRecordNotFound)

				require.NoError(t, s.Delete(t.Context(), id))
			})
		})
	}
}
