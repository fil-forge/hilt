package wrapkey_test

import (
	"runtime"
	"testing"

	"github.com/fil-forge/hilt/internal/testutil"
	"github.com/fil-forge/hilt/pkg/store"
	"github.com/fil-forge/hilt/pkg/store/wrapkey"
	wrapkeymemory "github.com/fil-forge/hilt/pkg/store/wrapkey/memory"
	wrapkeypostgres "github.com/fil-forge/hilt/pkg/store/wrapkey/postgres"
	"github.com/fil-forge/ucantone/did"
	"github.com/stretchr/testify/require"
)

type StoreKind string

const (
	Memory   StoreKind = "memory"
	Postgres StoreKind = "postgres"
)

var storeKinds = []StoreKind{Memory, Postgres}

func makeStore(t *testing.T, k StoreKind) wrapkey.Store {
	switch k {
	case Memory:
		return wrapkeymemory.New()
	case Postgres:
		return createPostgresStore(t)
	}
	panic("unknown store kind")
}

func createPostgresStore(t *testing.T) wrapkey.Store {
	if testutil.IsRunningInCI(t) && runtime.GOOS == "linux" {
		if !testutil.IsDockerAvailable(t) {
			t.Fatalf("docker is expected in CI linux testing environments, but wasn't found")
		}
	}
	if !testutil.IsDockerAvailable(t) {
		t.SkipNow()
	}
	pool := testutil.CreatePostgres(t)
	return wrapkeypostgres.New(pool)
}

// activeRecord builds an active v1 wrap-key record for a fresh tenant.
func activeRecord(t *testing.T) wrapkey.Record {
	t.Helper()
	tenant := testutil.RandomDID(t)
	return wrapkey.Record{
		Tenant:    tenant,
		Version:   1,
		KID:       wrapkey.KID(tenant, 1),
		PublicKey: "z6LSdummyPublicKey",
		Status:    wrapkey.Active,
		Epoch:     0,
		VaultKey:  wrapkey.VaultKey(tenant, 1),
	}
}

func TestWrapKeyStore(t *testing.T) {
	for _, k := range storeKinds {
		t.Run(string(k), func(t *testing.T) {
			s := makeStore(t, k)

			t.Run("adds and retrieves an active key", func(t *testing.T) {
				rec := activeRecord(t)
				require.NoError(t, s.Add(t.Context(), rec))

				got, err := s.GetActive(t.Context(), rec.Tenant)
				require.NoError(t, err)
				require.Equal(t, rec.Tenant, got.Tenant)
				require.Equal(t, 1, got.Version)
				require.Equal(t, rec.KID, got.KID)
				require.Equal(t, rec.PublicKey, got.PublicKey)
				require.Equal(t, wrapkey.Active, got.Status)
				require.Equal(t, rec.VaultKey, got.VaultKey)
				require.False(t, got.CreatedAt.IsZero())
				require.True(t, got.ArchivedAt.IsZero())
			})

			t.Run("Get returns a specific version", func(t *testing.T) {
				rec := activeRecord(t)
				require.NoError(t, s.Add(t.Context(), rec))

				got, err := s.Get(t.Context(), rec.Tenant, 1)
				require.NoError(t, err)
				require.Equal(t, rec.KID, got.KID)
			})

			t.Run("GetActive returns ErrRecordNotFound for unknown tenant", func(t *testing.T) {
				_, err := s.GetActive(t.Context(), testutil.RandomDID(t))
				require.ErrorIs(t, err, store.ErrRecordNotFound)
			})

			t.Run("Get returns ErrRecordNotFound for unknown version", func(t *testing.T) {
				_, err := s.Get(t.Context(), testutil.RandomDID(t), 7)
				require.ErrorIs(t, err, store.ErrRecordNotFound)
			})

			t.Run("Add rejects a duplicate (tenant, version)", func(t *testing.T) {
				rec := activeRecord(t)
				require.NoError(t, s.Add(t.Context(), rec))
				err := s.Add(t.Context(), rec)
				require.ErrorIs(t, err, store.ErrRecordExists)
			})

			t.Run("Add rejects a second active key for a tenant", func(t *testing.T) {
				rec := activeRecord(t)
				require.NoError(t, s.Add(t.Context(), rec))

				second := rec
				second.Version = 2
				second.KID = wrapkey.KID(rec.Tenant, 2)
				second.VaultKey = wrapkey.VaultKey(rec.Tenant, 2)
				err := s.Add(t.Context(), second)
				require.ErrorIs(t, err, store.ErrRecordExists)
			})

			t.Run("archive then add a new active version (rotation)", func(t *testing.T) {
				rec := activeRecord(t)
				tenant := rec.Tenant
				require.NoError(t, s.Add(t.Context(), rec))

				// Archive v1, then a new active v2 can be added.
				require.NoError(t, s.Archive(t.Context(), tenant, 1))

				v1, err := s.Get(t.Context(), tenant, 1)
				require.NoError(t, err)
				require.Equal(t, wrapkey.Archived, v1.Status)
				require.False(t, v1.ArchivedAt.IsZero())

				v2 := wrapkey.Record{
					Tenant:    tenant,
					Version:   2,
					KID:       wrapkey.KID(tenant, 2),
					PublicKey: "z6LSanotherPublicKey",
					Status:    wrapkey.Active,
					VaultKey:  wrapkey.VaultKey(tenant, 2),
				}
				require.NoError(t, s.Add(t.Context(), v2))

				active, err := s.GetActive(t.Context(), tenant)
				require.NoError(t, err)
				require.Equal(t, 2, active.Version)

				// Both versions are retained (archive-don't-destroy), newest first.
				all, err := s.List(t.Context(), tenant)
				require.NoError(t, err)
				require.Len(t, all, 2)
				require.Equal(t, 2, all[0].Version)
				require.Equal(t, 1, all[1].Version)
			})

			t.Run("Archive returns ErrRecordNotFound for unknown version", func(t *testing.T) {
				err := s.Archive(t.Context(), testutil.RandomDID(t), 1)
				require.ErrorIs(t, err, store.ErrRecordNotFound)
			})
		})
	}
}

func TestHelpers(t *testing.T) {
	tenant, err := did.Parse("did:plc:abc123")
	require.NoError(t, err)

	require.Equal(t, "wrap-1", wrapkey.Fragment(1))
	require.Equal(t, "wrap-2", wrapkey.Fragment(2))
	require.Equal(t, "did:plc:abc123#wrap-1", wrapkey.KID(tenant, 1))
	require.Equal(t, "/tenant/did:plc:abc123/wrap/1", wrapkey.VaultKey(tenant, 1))
}
