package accesskey_test

import (
	"context"
	"fmt"
	"testing"
	"time"

	htestutil "github.com/fil-forge/hilt/internal/testutil"
	"github.com/fil-forge/hilt/pkg/store"
	"github.com/fil-forge/hilt/pkg/store/accesskey"
	accesskeymemory "github.com/fil-forge/hilt/pkg/store/accesskey/memory"
	accesskeypostgres "github.com/fil-forge/hilt/pkg/store/accesskey/postgres"
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

// seeder ensures the referenced rows exist so the access_key foreign keys are
// satisfied: the parent tenant (and its provider), and any principals a key is
// bound to. It is a no-op for the memory store, which does not enforce
// referential integrity.
type seeder struct {
	tenant    func(t *testing.T, tenantID did.DID)
	principal func(t *testing.T, tenantID did.DID, externalID string)
}

func makeStore(t *testing.T, k StoreKind) (accesskey.Store, seeder) {
	switch k {
	case Memory:
		return accesskeymemory.New(), seeder{
			tenant:    func(*testing.T, did.DID) {},
			principal: func(*testing.T, did.DID, string) {},
		}
	case Postgres:
		pool := htestutil.PostgresOrSkip(t)
		return accesskeypostgres.New(pool), postgresSeeder(pool)
	}
	panic("unknown store kind")
}

func postgresSeeder(pool *pgxpool.Pool) seeder {
	providers := providerpostgres.New(pool)
	tenants := tenantpostgres.New(pool)
	principals := principalpostgres.New(pool)
	return seeder{
		tenant: func(t *testing.T, tenantID did.DID) {
			providerID := testutil.RandomDID(t)
			require.NoError(t, providers.Add(t.Context(), providerID, tenantID.String(), nil))
			require.NoError(t, tenants.Add(t.Context(), tenantID, "ext-"+tenantID.String(), providerID, tenant.Active))
		},
		principal: func(t *testing.T, tenantID did.DID, externalID string) {
			require.NoError(t, principals.Add(t.Context(), tenantID, externalID))
		},
	}
}

// service builds the input of a service key with the given permissions and
// bucket scope.
func service(id, tenantID did.DID, name string, buckets []did.DID, perms ...string) accesskey.Input {
	return accesskey.Input{ID: id, Tenant: tenantID, Name: name, Buckets: buckets, Permissions: perms}
}

// bound builds the input of a key bound to a principal.
func bound(id, tenantID did.DID, principal, name string) accesskey.Input {
	return accesskey.Input{ID: id, Tenant: tenantID, Name: name, Principal: &principal}
}

func ids(recs []accesskey.Record) []did.DID {
	out := make([]did.DID, 0, len(recs))
	for _, r := range recs {
		out = append(out, r.ID)
	}
	return out
}

func TestAccessKeyStore(t *testing.T) {
	for _, k := range storeKinds {
		t.Run(string(k), func(t *testing.T) {
			s, seed := makeStore(t, k)

			t.Run("adds and retrieves a service key with buckets and permissions", func(t *testing.T) {
				id := testutil.RandomDID(t)
				tenantID := testutil.RandomDID(t)
				seed.tenant(t, tenantID)
				buckets := []did.DID{testutil.RandomDID(t), testutil.RandomDID(t)}
				require.NoError(t, s.Add(t.Context(), service(id, tenantID, "ci-key", buckets, "s3:GetObject", "s3:PutObject")))

				rec, err := s.Get(t.Context(), id)
				require.NoError(t, err)
				require.Equal(t, id, rec.ID)
				require.Equal(t, tenantID, rec.Tenant)
				require.Equal(t, "ci-key", rec.Name)
				require.Equal(t, buckets, rec.Buckets)
				require.Equal(t, []string{"s3:GetObject", "s3:PutObject"}, rec.Permissions)
				require.Nil(t, rec.Principal)
				require.Nil(t, rec.ExpiresAt)
				require.False(t, rec.CreatedAt.IsZero())
			})

			t.Run("adds a service key with empty buckets (all-buckets)", func(t *testing.T) {
				id := testutil.RandomDID(t)
				tenantID := testutil.RandomDID(t)
				seed.tenant(t, tenantID)
				require.NoError(t, s.Add(t.Context(), service(id, tenantID, "all", nil, "s3:ListAllMyBuckets")))

				rec, err := s.Get(t.Context(), id)
				require.NoError(t, err)
				require.Empty(t, rec.Buckets)
				require.Equal(t, []string{"s3:ListAllMyBuckets"}, rec.Permissions)
			})

			t.Run("adds and retrieves a principal-bound key with no permissions or buckets", func(t *testing.T) {
				id := testutil.RandomDID(t)
				tenantID := testutil.RandomDID(t)
				seed.tenant(t, tenantID)
				seed.principal(t, tenantID, "user-1")
				require.NoError(t, s.Add(t.Context(), bound(id, tenantID, "user-1", "laptop")))

				rec, err := s.Get(t.Context(), id)
				require.NoError(t, err)
				require.Equal(t, "laptop", rec.Name)
				require.NotNil(t, rec.Principal)
				require.Equal(t, "user-1", *rec.Principal)
				require.Nil(t, rec.Permissions, "stored as NULL: the key holds no authority of its own")
				require.Nil(t, rec.Buckets)
			})

			t.Run("Get honours the share lock option", func(t *testing.T) {
				id := testutil.RandomDID(t)
				tenantID := testutil.RandomDID(t)
				seed.tenant(t, tenantID)
				require.NoError(t, s.Add(t.Context(), service(id, tenantID, "locked", nil, "s3:GetObject")))

				rec, err := s.Get(t.Context(), id, store.LockShare)
				require.NoError(t, err)
				require.Equal(t, id, rec.ID)

				_, err = s.Get(t.Context(), testutil.RandomDID(t), store.LockShare)
				require.ErrorIs(t, err, store.ErrRecordNotFound)
			})

			t.Run("persists an expiry that round-trips", func(t *testing.T) {
				id := testutil.RandomDID(t)
				tenantID := testutil.RandomDID(t)
				seed.tenant(t, tenantID)
				expires := time.Date(2027, 1, 2, 3, 4, 5, 0, time.UTC)
				in := service(id, tenantID, "exp", nil, "s3:GetObject")
				in.ExpiresAt = &expires
				require.NoError(t, s.Add(t.Context(), in))

				rec, err := s.Get(t.Context(), id)
				require.NoError(t, err)
				require.NotNil(t, rec.ExpiresAt)
				require.True(t, expires.Equal(*rec.ExpiresAt))
			})

			t.Run("Get returns ErrRecordNotFound for unknown id", func(t *testing.T) {
				_, err := s.Get(t.Context(), testutil.RandomDID(t))
				require.ErrorIs(t, err, store.ErrRecordNotFound)
			})

			t.Run("Add returns ErrRecordExists for duplicate id", func(t *testing.T) {
				id := testutil.RandomDID(t)
				tenantID := testutil.RandomDID(t)
				seed.tenant(t, tenantID)
				require.NoError(t, s.Add(t.Context(), service(id, tenantID, "dup", nil, "s3:GetObject")))
				err := s.Add(t.Context(), service(id, tenantID, "dup-2", nil, "s3:GetObject"))
				require.ErrorIs(t, err, store.ErrRecordExists)
			})

			t.Run("a service key's name is unique within the tenant", func(t *testing.T) {
				tenantID := testutil.RandomDID(t)
				otherTenant := testutil.RandomDID(t)
				seed.tenant(t, tenantID)
				seed.tenant(t, otherTenant)
				require.NoError(t, s.Add(t.Context(), service(testutil.RandomDID(t), tenantID, "name-dup", nil, "s3:GetObject")))
				// Same tenant + name but a different id must be rejected.
				err := s.Add(t.Context(), service(testutil.RandomDID(t), tenantID, "name-dup", nil, "s3:GetObject"))
				require.ErrorIs(t, err, store.ErrRecordExists)
				// The same name under a different tenant is allowed.
				require.NoError(t, s.Add(t.Context(), service(testutil.RandomDID(t), otherTenant, "name-dup", nil, "s3:GetObject")))
			})

			t.Run("a principal-bound key's name is unique within its principal", func(t *testing.T) {
				tenantID := testutil.RandomDID(t)
				otherTenant := testutil.RandomDID(t)
				seed.tenant(t, tenantID)
				seed.tenant(t, otherTenant)
				seed.principal(t, tenantID, "alice")
				seed.principal(t, tenantID, "bob")
				seed.principal(t, otherTenant, "alice")
				require.NoError(t, s.Add(t.Context(), bound(testutil.RandomDID(t), tenantID, "alice", "laptop")))
				// The same principal cannot hold two keys of the name.
				err := s.Add(t.Context(), bound(testutil.RandomDID(t), tenantID, "alice", "laptop"))
				require.ErrorIs(t, err, store.ErrRecordExists)
				// Another principal of the tenant may hold the name.
				require.NoError(t, s.Add(t.Context(), bound(testutil.RandomDID(t), tenantID, "bob", "laptop")))
				// So may the same principal id under another tenant.
				require.NoError(t, s.Add(t.Context(), bound(testutil.RandomDID(t), otherTenant, "alice", "laptop")))
				// A service key of the tenant may hold the name too: the two
				// uniqueness rules are independent.
				require.NoError(t, s.Add(t.Context(), service(testutil.RandomDID(t), tenantID, "laptop", nil, "s3:GetObject")))
				require.NoError(t, s.Add(t.Context(), bound(testutil.RandomDID(t), tenantID, "alice", "ci-key")))
				require.NoError(t, s.Add(t.Context(), service(testutil.RandomDID(t), tenantID, "ci-key", nil, "s3:GetObject")))
			})

			t.Run("Add returns ErrInvalidArgument for an inconsistent input", func(t *testing.T) {
				tenantID := testutil.RandomDID(t)
				seed.tenant(t, tenantID)
				seed.principal(t, tenantID, "user-1")
				user := "user-1"
				empty := ""
				cases := map[string]accesskey.Input{
					"undef id":                         service(did.Undef, tenantID, "k", nil, "s3:GetObject"),
					"undef tenant":                     service(testutil.RandomDID(t), did.Undef, "k", nil, "s3:GetObject"),
					"empty name":                       service(testutil.RandomDID(t), tenantID, "", nil, "s3:GetObject"),
					"undef bucket DID":                 service(testutil.RandomDID(t), tenantID, "k", []did.DID{testutil.RandomDID(t), did.Undef}, "s3:GetObject"),
					"empty principal":                  {ID: testutil.RandomDID(t), Tenant: tenantID, Name: "k", Principal: &empty},
					"principal-bound with permissions": {ID: testutil.RandomDID(t), Tenant: tenantID, Name: "k", Principal: &user, Permissions: []string{"s3:GetObject"}},
					"principal-bound with buckets":     {ID: testutil.RandomDID(t), Tenant: tenantID, Name: "k", Principal: &user, Buckets: []did.DID{testutil.RandomDID(t)}},
				}
				for name, in := range cases {
					t.Run(name, func(t *testing.T) {
						require.ErrorIs(t, s.Add(t.Context(), in), store.ErrInvalidArgument)
					})
				}
			})

			t.Run("ListByTenant isolates by tenant and filters by principal", func(t *testing.T) {
				tenantID := testutil.RandomDID(t)
				other := testutil.RandomDID(t)
				seed.tenant(t, tenantID)
				seed.tenant(t, other)
				seed.principal(t, tenantID, "alice")
				seed.principal(t, tenantID, "bob")
				seed.principal(t, other, "alice")

				svc := testutil.RandomDID(t)
				require.NoError(t, s.Add(t.Context(), service(svc, tenantID, "svc", nil, "s3:GetObject")))
				var alice []did.DID
				for i := range 2 {
					id := testutil.RandomDID(t)
					alice = append(alice, id)
					require.NoError(t, s.Add(t.Context(), bound(id, tenantID, "alice", fmt.Sprintf("alice-%d", i))))
				}
				bob := testutil.RandomDID(t)
				require.NoError(t, s.Add(t.Context(), bound(bob, tenantID, "bob", "bob-0")))
				require.NoError(t, s.Add(t.Context(), bound(testutil.RandomDID(t), other, "alice", "alice-0")))
				require.NoError(t, s.Add(t.Context(), service(testutil.RandomDID(t), other, "svc", nil, "s3:GetObject")))

				all, err := s.ListByTenant(t.Context(), tenantID)
				require.NoError(t, err)
				require.ElementsMatch(t, append(append([]did.DID{svc}, alice...), bob), ids(all))
				for _, r := range all {
					require.Equal(t, tenantID, r.Tenant)
				}

				alices, err := s.ListByTenant(t.Context(), tenantID, accesskey.WithPrincipal("alice"))
				require.NoError(t, err)
				require.ElementsMatch(t, alice, ids(alices))

				none, err := s.ListByTenant(t.Context(), tenantID, accesskey.WithPrincipal("nobody"))
				require.NoError(t, err)
				require.Empty(t, none)
			})

			t.Run("Delete removes the row and is idempotent", func(t *testing.T) {
				id := testutil.RandomDID(t)
				tenantID := testutil.RandomDID(t)
				seed.tenant(t, tenantID)
				require.NoError(t, s.Add(t.Context(), service(id, tenantID, "del", nil, "s3:GetObject")))

				require.NoError(t, s.Delete(t.Context(), id))
				_, err := s.Get(t.Context(), id)
				require.ErrorIs(t, err, store.ErrRecordNotFound)
				require.NoError(t, s.Delete(t.Context(), id), "deleting an absent row is a no-op")
			})
		})
	}
}

// TestAccessKeyStorePostgresIntegrity pins what only the Postgres schema
// enforces: a principal-bound key must name a principal of its tenant.
func TestAccessKeyStorePostgresIntegrity(t *testing.T) {
	pool := htestutil.PostgresOrSkip(t)
	s := accesskeypostgres.New(pool)
	seed := postgresSeeder(pool)

	t.Run("a key bound to an unknown principal is rejected", func(t *testing.T) {
		tenantID := testutil.RandomDID(t)
		seed.tenant(t, tenantID)
		err := s.Add(t.Context(), bound(testutil.RandomDID(t), tenantID, "ghost", "k"))
		require.ErrorIs(t, err, store.ErrInvalidArgument)
	})

	t.Run("a key bound to another tenant's principal is rejected", func(t *testing.T) {
		tenantID, other := testutil.RandomDID(t), testutil.RandomDID(t)
		seed.tenant(t, tenantID)
		seed.tenant(t, other)
		seed.principal(t, other, "user-1")
		err := s.Add(t.Context(), bound(testutil.RandomDID(t), tenantID, "user-1", "k"))
		require.ErrorIs(t, err, store.ErrInvalidArgument)
	})
}

// TestAccessKeyStorePostgresLocking pins the locking contract the authorizer
// relies on: a share-locked Get waits for a transaction that holds the row FOR
// UPDATE, and is answered once that transaction ends. Postgres only: the
// memory store cannot hold a row across calls.
func TestAccessKeyStorePostgresLocking(t *testing.T) {
	pool := htestutil.PostgresOrSkip(t)
	s := accesskeypostgres.New(pool)
	seed := postgresSeeder(pool)

	id := testutil.RandomDID(t)
	tenantID := testutil.RandomDID(t)
	seed.tenant(t, tenantID)
	require.NoError(t, s.Add(t.Context(), service(id, tenantID, "k", nil, "s3:GetObject")))

	tx, err := pool.Begin(t.Context())
	require.NoError(t, err)
	defer tx.Rollback(t.Context())

	var rec accesskey.Record
	committed, got := htestutil.RequireWaitsForWriter(t,
		func(entered chan<- struct{}, release <-chan struct{}) error {
			var found bool
			if err := tx.QueryRow(t.Context(), `SELECT TRUE FROM access_key WHERE id = $1 FOR UPDATE`, id.String()).Scan(&found); err != nil {
				return err
			}
			// An unlocked read is answered from the snapshot and never waits.
			if _, err := s.Get(t.Context(), id); err != nil {
				return fmt.Errorf("unlocked Get during the hold: %w", err)
			}
			close(entered)
			<-release
			return tx.Commit(t.Context())
		},
		func() error {
			var err error
			rec, err = s.Get(context.Background(), id, store.LockShare)
			return err
		})
	require.NoError(t, committed)
	require.NoError(t, got)
	require.Equal(t, id, rec.ID)
}
