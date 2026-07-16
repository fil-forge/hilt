package bucket_test

import (
	"context"
	"fmt"
	"runtime"
	"strings"
	"testing"

	"github.com/fil-forge/hilt/internal/testutil"
	"github.com/fil-forge/hilt/pkg/store"
	"github.com/fil-forge/hilt/pkg/store/bucket"
	bucketmemory "github.com/fil-forge/hilt/pkg/store/bucket/memory"
	bucketpostgres "github.com/fil-forge/hilt/pkg/store/bucket/postgres"
	providerpostgres "github.com/fil-forge/hilt/pkg/store/provider/postgres"
	"github.com/fil-forge/hilt/pkg/store/tenant"
	tenantpostgres "github.com/fil-forge/hilt/pkg/store/tenant/postgres"
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
// bucket.tenant_id foreign key is satisfied. It is a no-op for the memory store,
// which does not enforce referential integrity.
type seedFunc func(t *testing.T, tenantID did.DID)

func makeStore(t *testing.T, k StoreKind) (bucket.Store, seedFunc) {
	switch k {
	case Memory:
		return bucketmemory.New(), func(*testing.T, did.DID) {}
	case Postgres:
		pool := createPostgresPool(t)
		providers := providerpostgres.New(pool)
		tenants := tenantpostgres.New(pool)
		seed := func(t *testing.T, tenantID did.DID) {
			providerID := testutil.RandomDID(t)
			require.NoError(t, providers.Add(t.Context(), providerID, tenantID.String()))
			require.NoError(t, tenants.Add(t.Context(), tenantID, "ext-"+tenantID.String(), providerID, tenant.Active))
		}
		return bucketpostgres.New(pool), seed
	}
	panic("unknown store kind")
}

func createPostgresPool(t *testing.T) *pgxpool.Pool {
	if testutil.IsRunningInCI(t) && runtime.GOOS == "linux" {
		if !testutil.IsDockerAvailable(t) {
			t.Fatalf("docker is expected in CI linux testing environments, but wasn't found")
		}
	}
	if !testutil.IsDockerAvailable(t) {
		t.SkipNow()
	}
	return testutil.CreatePostgres(t)
}

func TestBucketStore(t *testing.T) {
	for _, k := range storeKinds {
		t.Run(string(k), func(t *testing.T) {
			s, seed := makeStore(t, k)

			t.Run("adds and retrieves a bucket by name", func(t *testing.T) {
				id := testutil.RandomDID(t)
				tenantID := testutil.RandomDID(t)
				seed(t, tenantID)
				require.NoError(t, s.Add(t.Context(), id, tenantID, "photos"))

				rec, err := s.GetByName(t.Context(), "photos")
				require.NoError(t, err)
				require.Equal(t, id, rec.ID)
				require.Equal(t, tenantID, rec.Tenant)
				require.Equal(t, "photos", rec.Name)
				require.False(t, rec.CreatedAt.IsZero())
			})

			t.Run("GetByName returns ErrRecordNotFound for unknown name", func(t *testing.T) {
				_, err := s.GetByName(t.Context(), "nope")
				require.ErrorIs(t, err, store.ErrRecordNotFound)
			})

			t.Run("Add returns ErrRecordExists for duplicate id", func(t *testing.T) {
				id := testutil.RandomDID(t)
				tenantID := testutil.RandomDID(t)
				seed(t, tenantID)
				require.NoError(t, s.Add(t.Context(), id, tenantID, "dup-id-a"))
				err := s.Add(t.Context(), id, tenantID, "dup-id-b")
				require.ErrorIs(t, err, store.ErrRecordExists)
			})

			t.Run("Add returns ErrRecordExists for duplicate name", func(t *testing.T) {
				tenantID := testutil.RandomDID(t)
				seed(t, tenantID)
				require.NoError(t, s.Add(t.Context(), testutil.RandomDID(t), tenantID, "shared-name"))
				err := s.Add(t.Context(), testutil.RandomDID(t), tenantID, "shared-name")
				require.ErrorIs(t, err, store.ErrRecordExists)
			})

			t.Run("Add returns ErrInvalidArgument for undef bucket ID", func(t *testing.T) {
				tenantID := testutil.RandomDID(t)
				seed(t, tenantID)
				err := s.Add(t.Context(), did.Undef, tenantID, "undef-id")
				require.ErrorIs(t, err, store.ErrInvalidArgument)
			})

			t.Run("Add returns ErrInvalidArgument for undef tenant", func(t *testing.T) {
				err := s.Add(t.Context(), testutil.RandomDID(t), did.Undef, "undef-tenant")
				require.ErrorIs(t, err, store.ErrInvalidArgument)
			})

			t.Run("Add returns ErrInvalidArgument for invalid names", func(t *testing.T) {
				tenantID := testutil.RandomDID(t)
				seed(t, tenantID)
				invalid := []string{
					"",                      // empty
					"ab",                    // too short
					strings.Repeat("a", 64), // too long
					"Invalid-Name",          // uppercase
					"under_score",           // disallowed character
					"-leading-hyphen",       // must start with letter or digit
					"trailing-hyphen-",      // must end with letter or digit
				}
				for _, name := range invalid {
					err := s.Add(t.Context(), testutil.RandomDID(t), tenantID, name)
					require.ErrorIs(t, err, store.ErrInvalidArgument, "name %q", name)
				}
			})

			t.Run("ListByTenant isolates and paginates by tenant in name order", func(t *testing.T) {
				tenantID := testutil.RandomDID(t)
				other := testutil.RandomDID(t)
				seed(t, tenantID)
				seed(t, other)
				for i := range 5 {
					require.NoError(t, s.Add(t.Context(), testutil.RandomDID(t), tenantID, fmt.Sprintf("lbt-%d", i)))
				}
				require.NoError(t, s.Add(t.Context(), testutil.RandomDID(t), other, "lbt-other"))

				// A truncated page's cursor is the name of its last record.
				page, err := s.ListByTenant(t.Context(), tenantID, bucket.WithLimit(2))
				require.NoError(t, err)
				require.Len(t, page.Results, 2)
				require.NotNil(t, page.Cursor)
				require.Equal(t, "lbt-1", *page.Cursor)

				all, err := store.Collect(t.Context(), func(ctx context.Context, opts store.PaginationConfig) (store.Page[bucket.Record], error) {
					listOpts := []bucket.ListOption{bucket.WithLimit(2)}
					if opts.Cursor != nil {
						listOpts = append(listOpts, bucket.WithCursor(*opts.Cursor))
					}
					return s.ListByTenant(ctx, tenantID, listOpts...)
				})
				require.NoError(t, err)
				names := make([]string, 0, len(all))
				for _, b := range all {
					require.Equal(t, tenantID, b.Tenant)
					names = append(names, b.Name)
				}
				require.Equal(t, []string{"lbt-0", "lbt-1", "lbt-2", "lbt-3", "lbt-4"}, names)
			})

			t.Run("ListByTenant filters by prefix and paginates within it", func(t *testing.T) {
				tenantID := testutil.RandomDID(t)
				seed(t, tenantID)
				for _, name := range []string{"pfx-app-a", "pfx-app-b", "pfx-app-c", "pfx-web-a"} {
					require.NoError(t, s.Add(t.Context(), testutil.RandomDID(t), tenantID, name))
				}

				page, err := s.ListByTenant(t.Context(), tenantID, bucket.WithPrefix("pfx-app-"), bucket.WithLimit(2))
				require.NoError(t, err)
				require.Len(t, page.Results, 2)
				require.Equal(t, "pfx-app-a", page.Results[0].Name)
				require.Equal(t, "pfx-app-b", page.Results[1].Name)
				require.NotNil(t, page.Cursor)

				page, err = s.ListByTenant(t.Context(), tenantID, bucket.WithPrefix("pfx-app-"), bucket.WithLimit(2), bucket.WithCursor(*page.Cursor))
				require.NoError(t, err)
				require.Len(t, page.Results, 1)
				require.Equal(t, "pfx-app-c", page.Results[0].Name)
				require.Nil(t, page.Cursor)
			})

			t.Run("ListByTenant cursor resumes strictly after a non-existent name", func(t *testing.T) {
				tenantID := testutil.RandomDID(t)
				seed(t, tenantID)
				for _, name := range []string{"nec-a", "nec-c", "nec-e"} {
					require.NoError(t, s.Add(t.Context(), testutil.RandomDID(t), tenantID, name))
				}

				page, err := s.ListByTenant(t.Context(), tenantID, bucket.WithCursor("nec-b"))
				require.NoError(t, err)
				require.Len(t, page.Results, 2)
				require.Equal(t, "nec-c", page.Results[0].Name)
				require.Equal(t, "nec-e", page.Results[1].Name)
			})

			t.Run("ListByTenant prefix matches literally, not as a pattern", func(t *testing.T) {
				tenantID := testutil.RandomDID(t)
				seed(t, tenantID)
				require.NoError(t, s.Add(t.Context(), testutil.RandomDID(t), tenantID, "wild-a"))
				require.NoError(t, s.Add(t.Context(), testutil.RandomDID(t), tenantID, "wildxa"))

				// A LIKE-style implementation would treat _ / % as wildcards and
				// match both buckets; a literal match finds neither.
				for _, prefix := range []string{"wild_", "wild%"} {
					page, err := s.ListByTenant(t.Context(), tenantID, bucket.WithPrefix(prefix))
					require.NoError(t, err)
					require.Empty(t, page.Results, "prefix %q", prefix)
				}
			})

			t.Run("ListByTenant filters by IDs", func(t *testing.T) {
				tenantID := testutil.RandomDID(t)
				other := testutil.RandomDID(t)
				seed(t, tenantID)
				seed(t, other)
				want := []did.DID{testutil.RandomDID(t), testutil.RandomDID(t)}
				require.NoError(t, s.Add(t.Context(), want[0], tenantID, "fbid-a"))
				require.NoError(t, s.Add(t.Context(), want[1], tenantID, "fbid-b"))
				// Decoys: same tenant but not requested, and a different tenant.
				require.NoError(t, s.Add(t.Context(), testutil.RandomDID(t), tenantID, "fbid-c"))
				require.NoError(t, s.Add(t.Context(), testutil.RandomDID(t), other, "fbid-other"))

				page, err := s.ListByTenant(t.Context(), tenantID, bucket.WithIDs(want...))
				require.NoError(t, err)
				got := make([]did.DID, 0, len(page.Results))
				for _, b := range page.Results {
					require.Equal(t, tenantID, b.Tenant)
					got = append(got, b.ID)
				}
				require.ElementsMatch(t, want, got)
			})

			t.Run("ListByTenant filters by names", func(t *testing.T) {
				tenantID := testutil.RandomDID(t)
				other := testutil.RandomDID(t)
				seed(t, tenantID)
				seed(t, other)
				want := []did.DID{testutil.RandomDID(t), testutil.RandomDID(t)}
				require.NoError(t, s.Add(t.Context(), want[0], tenantID, "fbn-a"))
				require.NoError(t, s.Add(t.Context(), want[1], tenantID, "fbn-b"))
				// Decoys: same tenant but not requested, and a different tenant.
				require.NoError(t, s.Add(t.Context(), testutil.RandomDID(t), tenantID, "fbn-c"))
				require.NoError(t, s.Add(t.Context(), testutil.RandomDID(t), other, "fbn-other"))

				// "fbn-other" belongs to a different tenant, so it is excluded by the
				// tenant scope even though it is requested.
				page, err := s.ListByTenant(t.Context(), tenantID, bucket.WithNames("fbn-a", "fbn-b", "fbn-other"))
				require.NoError(t, err)
				got := make([]did.DID, 0, len(page.Results))
				for _, b := range page.Results {
					require.Equal(t, tenantID, b.Tenant)
					got = append(got, b.ID)
				}
				require.ElementsMatch(t, want, got)
			})

			t.Run("ListByTenant rejects IDs and Names together", func(t *testing.T) {
				_, err := s.ListByTenant(t.Context(), testutil.RandomDID(t),
					bucket.WithIDs(testutil.RandomDID(t)), bucket.WithNames("x"))
				require.ErrorIs(t, err, bucket.ErrConflictingFilters)
			})

			t.Run("Delete removes a bucket and is idempotent", func(t *testing.T) {
				id := testutil.RandomDID(t)
				tenantID := testutil.RandomDID(t)
				seed(t, tenantID)
				require.NoError(t, s.Add(t.Context(), id, tenantID, "to-delete"))

				require.NoError(t, s.Delete(t.Context(), id))
				_, err := s.GetByName(t.Context(), "to-delete")
				require.ErrorIs(t, err, store.ErrRecordNotFound)

				require.NoError(t, s.Delete(t.Context(), id))
			})
		})
	}
}
