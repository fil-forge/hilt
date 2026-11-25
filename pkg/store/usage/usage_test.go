package usage_test

import (
	"runtime"
	"testing"
	"time"

	"github.com/fil-forge/hilt/internal/testutil"
	"github.com/fil-forge/hilt/pkg/store"
	providerpostgres "github.com/fil-forge/hilt/pkg/store/provider/postgres"
	"github.com/fil-forge/hilt/pkg/store/tenant"
	tenantmemory "github.com/fil-forge/hilt/pkg/store/tenant/memory"
	tenantpostgres "github.com/fil-forge/hilt/pkg/store/tenant/postgres"
	"github.com/fil-forge/hilt/pkg/store/usage"
	usagememory "github.com/fil-forge/hilt/pkg/store/usage/memory"
	usagepostgres "github.com/fil-forge/hilt/pkg/store/usage/postgres"
	"github.com/fil-forge/ucantone/did"
	"github.com/stretchr/testify/require"
)

type StoreKind string

const (
	Memory   StoreKind = "memory"
	Postgres StoreKind = "postgres"
)

var storeKinds = []StoreKind{Memory, Postgres}

// fixture is the store under test and what a test needs to satisfy the
// Postgres backend's foreign keys. The memory store enforces none, so its
// provider seeder does nothing.
type fixture struct {
	store        usage.Store
	seedTenant   func(t *testing.T) did.DID
	seedProvider func(t *testing.T) did.DID
	// dropTenant deletes a tenant.
	dropTenant func(t *testing.T, id did.DID)
}

func makeStore(t *testing.T, k StoreKind) fixture {
	switch k {
	case Memory:
		random := func(t *testing.T) did.DID { return testutil.RandomDID(t) }
		counts := usagememory.New()
		tenants := tenantmemory.New(tenantmemory.WithOnDelete(counts.ForgetTenant))
		return fixture{
			store: counts,
			seedTenant: func(t *testing.T) did.DID {
				id := testutil.RandomDID(t)
				require.NoError(t, tenants.Add(t.Context(), id, "ext-"+id.String(), tenant.Active))
				return id
			},
			seedProvider: random,
			dropTenant: func(t *testing.T, id did.DID) {
				require.NoError(t, tenants.Delete(t.Context(), id))
			},
		}
	case Postgres:
		if testutil.IsRunningInCI(t) && runtime.GOOS == "linux" {
			if !testutil.IsDockerAvailable(t) {
				t.Fatalf("docker is expected in CI linux testing environments, but wasn't found")
			}
		}
		if !testutil.IsDockerAvailable(t) {
			t.SkipNow()
		}
		pool := testutil.CreatePostgres(t)
		tenants := tenantpostgres.New(pool)
		providers := providerpostgres.New(pool)
		return fixture{
			store: usagepostgres.New(pool),
			seedTenant: func(t *testing.T) did.DID {
				id := testutil.RandomDID(t)
				require.NoError(t, tenants.Add(t.Context(), id, "ext-"+id.String(), tenant.Active))
				return id
			},
			seedProvider: func(t *testing.T) did.DID {
				id := testutil.RandomDID(t)
				require.NoError(t, providers.Add(t.Context(), id, id.String(), nil))
				return id
			},
			dropTenant: func(t *testing.T, id did.DID) {
				require.NoError(t, tenants.Delete(t.Context(), id))
			},
		}
	}
	panic("unknown store kind")
}

var (
	h0 = time.Date(2026, 11, 25, 10, 0, 0, 0, time.UTC)
	h1 = h0.Add(time.Hour)
	h2 = h0.Add(2 * time.Hour)
)

func TestUsageStore(t *testing.T) {
	for _, k := range storeKinds {
		t.Run(string(k), func(t *testing.T) {
			f := makeStore(t, k)
			s := f.store

			t.Run("stores counts and returns them by bucket in hour order", func(t *testing.T) {
				provider, tenantID, bucket := f.seedProvider(t), f.seedTenant(t), testutil.RandomDID(t)
				require.NoError(t, s.SetEgress(t.Context(), provider, []usage.EgressCount{
					{Bucket: bucket, Tenant: tenantID, Hour: h1, Bytes: 20},
					{Bucket: bucket, Tenant: tenantID, Hour: h0, Bytes: 10},
				}))

				got, err := s.BucketEgress(t.Context(), bucket, h0, h2)
				require.NoError(t, err)
				require.Equal(t, []usage.HourlyEgress{{Hour: h0, Bytes: 10}, {Hour: h1, Bytes: 20}}, got)
			})

			t.Run("a later report replaces an hour's count", func(t *testing.T) {
				provider, tenantID, bucket := f.seedProvider(t), f.seedTenant(t), testutil.RandomDID(t)
				first := []usage.EgressCount{{Bucket: bucket, Tenant: tenantID, Hour: h0, Bytes: 10}}
				require.NoError(t, s.SetEgress(t.Context(), provider, first))
				// Repeating a report changes nothing.
				require.NoError(t, s.SetEgress(t.Context(), provider, first))
				got, err := s.BucketEgress(t.Context(), bucket, h0, h1)
				require.NoError(t, err)
				require.Equal(t, []usage.HourlyEgress{{Hour: h0, Bytes: 10}}, got)

				// The hour grows, and the new total stands in for the old one.
				require.NoError(t, s.SetEgress(t.Context(), provider, []usage.EgressCount{
					{Bucket: bucket, Tenant: tenantID, Hour: h0, Bytes: 25},
				}))
				got, err = s.BucketEgress(t.Context(), bucket, h0, h1)
				require.NoError(t, err)
				require.Equal(t, []usage.HourlyEgress{{Hour: h0, Bytes: 25}}, got)
			})

			t.Run("the range takes hours starting in [from, to)", func(t *testing.T) {
				provider, tenantID, bucket := f.seedProvider(t), f.seedTenant(t), testutil.RandomDID(t)
				require.NoError(t, s.SetEgress(t.Context(), provider, []usage.EgressCount{
					{Bucket: bucket, Tenant: tenantID, Hour: h0, Bytes: 1},
					{Bucket: bucket, Tenant: tenantID, Hour: h1, Bytes: 2},
					{Bucket: bucket, Tenant: tenantID, Hour: h2, Bytes: 4},
				}))

				got, err := s.BucketEgress(t.Context(), bucket, h1, h2)
				require.NoError(t, err)
				require.Equal(t, []usage.HourlyEgress{{Hour: h1, Bytes: 2}}, got)

				// A range that starts part way through an hour leaves that hour out.
				got, err = s.BucketEgress(t.Context(), bucket, h0.Add(time.Minute), h2.Add(time.Minute))
				require.NoError(t, err)
				require.Equal(t, []usage.HourlyEgress{{Hour: h1, Bytes: 2}, {Hour: h2, Bytes: 4}}, got)

				got, err = s.BucketEgress(t.Context(), bucket, h2.Add(time.Hour), h2.Add(2*time.Hour))
				require.NoError(t, err)
				require.Empty(t, got)
			})

			t.Run("a tenant's egress sums its buckets and leaves other tenants' out", func(t *testing.T) {
				provider := f.seedProvider(t)
				tenantID, other := f.seedTenant(t), f.seedTenant(t)
				a, b, theirs := testutil.RandomDID(t), testutil.RandomDID(t), testutil.RandomDID(t)
				require.NoError(t, s.SetEgress(t.Context(), provider, []usage.EgressCount{
					{Bucket: a, Tenant: tenantID, Hour: h0, Bytes: 10},
					{Bucket: b, Tenant: tenantID, Hour: h0, Bytes: 5},
					{Bucket: b, Tenant: tenantID, Hour: h1, Bytes: 7},
					{Bucket: theirs, Tenant: other, Hour: h0, Bytes: 1000},
				}))

				got, err := s.TenantEgress(t.Context(), tenantID, h0, h2)
				require.NoError(t, err)
				require.Equal(t, []usage.HourlyEgress{{Hour: h0, Bytes: 15}, {Hour: h1, Bytes: 7}}, got)
			})

			t.Run("counts from two providers for one bucket are kept apart and summed", func(t *testing.T) {
				p1, p2 := f.seedProvider(t), f.seedProvider(t)
				tenantID, bucket := f.seedTenant(t), testutil.RandomDID(t)
				require.NoError(t, s.SetEgress(t.Context(), p1, []usage.EgressCount{{Bucket: bucket, Tenant: tenantID, Hour: h0, Bytes: 10}}))
				require.NoError(t, s.SetEgress(t.Context(), p2, []usage.EgressCount{{Bucket: bucket, Tenant: tenantID, Hour: h0, Bytes: 3}}))
				// One provider's later report does not replace the other's.
				require.NoError(t, s.SetEgress(t.Context(), p1, []usage.EgressCount{{Bucket: bucket, Tenant: tenantID, Hour: h0, Bytes: 11}}))

				got, err := s.BucketEgress(t.Context(), bucket, h0, h1)
				require.NoError(t, err)
				require.Equal(t, []usage.HourlyEgress{{Hour: h0, Bytes: 14}}, got)
			})

			t.Run("refuses a report it cannot store, and stores none of it", func(t *testing.T) {
				provider, tenantID, bucket := f.seedProvider(t), f.seedTenant(t), testutil.RandomDID(t)
				good := usage.EgressCount{Bucket: bucket, Tenant: tenantID, Hour: h0, Bytes: 10}
				for name, bad := range map[string]usage.EgressCount{
					"no bucket":       {Tenant: tenantID, Hour: h1, Bytes: 1},
					"no tenant":       {Bucket: bucket, Hour: h1, Bytes: 1},
					"part of an hour": {Bucket: bucket, Tenant: tenantID, Hour: h1.Add(time.Second), Bytes: 1},
					"too large":       {Bucket: bucket, Tenant: tenantID, Hour: h1, Bytes: usage.MaxBytes + 1},
					"named twice":     good,
				} {
					err := s.SetEgress(t.Context(), provider, []usage.EgressCount{good, bad})
					require.ErrorIs(t, err, store.ErrInvalidArgument, name)
				}
				require.ErrorIs(t, s.SetEgress(t.Context(), did.Undef, []usage.EgressCount{good}), store.ErrInvalidArgument)

				got, err := s.BucketEgress(t.Context(), bucket, h0, h2)
				require.NoError(t, err)
				require.Empty(t, got)
			})

			t.Run("accepts an empty report and the largest count", func(t *testing.T) {
				provider, tenantID, bucket := f.seedProvider(t), f.seedTenant(t), testutil.RandomDID(t)
				require.NoError(t, s.SetEgress(t.Context(), provider, nil))
				require.NoError(t, s.SetEgress(t.Context(), provider, []usage.EgressCount{
					{Bucket: bucket, Tenant: tenantID, Hour: h0, Bytes: usage.MaxBytes},
				}))
				got, err := s.BucketEgress(t.Context(), bucket, h0, h1)
				require.NoError(t, err)
				require.Equal(t, []usage.HourlyEgress{{Hour: h0, Bytes: usage.MaxBytes}}, got)
			})

			t.Run("a sum past the largest count is the largest count", func(t *testing.T) {
				p1, p2, tenantID := f.seedProvider(t), f.seedProvider(t), f.seedTenant(t)
				a, b := testutil.RandomDID(t), testutil.RandomDID(t)
				require.NoError(t, s.SetEgress(t.Context(), p1, []usage.EgressCount{
					{Bucket: a, Tenant: tenantID, Hour: h0, Bytes: usage.MaxBytes},
					{Bucket: b, Tenant: tenantID, Hour: h0, Bytes: usage.MaxBytes},
					{Bucket: b, Tenant: tenantID, Hour: h1, Bytes: 5},
				}))
				require.NoError(t, s.SetEgress(t.Context(), p2, []usage.EgressCount{
					{Bucket: a, Tenant: tenantID, Hour: h0, Bytes: usage.MaxBytes},
					{Bucket: b, Tenant: tenantID, Hour: h0, Bytes: 1},
				}))

				got, err := s.TenantEgress(t.Context(), tenantID, h0, h2)
				require.NoError(t, err)
				require.Equal(t, []usage.HourlyEgress{{Hour: h0, Bytes: usage.MaxBytes}, {Hour: h1, Bytes: 5}}, got)

				got, err = s.BucketEgress(t.Context(), a, h0, h1)
				require.NoError(t, err)
				require.Equal(t, []usage.HourlyEgress{{Hour: h0, Bytes: usage.MaxBytes}}, got)
			})

			t.Run("a tenant's counts go when the tenant does", func(t *testing.T) {
				provider, tenantID, bucket := f.seedProvider(t), f.seedTenant(t), testutil.RandomDID(t)
				other, kept := f.seedTenant(t), testutil.RandomDID(t)
				require.NoError(t, s.SetEgress(t.Context(), provider, []usage.EgressCount{
					{Bucket: bucket, Tenant: tenantID, Hour: h0, Bytes: 10},
					{Bucket: kept, Tenant: other, Hour: h0, Bytes: 7},
				}))
				f.dropTenant(t, tenantID)
				got, err := s.BucketEgress(t.Context(), bucket, h0, h1)
				require.NoError(t, err)
				require.Empty(t, got)
				got, err = s.BucketEgress(t.Context(), kept, h0, h1)
				require.NoError(t, err)
				require.Equal(t, []usage.HourlyEgress{{Hour: h0, Bytes: 7}}, got)
			})
		})
	}
}
