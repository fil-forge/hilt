package usage_test

import (
	"testing"
	"time"

	"github.com/fil-forge/hilt/internal/testutil"
	"github.com/fil-forge/hilt/pkg/store"
	providerpostgres "github.com/fil-forge/hilt/pkg/store/provider/postgres"
	"github.com/fil-forge/hilt/pkg/store/tenant"
	tenantpostgres "github.com/fil-forge/hilt/pkg/store/tenant/postgres"
	"github.com/fil-forge/hilt/pkg/store/usage"
	usagepostgres "github.com/fil-forge/hilt/pkg/store/usage/postgres"
	"github.com/fil-forge/ucantone/did"
	"github.com/stretchr/testify/require"
)

// fixture is the store under test and seeders for the rows its foreign keys
// reference.
type fixture struct {
	store        usage.Store
	seedTenant   func(t *testing.T) did.DID
	seedProvider func(t *testing.T) did.DID
	// dropTenant deletes a tenant.
	dropTenant func(t *testing.T, id did.DID)
}

func makeStore(t *testing.T) fixture {
	pool := testutil.PostgresOrSkip(t)
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

var (
	h0 = time.Date(2026, 11, 25, 10, 0, 0, 0, time.UTC)
	h1 = h0.Add(time.Hour)
	h2 = h0.Add(2 * time.Hour)
)

func TestUsageStore(t *testing.T) {
	f := makeStore(t)
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

	t.Run("an hour keeps the largest count reported for it", func(t *testing.T) {
		provider, tenantID, bucket := f.seedProvider(t), f.seedTenant(t), testutil.RandomDID(t)
		first := []usage.EgressCount{{Bucket: bucket, Tenant: tenantID, Hour: h0, Bytes: 10}}
		require.NoError(t, s.SetEgress(t.Context(), provider, first))
		// Repeating a report changes nothing.
		require.NoError(t, s.SetEgress(t.Context(), provider, first))
		got, err := s.BucketEgress(t.Context(), bucket, h0, h1)
		require.NoError(t, err)
		require.Equal(t, []usage.HourlyEgress{{Hour: h0, Bytes: 10}}, got)

		// The hour grows, and the larger total takes the old one's place.
		require.NoError(t, s.SetEgress(t.Context(), provider, []usage.EgressCount{
			{Bucket: bucket, Tenant: tenantID, Hour: h0, Bytes: 25},
		}))
		got, err = s.BucketEgress(t.Context(), bucket, h0, h1)
		require.NoError(t, err)
		require.Equal(t, []usage.HourlyEgress{{Hour: h0, Bytes: 25}}, got)

		// An older total arriving late changes nothing, while a
		// larger one in the same report is still stored.
		require.NoError(t, s.SetEgress(t.Context(), provider, []usage.EgressCount{
			{Bucket: bucket, Tenant: tenantID, Hour: h0, Bytes: 10},
			{Bucket: bucket, Tenant: tenantID, Hour: h1, Bytes: 7},
		}))
		got, err = s.BucketEgress(t.Context(), bucket, h0, h2)
		require.NoError(t, err)
		require.Equal(t, []usage.HourlyEgress{{Hour: h0, Bytes: 25}, {Hour: h1, Bytes: 7}}, got)
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

		// The bounds are instants, so part of a second counts.
		got, err = s.BucketEgress(t.Context(), bucket, h0.Add(time.Millisecond), h2.Add(time.Millisecond))
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
		// One provider's later report leaves the other's count alone.
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

	t.Run("an hour keeps the largest of each object total reported for it", func(t *testing.T) {
		provider, tenantID, bucket := f.seedProvider(t), f.seedTenant(t), testutil.RandomDID(t)
		first := []usage.ObjectCount{{Bucket: bucket, Tenant: tenantID, Hour: h0, Added: 10, Removed: 4}}
		require.NoError(t, s.SetObjects(t.Context(), provider, first))
		// Repeating a report changes nothing.
		require.NoError(t, s.SetObjects(t.Context(), provider, first))
		got, err := s.BucketObjects(t.Context(), bucket, h0, h1)
		require.NoError(t, err)
		require.Equal(t, []usage.HourlyObjects{{Hour: h0, Added: 10, Removed: 4}}, got)

		// The hour goes on, and each total that grew takes the old one's place.
		require.NoError(t, s.SetObjects(t.Context(), provider, []usage.ObjectCount{
			{Bucket: bucket, Tenant: tenantID, Hour: h0, Added: 12, Removed: 9},
		}))
		// An older report arriving late changes nothing, while
		// another hour in the same report is still stored.
		require.NoError(t, s.SetObjects(t.Context(), provider, []usage.ObjectCount{
			{Bucket: bucket, Tenant: tenantID, Hour: h0, Added: 11, Removed: 4},
			{Bucket: bucket, Tenant: tenantID, Hour: h1, Added: 13, Removed: 9},
		}))
		// Totals are kept apart: one that grew is stored beside one that did not.
		require.NoError(t, s.SetObjects(t.Context(), provider, []usage.ObjectCount{
			{Bucket: bucket, Tenant: tenantID, Hour: h1, Added: 2, Removed: 10},
		}))
		got, err = s.BucketObjects(t.Context(), bucket, h0, h2)
		require.NoError(t, err)
		require.Equal(t, []usage.HourlyObjects{
			{Hour: h0, Added: 12, Removed: 9},
			{Hour: h1, Added: 13, Removed: 10},
		}, got)
	})

	t.Run("a bucket's objects open with the latest hour before the range", func(t *testing.T) {
		provider, tenantID := f.seedProvider(t), f.seedTenant(t)
		bucket, other := testutil.RandomDID(t), testutil.RandomDID(t)
		long := h0.Add(-90 * 24 * time.Hour)
		require.NoError(t, s.SetObjects(t.Context(), provider, []usage.ObjectCount{
			{Bucket: bucket, Tenant: tenantID, Hour: long, Added: 1},
			{Bucket: bucket, Tenant: tenantID, Hour: h0, Added: 5, Removed: 1},
			{Bucket: bucket, Tenant: tenantID, Hour: h1, Added: 6, Removed: 1},
			{Bucket: bucket, Tenant: tenantID, Hour: h2, Added: 9, Removed: 3},
			{Bucket: other, Tenant: tenantID, Hour: h1, Added: 1000},
		}))

		// Only the latest of the hours before the range comes with it.
		got, err := s.BucketObjects(t.Context(), bucket, h1, h2)
		require.NoError(t, err)
		require.Equal(t, []usage.HourlyObjects{
			{Hour: h0, Added: 5, Removed: 1},
			{Hour: h1, Added: 6, Removed: 1},
		}, got)

		// A range in which the bucket did not change still says what it held.
		got, err = s.BucketObjects(t.Context(), bucket, h0.Add(-2*time.Hour), h0.Add(-time.Hour))
		require.NoError(t, err)
		require.Equal(t, []usage.HourlyObjects{{Hour: long, Added: 1}}, got)

		// A range starting part way through an hour opens with that hour.
		got, err = s.BucketObjects(t.Context(), bucket, h2.Add(time.Minute), h2.Add(time.Hour))
		require.NoError(t, err)
		require.Equal(t, []usage.HourlyObjects{{Hour: h2, Added: 9, Removed: 3}}, got)

		// A range ending part way through a second takes in the hour
		// that starts on that second.
		got, err = s.BucketObjects(t.Context(), bucket, h1, h2.Add(time.Millisecond))
		require.NoError(t, err)
		require.Equal(t, []usage.HourlyObjects{
			{Hour: h0, Added: 5, Removed: 1},
			{Hour: h1, Added: 6, Removed: 1},
			{Hour: h2, Added: 9, Removed: 3},
		}, got)

		// Nothing was reported before the bucket's first hour.
		got, err = s.BucketObjects(t.Context(), bucket, long.Add(-2*time.Hour), long)
		require.NoError(t, err)
		require.Empty(t, got)
	})

	t.Run("refuses object counts it cannot store, and stores none of them", func(t *testing.T) {
		provider, tenantID, bucket := f.seedProvider(t), f.seedTenant(t), testutil.RandomDID(t)
		good := usage.ObjectCount{Bucket: bucket, Tenant: tenantID, Hour: h0, Added: 10}
		for name, bad := range map[string]usage.ObjectCount{
			"no bucket":         {Tenant: tenantID, Hour: h1, Added: 1},
			"no tenant":         {Bucket: bucket, Hour: h1, Added: 1},
			"part of an hour":   {Bucket: bucket, Tenant: tenantID, Hour: h1.Add(time.Second), Added: 1},
			"added too large":   {Bucket: bucket, Tenant: tenantID, Hour: h1, Added: usage.MaxObjects + 1},
			"removed too large": {Bucket: bucket, Tenant: tenantID, Hour: h1, Removed: usage.MaxObjects + 1},
			"named twice":       good,
		} {
			err := s.SetObjects(t.Context(), provider, []usage.ObjectCount{good, bad})
			require.ErrorIs(t, err, store.ErrInvalidArgument, name)
		}
		require.ErrorIs(t, s.SetObjects(t.Context(), did.Undef, []usage.ObjectCount{good}), store.ErrInvalidArgument)

		got, err := s.BucketObjects(t.Context(), bucket, h0, h2)
		require.NoError(t, err)
		require.Empty(t, got)
	})

	t.Run("accepts no object counts, the largest, and more lost than gained", func(t *testing.T) {
		provider, tenantID, bucket := f.seedProvider(t), f.seedTenant(t), testutil.RandomDID(t)
		require.NoError(t, s.SetObjects(t.Context(), provider, nil))
		require.NoError(t, s.SetObjects(t.Context(), provider, []usage.ObjectCount{
			{Bucket: bucket, Tenant: tenantID, Hour: h0, Added: usage.MaxObjects, Removed: usage.MaxObjects},
			{Bucket: bucket, Tenant: tenantID, Hour: h1, Added: 1, Removed: 3},
		}))
		got, err := s.BucketObjects(t.Context(), bucket, h0, h2)
		require.NoError(t, err)
		require.Len(t, got, 2)
		require.Zero(t, got[0].Held())
		// More lost than gained is stored as reported and read as nothing held.
		require.Equal(t, usage.HourlyObjects{Hour: h1, Added: 1, Removed: 3}, got[1])
		require.Zero(t, got[1].Held())
	})

	t.Run("a tenant's object counts go when the tenant does", func(t *testing.T) {
		provider, tenantID, bucket := f.seedProvider(t), f.seedTenant(t), testutil.RandomDID(t)
		other, kept := f.seedTenant(t), testutil.RandomDID(t)
		require.NoError(t, s.SetObjects(t.Context(), provider, []usage.ObjectCount{
			{Bucket: bucket, Tenant: tenantID, Hour: h0, Added: 10},
			{Bucket: kept, Tenant: other, Hour: h0, Added: 7},
		}))
		f.dropTenant(t, tenantID)
		got, err := s.BucketObjects(t.Context(), bucket, h0, h1)
		require.NoError(t, err)
		require.Empty(t, got)
		got, err = s.BucketObjects(t.Context(), kept, h0, h1)
		require.NoError(t, err)
		require.Equal(t, []usage.HourlyObjects{{Hour: h0, Added: 7}}, got)
	})
}
