package metrics_test

import (
	"testing"
	"time"

	"github.com/fil-forge/hilt/internal/testutil"
	metricssvc "github.com/fil-forge/hilt/pkg/api/service/metrics"
	bucketmemory "github.com/fil-forge/hilt/pkg/store/bucket/memory"
	"github.com/fil-forge/hilt/pkg/store/tenant"
	tenantmemory "github.com/fil-forge/hilt/pkg/store/tenant/memory"
	usagestore "github.com/fil-forge/hilt/pkg/store/usage"
	usagememory "github.com/fil-forge/hilt/pkg/store/usage/memory"
	"github.com/fil-forge/ucantone/did"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

// egressFixture is a tenant with two buckets, served by one provider, over
// memory stores. The egress series reads nothing from the upload service or
// the vault, so the service is built without them.
type egressFixture struct {
	svc      *metricssvc.Service
	usage    *usagememory.Store
	buckets  *bucketmemory.Store
	tenant   did.DID
	provider did.DID
	a, b     did.DID
}

var egressNow = time.Date(2026, 11, 25, 12, 30, 0, 0, time.UTC)

func setupEgress(t *testing.T) *egressFixture {
	t.Helper()
	f := &egressFixture{
		usage:    usagememory.New(),
		buckets:  bucketmemory.New(),
		tenant:   testutil.RandomDID(t),
		provider: testutil.RandomDID(t),
		a:        testutil.RandomDID(t),
		b:        testutil.RandomDID(t),
	}
	tenants := tenantmemory.New()
	require.NoError(t, tenants.Add(t.Context(), f.tenant, "tenant-1", tenant.Active))
	require.NoError(t, f.buckets.Add(t.Context(), f.a, f.tenant, f.provider, "bucket-a"))
	require.NoError(t, f.buckets.Add(t.Context(), f.b, f.tenant, f.provider, "bucket-b"))
	f.svc = metricssvc.New(zap.NewNop(), tenants, f.buckets, nil, nil, nil, f.usage,
		metricssvc.WithClock(func() time.Time { return egressNow }))
	return f
}

func (f *egressFixture) report(t *testing.T, bucket did.DID, hour time.Time, bytes uint64) {
	t.Helper()
	require.NoError(t, f.usage.SetEgress(t.Context(), f.provider, []usagestore.EgressCount{
		{Bucket: bucket, Tenant: f.tenant, Hour: hour, Bytes: bytes},
	}))
}

func at(hour, minute int) time.Time {
	return time.Date(2026, 11, 25, hour, minute, 0, 0, time.UTC)
}

func TestBucketEgressLaysHoursOntoWindows(t *testing.T) {
	f := setupEgress(t)
	f.report(t, f.a, at(8, 0), 1)
	f.report(t, f.a, at(9, 0), 2)
	f.report(t, f.a, at(10, 0), 4)
	f.report(t, f.b, at(9, 0), 1000)

	// Two-hour windows over 08:00-12:00: each sums the hours starting in it,
	// and is timestamped at its end.
	got, err := f.svc.BucketEgress(t.Context(), "tenant-1", "bucket-a", at(8, 0), at(12, 0), 2*time.Hour)
	require.NoError(t, err)
	require.Equal(t, []metricssvc.EgressSample{
		{End: at(10, 0), BytesEgressed: 3},
		{End: at(12, 0), BytesEgressed: 4},
	}, got)
}

func TestEgressSeriesIsDense(t *testing.T) {
	f := setupEgress(t)
	f.report(t, f.a, at(10, 0), 7)

	got, err := f.svc.BucketEgress(t.Context(), "tenant-1", "bucket-a", at(8, 0), at(12, 0), time.Hour)
	require.NoError(t, err)
	require.Equal(t, []metricssvc.EgressSample{
		{End: at(9, 0), BytesEgressed: 0},
		{End: at(10, 0), BytesEgressed: 0},
		{End: at(11, 0), BytesEgressed: 7},
		{End: at(12, 0), BytesEgressed: 0},
	}, got)
}

// A range running past the present ends at the present, with a short last
// window, as the storage series does.
func TestEgressRangeEndsAtThePresent(t *testing.T) {
	f := setupEgress(t)
	f.report(t, f.a, at(11, 0), 5)
	f.report(t, f.a, at(12, 0), 9) // the hour in progress

	got, err := f.svc.BucketEgress(t.Context(), "tenant-1", "bucket-a", at(11, 0), at(15, 0), time.Hour)
	require.NoError(t, err)
	require.Equal(t, []metricssvc.EgressSample{
		{End: at(12, 0), BytesEgressed: 5},
		{End: egressNow, BytesEgressed: 9},
	}, got)

	got, err = f.svc.BucketEgress(t.Context(), "tenant-1", "bucket-a", at(13, 0), at(15, 0), time.Hour)
	require.NoError(t, err)
	require.Empty(t, got)
}

// A range that starts part way through an hour does not count that hour: its
// bytes belong to the window the hour starts in.
func TestEgressRangeStartingMidHour(t *testing.T) {
	f := setupEgress(t)
	f.report(t, f.a, at(8, 0), 1)
	f.report(t, f.a, at(9, 0), 2)

	got, err := f.svc.BucketEgress(t.Context(), "tenant-1", "bucket-a", at(8, 30), at(10, 30), time.Hour)
	require.NoError(t, err)
	require.Equal(t, []metricssvc.EgressSample{
		{End: at(9, 30), BytesEgressed: 2},
		{End: at(10, 30), BytesEgressed: 0},
	}, got)
}

func TestTenantEgressCountsDeletedBuckets(t *testing.T) {
	f := setupEgress(t)
	f.report(t, f.a, at(9, 0), 10)
	f.report(t, f.b, at(9, 0), 5)
	require.NoError(t, f.buckets.Delete(t.Context(), f.a))
	require.NoError(t, f.buckets.Delete(t.Context(), f.b))

	// The tenant holds no buckets now, and what they sent still counts.
	got, err := f.svc.TenantEgress(t.Context(), "tenant-1", at(9, 0), at(10, 0), time.Hour)
	require.NoError(t, err)
	require.Equal(t, []metricssvc.EgressSample{{End: at(10, 0), BytesEgressed: 15}}, got)

	_, err = f.svc.BucketEgress(t.Context(), "tenant-1", "bucket-a", at(9, 0), at(10, 0), time.Hour)
	require.ErrorIs(t, err, metricssvc.ErrBucketNotFound)
}

func TestEgressRefusals(t *testing.T) {
	f := setupEgress(t)

	_, err := f.svc.TenantEgress(t.Context(), "nobody", at(9, 0), at(10, 0), time.Hour)
	require.ErrorIs(t, err, metricssvc.ErrTenantNotFound)
	_, err = f.svc.BucketEgress(t.Context(), "tenant-1", "missing", at(9, 0), at(10, 0), time.Hour)
	require.ErrorIs(t, err, metricssvc.ErrBucketNotFound)

	// One window more than a series may hold.
	from := egressNow.Add(-time.Duration(metricssvc.MaxEgressSamples+1) * time.Hour)
	_, err = f.svc.TenantEgress(t.Context(), "tenant-1", from, egressNow, time.Hour)
	require.ErrorIs(t, err, metricssvc.ErrTooManySamples)
	got, err := f.svc.TenantEgress(t.Context(), "tenant-1", from.Add(time.Hour), egressNow, time.Hour)
	require.NoError(t, err)
	require.Len(t, got, metricssvc.MaxEgressSamples)
}
