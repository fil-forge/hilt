package rpc_test

import (
	"testing"
	"time"

	"github.com/fil-forge/hilt/internal/testutil"
	"github.com/fil-forge/hilt/pkg/rpc"
	bucketmemory "github.com/fil-forge/hilt/pkg/store/bucket/memory"
	usagestore "github.com/fil-forge/hilt/pkg/store/usage"
	usagememory "github.com/fil-forge/hilt/pkg/store/usage/memory"
	"github.com/fil-forge/libforge/commands/s3/usage"
	"github.com/fil-forge/ucantone/did"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

var (
	usageHour0 = time.Date(2026, 11, 25, 10, 0, 0, 0, time.UTC)
	usageHour1 = usageHour0.Add(time.Hour)
)

// usageFixture is a provider serving one tenant's bucket, over memory stores.
type usageFixture struct {
	buckets  *bucketmemory.Store
	counts   *usagememory.Store
	provider did.DID
	tenant   did.DID
	bucket   did.DID
}

func newUsageFixture(t *testing.T) *usageFixture {
	t.Helper()
	f := &usageFixture{
		buckets:  bucketmemory.New(),
		counts:   usagememory.New(),
		provider: testutil.RandomDID(t),
		tenant:   testutil.RandomDID(t),
		bucket:   testutil.RandomDID(t),
	}
	require.NoError(t, f.buckets.Add(t.Context(), f.bucket, f.tenant, f.provider, "photos"))
	return f
}

func (f *usageFixture) report(t *testing.T, provider did.DID, egress ...usage.SpaceEgress) (*usage.ReportOK, error) {
	t.Helper()
	return rpc.ReportUsage(t.Context(), zap.NewNop(), f.buckets, f.counts, provider, &usage.ReportArguments{Egress: egress})
}

func (f *usageFixture) stored(t *testing.T, bucket did.DID) []usagestore.HourlyEgress {
	t.Helper()
	got, err := f.counts.BucketEgress(t.Context(), bucket, usageHour0, usageHour1.Add(time.Hour))
	require.NoError(t, err)
	return got
}

func hours(counts ...uint64) []usage.HourEgress {
	out := make([]usage.HourEgress, 0, len(counts))
	for i, c := range counts {
		out = append(out, usage.HourEgress{Hour: usageHour0.Add(time.Duration(i) * time.Hour).Unix(), Bytes: c})
	}
	return out
}

func TestReportUsageStoresAProvidersCounts(t *testing.T) {
	f := newUsageFixture(t)

	ok, err := f.report(t, f.provider, usage.SpaceEgress{Space: f.bucket, Hours: hours(10, 20)})
	require.NoError(t, err)
	require.Empty(t, ok.Warnings)
	require.Equal(t, []usagestore.HourlyEgress{{Hour: usageHour0, Bytes: 10}, {Hour: usageHour1, Bytes: 20}}, f.stored(t, f.bucket))

	// The counts are attributed to the bucket's tenant, which the report
	// does not name.
	tenantTotal, err := f.counts.TenantEgress(t.Context(), f.tenant, usageHour0, usageHour1.Add(time.Hour))
	require.NoError(t, err)
	require.Equal(t, []usagestore.HourlyEgress{{Hour: usageHour0, Bytes: 10}, {Hour: usageHour1, Bytes: 20}}, tenantTotal)

	// An hour reported again, grown, replaces what was held; a repeat changes nothing.
	for range 2 {
		ok, err = f.report(t, f.provider, usage.SpaceEgress{Space: f.bucket, Hours: hours(10, 35)})
		require.NoError(t, err)
		require.Empty(t, ok.Warnings)
	}
	require.Equal(t, []usagestore.HourlyEgress{{Hour: usageHour0, Bytes: 10}, {Hour: usageHour1, Bytes: 35}}, f.stored(t, f.bucket))
}

// One count that cannot be used does not fail the report: the rest is stored
// and the gateway is told what was left out.
func TestReportUsageSkipsBucketsItCannotAttribute(t *testing.T) {
	f := newUsageFixture(t)
	unknown := testutil.RandomDID(t)
	theirs := testutil.RandomDID(t)
	require.NoError(t, f.buckets.Add(t.Context(), theirs, testutil.RandomDID(t), testutil.RandomDID(t), "elsewhere"))

	ok, err := f.report(t, f.provider,
		usage.SpaceEgress{Space: unknown, Hours: hours(1)},
		usage.SpaceEgress{Space: f.bucket, Hours: hours(10)},
		usage.SpaceEgress{Space: theirs, Hours: hours(1000)},
	)
	require.NoError(t, err)
	// Each bucket left out comes back with the reason, in the report's order.
	require.Len(t, ok.Warnings, 2)
	require.Equal(t, usage.UnknownBucketWarningName, ok.Warnings[0].Name)
	require.Equal(t, unknown, ok.Warnings[0].Space)
	require.NotEmpty(t, ok.Warnings[0].Message)
	require.Equal(t, usage.BucketRegionMismatchWarningName, ok.Warnings[1].Name)
	require.Equal(t, theirs, ok.Warnings[1].Space)
	require.NotEmpty(t, ok.Warnings[1].Message)
	require.Equal(t, []usagestore.HourlyEgress{{Hour: usageHour0, Bytes: 10}}, f.stored(t, f.bucket))
	// Another provider's bucket gains nothing from a provider that does not serve it.
	require.Empty(t, f.stored(t, theirs))
	require.Empty(t, f.stored(t, unknown))
}

// A bucket's last hours are reported after it has been deleted, and still
// count toward its tenant.
func TestReportUsageAcceptsADeletedBucket(t *testing.T) {
	f := newUsageFixture(t)
	require.NoError(t, f.buckets.Delete(t.Context(), f.bucket))

	ok, err := f.report(t, f.provider, usage.SpaceEgress{Space: f.bucket, Hours: hours(10)})
	require.NoError(t, err)
	require.Empty(t, ok.Warnings)

	tenantTotal, err := f.counts.TenantEgress(t.Context(), f.tenant, usageHour0, usageHour1)
	require.NoError(t, err)
	require.Equal(t, []usagestore.HourlyEgress{{Hour: usageHour0, Bytes: 10}}, tenantTotal)
}

func TestReportUsageRefusesAReportThatIsNotWellFormed(t *testing.T) {
	f := newUsageFixture(t)
	good := usage.HourEgress{Hour: usageHour0.Unix(), Bytes: 10}

	for name, bad := range map[string][]usage.SpaceEgress{
		"part of an hour": {{Space: f.bucket, Hours: []usage.HourEgress{good, {Hour: usageHour1.Unix() + 1, Bytes: 1}}}},
		"too large":       {{Space: f.bucket, Hours: []usage.HourEgress{good, {Hour: usageHour1.Unix(), Bytes: usagestore.MaxBytes + 1}}}},
		"hour twice":      {{Space: f.bucket, Hours: []usage.HourEgress{good, good}}},
		"bucket twice":    {{Space: f.bucket, Hours: []usage.HourEgress{good}}, {Space: f.bucket, Hours: []usage.HourEgress{good}}},
	} {
		_, err := f.report(t, f.provider, bad...)
		require.ErrorIs(t, err, rpc.ErrInvalidUsageReport, name)
		// None of a refused report is stored, the good count included.
		require.Empty(t, f.stored(t, f.bucket), name)
	}
}

func TestReportUsageLimitsTheCountsInOneReport(t *testing.T) {
	f := newUsageFixture(t)
	many := make([]usage.HourEgress, rpc.MaxReportCounts/2+1)
	for i := range many {
		many[i] = usage.HourEgress{Hour: usageHour0.Add(time.Duration(i) * time.Hour).Unix(), Bytes: 1}
	}
	other := testutil.RandomDID(t)
	require.NoError(t, f.buckets.Add(t.Context(), other, f.tenant, f.provider, "videos"))

	// The limit is on the report as a whole, across its buckets.
	_, err := f.report(t, f.provider,
		usage.SpaceEgress{Space: f.bucket, Hours: many},
		usage.SpaceEgress{Space: other, Hours: many},
	)
	require.ErrorIs(t, err, rpc.ErrTooManyCounts)

	ok, err := f.report(t, f.provider, usage.SpaceEgress{Space: f.bucket, Hours: many})
	require.NoError(t, err)
	require.Empty(t, ok.Warnings)
}

func TestReportUsageAcceptsAnEmptyReport(t *testing.T) {
	f := newUsageFixture(t)
	ok, err := f.report(t, f.provider)
	require.NoError(t, err)
	require.NotNil(t, ok.Warnings)
	require.Empty(t, ok.Warnings)
}
