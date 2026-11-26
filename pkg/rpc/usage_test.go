package rpc_test

import (
	"testing"
	"time"

	"github.com/fil-forge/hilt/internal/testutil"
	"github.com/fil-forge/hilt/pkg/rpc"
	bucketpostgres "github.com/fil-forge/hilt/pkg/store/bucket/postgres"
	providerpostgres "github.com/fil-forge/hilt/pkg/store/provider/postgres"
	"github.com/fil-forge/hilt/pkg/store/tenant"
	tenantpostgres "github.com/fil-forge/hilt/pkg/store/tenant/postgres"
	usagestore "github.com/fil-forge/hilt/pkg/store/usage"
	usagepostgres "github.com/fil-forge/hilt/pkg/store/usage/postgres"
	"github.com/fil-forge/libforge/commands/s3/usage"
	"github.com/fil-forge/ucantone/did"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

var (
	usageHour0 = time.Date(2026, 11, 25, 10, 0, 0, 0, time.UTC)
	usageHour1 = usageHour0.Add(time.Hour)
)

// usageFixture is a provider serving one tenant's bucket.
type usageFixture struct {
	pool     *pgxpool.Pool
	buckets  *bucketpostgres.Store
	counts   *usagepostgres.Store
	provider did.DID
	tenant   did.DID
	bucket   did.DID
}

func newUsageFixture(t *testing.T) *usageFixture {
	t.Helper()
	pool := testutil.PostgresOrSkip(t)
	f := &usageFixture{
		pool:    pool,
		buckets: bucketpostgres.New(pool),
		counts:  usagepostgres.New(pool),
		bucket:  testutil.RandomDID(t),
	}
	f.provider, f.tenant = f.newProvider(t), f.newTenant(t)
	require.NoError(t, f.buckets.Add(t.Context(), f.bucket, f.tenant, f.provider, "photos"))
	return f
}

// newProvider registers a provider.
func (f *usageFixture) newProvider(t *testing.T) did.DID {
	t.Helper()
	id := testutil.RandomDID(t)
	require.NoError(t, providerpostgres.New(f.pool).Add(t.Context(), id, "region-"+id.String(), nil))
	return id
}

// newTenant creates a tenant.
func (f *usageFixture) newTenant(t *testing.T) did.DID {
	t.Helper()
	id := testutil.RandomDID(t)
	require.NoError(t, tenantpostgres.New(f.pool).Add(t.Context(), id, "ext-"+id.String(), tenant.Active))
	return id
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

	// An hour reported again, grown, takes the place of what was held; a repeat changes nothing.
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
	require.NoError(t, f.buckets.Add(t.Context(), theirs, f.newTenant(t), f.newProvider(t), "elsewhere"))

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

// A fault in the counts of a bucket that would be left out refuses the report
// like any other: nothing is stored and no warning is returned.
func TestReportUsageChecksTheCountsOfBucketsItLeavesOut(t *testing.T) {
	f := newUsageFixture(t)
	good := usage.HourEgress{Hour: usageHour0.Unix(), Bytes: 10}
	unknown := testutil.RandomDID(t)
	stranger, strangers := f.newProvider(t), testutil.RandomDID(t)
	require.NoError(t, f.buckets.Add(t.Context(), strangers, f.tenant, stranger, "elsewhere"))
	mine := usage.SpaceEgress{Space: f.bucket, Hours: []usage.HourEgress{good}}

	for name, bad := range map[string]usage.SpaceEgress{
		"part of an hour":  {Space: unknown, Hours: []usage.HourEgress{{Hour: usageHour1.Unix() + 1, Bytes: 1}}},
		"too large":        {Space: unknown, Hours: []usage.HourEgress{{Hour: usageHour1.Unix(), Bytes: usagestore.MaxBytes + 1}}},
		"hour twice":       {Space: unknown, Hours: []usage.HourEgress{good, good}},
		"another's, twice": {Space: strangers, Hours: []usage.HourEgress{good, good}},
	} {
		ok, err := f.report(t, f.provider, mine, bad)
		require.ErrorIs(t, err, rpc.ErrInvalidUsageReport, name)
		require.Nil(t, ok, name)
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

func (f *usageFixture) reportAll(t *testing.T, args *usage.ReportArguments) (*usage.ReportOK, error) {
	t.Helper()
	return rpc.ReportUsage(t.Context(), zap.NewNop(), f.buckets, f.counts, f.provider, args)
}

func (f *usageFixture) storedObjects(t *testing.T, bucket did.DID) []usagestore.HourlyObjects {
	t.Helper()
	got, err := f.counts.BucketObjects(t.Context(), bucket, usageHour0, usageHour1.Add(time.Hour))
	require.NoError(t, err)
	return got
}

func TestReportUsageStoresObjectCounts(t *testing.T) {
	f := newUsageFixture(t)

	ok, err := f.reportAll(t, &usage.ReportArguments{
		Egress: []usage.SpaceEgress{{Space: f.bucket, Hours: hours(10)}},
		Objects: []usage.SpaceObjects{{Space: f.bucket, Hours: []usage.HourObjects{
			{Hour: usageHour0.Unix(), Added: 5, Removed: 1},
			{Hour: usageHour1.Unix(), Added: 8, Removed: 1},
		}}},
	})
	require.NoError(t, err)
	require.Empty(t, ok.Warnings)
	require.Equal(t, []usagestore.HourlyEgress{{Hour: usageHour0, Bytes: 10}}, f.stored(t, f.bucket))
	require.Equal(t, []usagestore.HourlyObjects{
		{Hour: usageHour0, Added: 5, Removed: 1},
		{Hour: usageHour1, Added: 8, Removed: 1},
	}, f.storedObjects(t, f.bucket))

	// An hour reported again keeps the largest of each total, and a report
	// of objects alone is a whole report.
	for range 2 {
		ok, err = f.reportAll(t, &usage.ReportArguments{
			Objects: []usage.SpaceObjects{{Space: f.bucket, Hours: []usage.HourObjects{
				{Hour: usageHour1.Unix(), Added: 9, Removed: 4},
			}}},
		})
		require.NoError(t, err)
		require.Empty(t, ok.Warnings)
	}
	require.Equal(t, []usagestore.HourlyObjects{
		{Hour: usageHour0, Added: 5, Removed: 1},
		{Hour: usageHour1, Added: 9, Removed: 4},
	}, f.storedObjects(t, f.bucket))
}

// A bucket whose counts are left out is warned about once, however many of
// the report's counts name it.
func TestReportUsageWarnsOnceForABucketItLeavesOut(t *testing.T) {
	f := newUsageFixture(t)
	unknown := testutil.RandomDID(t)
	one := []usage.HourObjects{{Hour: usageHour0.Unix(), Added: 1}}

	ok, err := f.reportAll(t, &usage.ReportArguments{
		Egress: []usage.SpaceEgress{{Space: unknown, Hours: hours(1)}},
		Objects: []usage.SpaceObjects{
			{Space: unknown, Hours: one},
			{Space: f.bucket, Hours: one},
		},
	})
	require.NoError(t, err)
	require.Len(t, ok.Warnings, 1)
	require.Equal(t, usage.UnknownBucketWarningName, ok.Warnings[0].Name)
	require.Equal(t, unknown, ok.Warnings[0].Space)
	require.Empty(t, f.storedObjects(t, unknown))
	require.Equal(t, []usagestore.HourlyObjects{{Hour: usageHour0, Added: 1}}, f.storedObjects(t, f.bucket))
}

// An emptied bucket's last changes are reported after it has been deleted.
func TestReportUsageAcceptsADeletedBucketsObjectCounts(t *testing.T) {
	f := newUsageFixture(t)
	require.NoError(t, f.buckets.Delete(t.Context(), f.bucket))

	ok, err := f.reportAll(t, &usage.ReportArguments{
		Objects: []usage.SpaceObjects{{Space: f.bucket, Hours: []usage.HourObjects{
			{Hour: usageHour0.Unix(), Added: 5, Removed: 5},
		}}},
	})
	require.NoError(t, err)
	require.Empty(t, ok.Warnings)
	require.Equal(t, []usagestore.HourlyObjects{{Hour: usageHour0, Added: 5, Removed: 5}}, f.storedObjects(t, f.bucket))
}

func TestReportUsageRefusesObjectCountsThatAreNotWellFormed(t *testing.T) {
	f := newUsageFixture(t)
	good := usage.HourObjects{Hour: usageHour0.Unix(), Added: 10}
	unknown := testutil.RandomDID(t)

	for name, bad := range map[string][]usage.SpaceObjects{
		"part of an hour":   {{Space: f.bucket, Hours: []usage.HourObjects{good, {Hour: usageHour1.Unix() + 1, Added: 1}}}},
		"added too large":   {{Space: f.bucket, Hours: []usage.HourObjects{good, {Hour: usageHour1.Unix(), Added: usagestore.MaxObjects + 1}}}},
		"removed too large": {{Space: f.bucket, Hours: []usage.HourObjects{good, {Hour: usageHour1.Unix(), Removed: usagestore.MaxObjects + 1}}}},
		"hour twice":        {{Space: f.bucket, Hours: []usage.HourObjects{good, good}}},
		"bucket twice":      {{Space: f.bucket, Hours: []usage.HourObjects{good}}, {Space: f.bucket, Hours: []usage.HourObjects{good}}},
		"unknown's, twice":  {{Space: f.bucket, Hours: []usage.HourObjects{good}}, {Space: unknown, Hours: []usage.HourObjects{good, good}}},
	} {
		ok, err := f.reportAll(t, &usage.ReportArguments{
			Egress:  []usage.SpaceEgress{{Space: f.bucket, Hours: hours(10)}},
			Objects: bad,
		})
		require.ErrorIs(t, err, rpc.ErrInvalidUsageReport, name)
		require.Nil(t, ok, name)
		// None of a refused report is stored, its egress included.
		require.Empty(t, f.stored(t, f.bucket), name)
		require.Empty(t, f.storedObjects(t, f.bucket), name)
	}
}

// The limit on a report's counts is across both kinds.
func TestReportUsageLimitsEgressAndObjectCountsTogether(t *testing.T) {
	f := newUsageFixture(t)
	sent := make([]usage.HourEgress, rpc.MaxReportCounts/2+1)
	held := make([]usage.HourObjects, rpc.MaxReportCounts/2+1)
	for i := range sent {
		hour := usageHour0.Add(time.Duration(i) * time.Hour).Unix()
		sent[i] = usage.HourEgress{Hour: hour, Bytes: 1}
		held[i] = usage.HourObjects{Hour: hour, Added: 1}
	}

	_, err := f.reportAll(t, &usage.ReportArguments{
		Egress:  []usage.SpaceEgress{{Space: f.bucket, Hours: sent}},
		Objects: []usage.SpaceObjects{{Space: f.bucket, Hours: held}},
	})
	require.ErrorIs(t, err, rpc.ErrTooManyCounts)

	ok, err := f.reportAll(t, &usage.ReportArguments{Objects: []usage.SpaceObjects{{Space: f.bucket, Hours: held}}})
	require.NoError(t, err)
	require.Empty(t, ok.Warnings)
}
