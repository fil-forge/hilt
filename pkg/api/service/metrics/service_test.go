package metrics_test

import (
	"net/http"
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/fil-forge/hilt/internal/testutil"
	metricssvc "github.com/fil-forge/hilt/pkg/api/service/metrics"
	"github.com/fil-forge/hilt/pkg/client/upload"
	bucketpostgres "github.com/fil-forge/hilt/pkg/store/bucket/postgres"
	delegationpostgres "github.com/fil-forge/hilt/pkg/store/delegation/postgres"
	providerpostgres "github.com/fil-forge/hilt/pkg/store/provider/postgres"
	"github.com/fil-forge/hilt/pkg/store/tenant"
	tenantpostgres "github.com/fil-forge/hilt/pkg/store/tenant/postgres"
	usagestore "github.com/fil-forge/hilt/pkg/store/usage"
	usagepostgres "github.com/fil-forge/hilt/pkg/store/usage/postgres"
	"github.com/fil-forge/hilt/pkg/vault"
	vaultmemory "github.com/fil-forge/hilt/pkg/vault/memory"
	metricscmds "github.com/fil-forge/libforge/commands/metrics"
	"github.com/fil-forge/ucantone/binding"
	"github.com/fil-forge/ucantone/did"
	"github.com/fil-forge/ucantone/multikey"
	"github.com/fil-forge/ucantone/multikey/ed25519"
	"github.com/fil-forge/ucantone/multikey/secp256k1"
	"github.com/fil-forge/ucantone/server"
	"github.com/fil-forge/ucantone/ucan"
	"github.com/fil-forge/ucantone/ucan/command"
	"github.com/fil-forge/ucantone/ucan/delegation"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

// sampled records the subject of each /metrics/sample invocation the stub Sprue
// served, so a test can tell which space was asked about.
type sampled struct {
	// mu guards the records: a tenant query samples its buckets concurrently.
	mu       sync.Mutex
	subjects []did.DID
	args     []*metricscmds.SampleArguments
	// series overrides what a space's call returns, standing in for the upload
	// service having clamped that call against a different instant.
	series map[did.DID][]metricscmds.SampleItem
	// usage is the store the service reads the gateways' counts from.
	usage *usagepostgres.Store
	// buckets says which provider and tenant a bucket's counts belong to.
	buckets *bucketpostgres.Store
}

// setup wires the metrics service against an in-process Sprue
// that serves /metrics/sample, mirroring production: one tenant whose secp256k1
// key is in the vault, owning two buckets, each of which has issued the
// tenant top authority over itself. That root lives only in the delegation store, as
// bucket.Service.Create puts it there — the upload client's base proofs are the
// static set loaded from config and never contain it.
func setup(t *testing.T, opts ...metricssvc.Option) (*metricssvc.Service, did.DID, did.DID, *sampled) {
	t.Helper()
	pool := testutil.PostgresOrSkip(t)
	ctx := t.Context()
	tenants, buckets := tenantpostgres.New(pool), bucketpostgres.New(pool)
	delegations, secrets := delegationpostgres.New(pool), vaultmemory.New()

	signer, err := secp256k1.Generate()
	require.NoError(t, err)
	tenantID := signer.KeyDID()
	require.NoError(t, tenants.Add(ctx, tenantID, "tenant-1", tenant.Active))
	require.NoError(t, secrets.Write(ctx, vault.TenantKeyPath(tenantID), signer.Bytes()))
	providerID := testutil.RandomDID(t)
	require.NoError(t, providerpostgres.New(pool).Add(ctx, providerID, "region-1", nil))

	bucketSigner, err := ed25519.Generate()
	require.NoError(t, err)
	bucketID := bucketSigner.KeyDID()
	require.NoError(t, buckets.Add(ctx, bucketID, tenantID, providerID, "bucket-a"))
	root, err := delegation.Delegate(
		multikey.NewIssuer(bucketID, bucketSigner), tenantID, bucketID, command.Top(), delegation.WithNoExpiration())
	require.NoError(t, err)
	require.NoError(t, delegations.PutBatch(ctx, []ucan.Delegation{root}))

	bucketBSigner, err := ed25519.Generate()
	require.NoError(t, err)
	bucketBID := bucketBSigner.KeyDID()
	require.NoError(t, buckets.Add(ctx, bucketBID, tenantID, providerID, "bucket-b"))
	rootB, err := delegation.Delegate(
		multikey.NewIssuer(bucketBID, bucketBSigner), tenantID, bucketBID, command.Top(), delegation.WithNoExpiration())
	require.NoError(t, err)
	require.NoError(t, delegations.PutBatch(ctx, []ucan.Delegation{rootB}))

	sprueSigner, err := ed25519.Generate()
	require.NoError(t, err)
	sprue := multikey.NewIssuer(sprueSigner.KeyDID(), sprueSigner)

	seen := &sampled{series: map[did.DID][]metricscmds.SampleItem{}, usage: usagepostgres.New(pool), buckets: buckets}
	srv := server.NewHTTP(sprue)
	srv.Handle(metricscmds.Sample.Command, metricscmds.Sample.Handler(
		func(req *binding.Request[*metricscmds.SampleArguments], res *binding.Response[*metricscmds.SampleOK]) error {
			args := req.Task().Arguments()
			subject := req.Task().Subject()
			seen.mu.Lock()
			defer seen.mu.Unlock()
			seen.subjects = append(seen.subjects, subject)
			seen.args = append(seen.args, args)
			items, ok := seen.series[subject]
			if !ok {
				items = []metricscmds.SampleItem{{
					Timestamp: args.To, BytesStored: 1024, BytesIngested: 512, UploadCount: 3,
				}}
			}
			return res.SetSuccess(&metricscmds.SampleOK{
				From: args.From, To: args.To, Window: args.Window, Samples: items,
			})
		}))

	sprueURL, err := url.Parse("http://sprue.test")
	require.NoError(t, err)
	client, err := upload.NewClient(sprue.DID(), *sprueURL, multikey.NewIssuer(tenantID, signer),
		upload.WithHTTPClient(&http.Client{Transport: srv}))
	require.NoError(t, err)

	return metricssvc.New(zap.NewNop(), tenants, buckets, secrets, client, delegations, seen.usage, opts...), bucketID, bucketBID, seen
}

// A bucket's proof chain is rooted in the delegation the bucket issued at
// creation, which lives in the delegation store. Sampling must search that
// store, not the client's static config proofs, or every tenant's metrics fail
// before the request is made.
func TestSampleUsesThePersistedProofChain(t *testing.T) {
	svc, bucketID, _, seen := setup(t)
	from := time.Now().Add(-2 * time.Hour).UTC()
	reportObjects(t, seen, bucketID, from.Truncate(time.Hour), 3, 0)

	samples, err := svc.Bucket(t.Context(), "tenant-1", "bucket-a", from, from.Add(time.Hour), time.Hour)
	require.NoError(t, err)
	require.Len(t, samples, 1)
	require.Equal(t, uint64(1024), samples[0].BytesStored)
	require.Equal(t, uint64(3), samples[0].ObjectCount)
	require.Equal(t, []did.DID{bucketID}, seen.subjects)
}

// A range lying wholly in the future is a valid question with no data behind it
// yet. Clamping its end to the present puts that end before its start, and the
// upload service rejects an inverted range, so the series has to be answered
// here instead of being asked for.
func TestFutureOnlyRangeReturnsNoSamplesWithoutAsking(t *testing.T) {
	now := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	clock := metricssvc.WithClock(func() time.Time { return now })
	from := now.Add(24 * time.Hour)

	t.Run("bucket", func(t *testing.T) {
		svc, _, _, seen := setup(t, clock)
		samples, err := svc.Bucket(t.Context(), "tenant-1", "bucket-a", from, from.Add(time.Hour), time.Hour)
		require.NoError(t, err)
		require.Empty(t, samples)
		require.Empty(t, seen.args, "no invocation should reach the upload service")
	})

	t.Run("tenant", func(t *testing.T) {
		svc, _, _, seen := setup(t, clock)
		samples, err := svc.Tenant(t.Context(), "tenant-1", from, from.Add(time.Hour), time.Hour)
		require.NoError(t, err)
		require.Empty(t, samples)
		require.Empty(t, seen.args, "no invocation should reach the upload service")
	})
}

// A range straddling the present keeps the part that has already happened.
func TestRangeEndingInTheFutureIsTrimmedNotDropped(t *testing.T) {
	now := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	svc, _, _, seen := setup(t, metricssvc.WithClock(func() time.Time { return now }))
	from := now.Add(-time.Hour)

	samples, err := svc.Bucket(t.Context(), "tenant-1", "bucket-a", from, from.Add(24*time.Hour), time.Hour)
	require.NoError(t, err)
	require.Len(t, samples, 1)
	require.Len(t, seen.args, 1)
	require.Greater(t, seen.args[0].To, seen.args[0].From)
	require.Equal(t, now.Unix(), seen.args[0].To, "the end should be clamped to the present")
}

// An unknown bucket is still a 404, even when the range would have been empty:
// the resource genuinely does not exist, and that is the more specific answer.
func TestUnknownBucketOutranksAnEmptyRange(t *testing.T) {
	svc, _, _, _ := setup(t)
	from := time.Now().Add(24 * time.Hour).UTC()

	_, err := svc.Bucket(t.Context(), "tenant-1", "nope", from, from.Add(time.Hour), time.Hour)
	require.ErrorIs(t, err, metricssvc.ErrBucketNotFound)
}

// The wire carries whole Unix seconds, so a range finer than that collapses on
// the way out. Resolving the bounds here means the API accepts exactly the
// ranges it can forward, and a caller gets a reason rather than an upstream
// rejection it cannot see.
func TestParseRangeResolvesBoundsToWholeSeconds(t *testing.T) {
	t.Run("rejects an interval inside one second", func(t *testing.T) {
		_, _, _, err := metricssvc.ParseRange("2026-01-01T00:00:00.1Z", "2026-01-01T00:00:00.9Z", "1h")
		require.ErrorIs(t, err, metricssvc.ErrInvalidRange)
	})

	t.Run("keeps an interval that still spans a second", func(t *testing.T) {
		from, to, _, err := metricssvc.ParseRange("2026-01-01T00:00:00.9Z", "2026-01-01T00:00:01.1Z", "1h")
		require.NoError(t, err)
		require.Equal(t, int64(1767225600), from.Unix())
		require.Equal(t, int64(1767225601), to.Unix())
		require.True(t, to.After(from))
	})

	t.Run("accepts a zero fraction", func(t *testing.T) {
		from, to, _, err := metricssvc.ParseRange("2026-01-01T00:00:00.000Z", "2026-01-01T01:00:00.000Z", "1h")
		require.NoError(t, err)
		require.True(t, to.After(from))
	})
}

// The present carries sub-second precision the wire does not, so a range ending
// inside the current second must not be forwarded with equal bounds.
func TestRangeEndingInsideTheCurrentSecondIsNotAsked(t *testing.T) {
	// Part way through a second, with the range starting on that second's edge.
	now := time.Date(2026, 1, 1, 12, 0, 0, 500_000_000, time.UTC)
	svc, _, _, seen := setup(t, metricssvc.WithClock(func() time.Time { return now }))
	from := now.Truncate(time.Second)

	samples, err := svc.Bucket(t.Context(), "tenant-1", "bucket-a", from, from.Add(time.Hour), time.Hour)
	require.NoError(t, err)
	require.Empty(t, samples)
	require.Empty(t, seen.args, "From would have equalled To on the wire")
}

// The upload service ends a range at its own clock. If this service's clock runs
// ahead, each bucket's call is clamped against a different instant and only the
// final bucket of each run moves. Summing those tails by timestamp would publish
// an instant holding one bucket's bytes as the tenant's total — a reported drop
// in usage where there was none.
func TestTenantSumsOnlyInstantsEveryBucketReported(t *testing.T) {
	now := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	svc, bucketA, bucketB, seen := setup(t, metricssvc.WithClock(func() time.Time { return now }))
	from := now.Add(-2 * time.Hour)
	aligned := from.Add(time.Hour).Unix()

	// Both runs agree on the aligned bucket and part ways on the tail: one was
	// clamped a second later than the other.
	seen.series[bucketA] = []metricscmds.SampleItem{
		{Timestamp: aligned, BytesStored: 100, BytesIngested: 10, UploadCount: 1},
		{Timestamp: now.Unix(), BytesStored: 200, BytesIngested: 20, UploadCount: 2},
	}
	seen.series[bucketB] = []metricscmds.SampleItem{
		{Timestamp: aligned, BytesStored: 1000, BytesIngested: 100, UploadCount: 10},
		{Timestamp: now.Add(-time.Second).Unix(), BytesStored: 2000, BytesIngested: 200, UploadCount: 20},
	}

	reportObjects(t, seen, bucketA, from, 1, 0)
	reportObjects(t, seen, bucketB, from, 12, 2)

	samples, err := svc.Tenant(t.Context(), "tenant-1", from, now, time.Hour)
	require.NoError(t, err)

	require.Len(t, samples, 1, "only the instant both buckets reported is reportable")
	require.Equal(t, aligned, samples[0].End.Unix())
	require.Equal(t, uint64(1100), samples[0].BytesStored)
	require.Equal(t, uint64(110), samples[0].BytesIngested)
	require.Equal(t, uint64(11), samples[0].ObjectCount)
}

// The ordinary case: every bucket answers the same grid, so nothing is trimmed.
func TestTenantSumsAlignedRunsWhole(t *testing.T) {
	now := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	svc, bucketA, bucketB, seen := setup(t, metricssvc.WithClock(func() time.Time { return now }))
	from := now.Add(-2 * time.Hour)
	first, second := from.Add(time.Hour).Unix(), now.Unix()

	seen.series[bucketA] = []metricscmds.SampleItem{
		{Timestamp: first, BytesStored: 100, BytesIngested: 10, UploadCount: 1},
		{Timestamp: second, BytesStored: 200, BytesIngested: 20, UploadCount: 2},
	}
	seen.series[bucketB] = []metricscmds.SampleItem{
		{Timestamp: first, BytesStored: 1000, BytesIngested: 100, UploadCount: 10},
		{Timestamp: second, BytesStored: 2000, BytesIngested: 200, UploadCount: 20},
	}

	reportObjects(t, seen, bucketA, from, 1, 0)
	reportObjects(t, seen, bucketA, from.Add(time.Hour), 3, 1)
	reportObjects(t, seen, bucketB, from, 10, 0)
	reportObjects(t, seen, bucketB, from.Add(time.Hour), 25, 5)

	samples, err := svc.Tenant(t.Context(), "tenant-1", from, now, time.Hour)
	require.NoError(t, err)

	require.Len(t, samples, 2)
	require.Equal(t, uint64(1100), samples[0].BytesStored)
	require.Equal(t, uint64(2200), samples[1].BytesStored)
	require.Equal(t, uint64(11), samples[0].ObjectCount)
	require.Equal(t, uint64(22), samples[1].ObjectCount)
}

// reportObjects stores what a gateway would report of a bucket's objects as
// of an hour: how many it has ever gained and lost.
func reportObjects(t *testing.T, seen *sampled, bucket did.DID, hour time.Time, added, removed uint64) {
	t.Helper()
	// Reported by the bucket's own provider for its own tenant, which the
	// counts' foreign keys require.
	owner, err := seen.buckets.Owner(t.Context(), bucket)
	require.NoError(t, err)
	require.NoError(t, seen.usage.SetObjects(t.Context(), owner.Provider, []usagestore.ObjectCount{
		{Bucket: bucket, Tenant: owner.Tenant, Hour: hour, Added: added, Removed: removed},
	}))
}

// A bucket's object count is what its gateway reported, held from the hour
// of each report until the next. The upload service's own count of uploads
// is not read.
func TestObjectCountComesFromTheGatewaysReports(t *testing.T) {
	now := time.Date(2026, 1, 1, 12, 30, 0, 0, time.UTC)
	svc, bucketA, _, seen := setup(t, metricssvc.WithClock(func() time.Time { return now }))
	from := time.Date(2026, 1, 1, 8, 0, 0, 0, time.UTC)
	hour := func(h int) time.Time { return time.Date(2026, 1, 1, h, 0, 0, 0, time.UTC) }

	items := []metricscmds.SampleItem{}
	for _, end := range []time.Time{hour(9), hour(10), hour(11), hour(12), now} {
		items = append(items, metricscmds.SampleItem{Timestamp: end.Unix(), UploadCount: 999})
	}
	seen.series[bucketA] = items

	// Reported the day before, so it is what the bucket holds as the range opens.
	reportObjects(t, seen, bucketA, hour(8).Add(-24*time.Hour), 5, 1)
	// Nothing changed from 08:00 to 10:00. The bucket changed in the hour from 10:00.
	reportObjects(t, seen, bucketA, hour(10), 9, 2)
	// More recorded lost than gained reads as an empty bucket.
	reportObjects(t, seen, bucketA, hour(11), 9, 12)
	// The hour in progress, as far as it has been reported.
	reportObjects(t, seen, bucketA, hour(12), 20, 12)

	samples, err := svc.Bucket(t.Context(), "tenant-1", "bucket-a", from, now, time.Hour)
	require.NoError(t, err)
	got := []uint64{}
	for _, s := range samples {
		got = append(got, s.ObjectCount)
	}
	require.Equal(t, []uint64{4, 4, 7, 0, 8}, got)
}

// A bucket no gateway has reported on holds no objects, whatever the upload
// service counts.
func TestObjectCountIsZeroWithoutAReport(t *testing.T) {
	now := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	svc, _, _, _ := setup(t, metricssvc.WithClock(func() time.Time { return now }))

	samples, err := svc.Bucket(t.Context(), "tenant-1", "bucket-a", now.Add(-time.Hour), now, time.Hour)
	require.NoError(t, err)
	require.Len(t, samples, 1)
	require.Equal(t, uint64(1024), samples[0].BytesStored)
	require.Zero(t, samples[0].ObjectCount)
}
