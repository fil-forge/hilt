package metrics_test

import (
	"net/http"
	"net/url"
	"testing"
	"time"

	metricssvc "github.com/fil-forge/hilt/pkg/api/service/metrics"
	"github.com/fil-forge/hilt/pkg/client/upload"
	bucketmemory "github.com/fil-forge/hilt/pkg/store/bucket/memory"
	delegationmemory "github.com/fil-forge/hilt/pkg/store/delegation/memory"
	"github.com/fil-forge/hilt/pkg/store/tenant"
	tenantmemory "github.com/fil-forge/hilt/pkg/store/tenant/memory"
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
	subjects []did.DID
	args     []*metricscmds.SampleArguments
}

// setup wires the metrics service over memory stores against an in-process Sprue
// that serves /metrics/sample, mirroring production: one tenant whose secp256k1
// key is in the vault, owning one bucket that has issued the tenant top
// authority over itself. That root lives only in the delegation store, as
// bucket.Service.Create puts it there — the upload client's base proofs are the
// static set loaded from config and never contain it.
func setup(t *testing.T, opts ...metricssvc.Option) (*metricssvc.Service, did.DID, *sampled) {
	t.Helper()
	ctx := t.Context()
	tenants, buckets := tenantmemory.New(), bucketmemory.New()
	delegations, secrets := delegationmemory.New(), vaultmemory.New()

	signer, err := secp256k1.Generate()
	require.NoError(t, err)
	tenantID := signer.KeyDID()
	require.NoError(t, tenants.Add(ctx, tenantID, "tenant-1", tenantID, tenant.Active))
	require.NoError(t, secrets.Write(ctx, vault.TenantKeyPath(tenantID), signer.Bytes()))

	bucketSigner, err := ed25519.Generate()
	require.NoError(t, err)
	bucketID := bucketSigner.KeyDID()
	require.NoError(t, buckets.Add(ctx, bucketID, tenantID, "bucket-a"))
	root, err := delegation.Delegate(
		multikey.NewIssuer(bucketID, bucketSigner), tenantID, bucketID, command.Top(), delegation.WithNoExpiration())
	require.NoError(t, err)
	require.NoError(t, delegations.PutBatch(ctx, []ucan.Delegation{root}))

	sprueSigner, err := ed25519.Generate()
	require.NoError(t, err)
	sprue := multikey.NewIssuer(sprueSigner.KeyDID(), sprueSigner)

	seen := &sampled{}
	srv := server.NewHTTP(sprue)
	srv.Handle(metricscmds.Sample.Command, metricscmds.Sample.Handler(
		func(req *binding.Request[*metricscmds.SampleArguments], res *binding.Response[*metricscmds.SampleOK]) error {
			args := req.Task().Arguments()
			seen.subjects = append(seen.subjects, req.Task().Subject())
			seen.args = append(seen.args, args)
			return res.SetSuccess(&metricscmds.SampleOK{
				From: args.From, To: args.To, Window: args.Window,
				Samples: []metricscmds.SampleItem{{
					Timestamp: args.To, BytesStored: 1024, BytesIngested: 512, UploadCount: 3,
				}},
			})
		}))

	sprueURL, err := url.Parse("http://sprue.test")
	require.NoError(t, err)
	client, err := upload.NewClient(sprue.DID(), *sprueURL, multikey.NewIssuer(tenantID, signer),
		upload.WithHTTPClient(&http.Client{Transport: srv}))
	require.NoError(t, err)

	return metricssvc.New(zap.NewNop(), tenants, buckets, secrets, client, delegations, opts...), bucketID, seen
}

// A bucket's proof chain is rooted in the delegation the bucket issued at
// creation, which lives in the delegation store. Sampling must search that
// store, not the client's static config proofs, or every tenant's metrics fail
// before the request is made.
func TestSampleUsesThePersistedProofChain(t *testing.T) {
	svc, bucketID, seen := setup(t)
	from := time.Now().Add(-2 * time.Hour).UTC()

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
		svc, _, seen := setup(t, clock)
		samples, err := svc.Bucket(t.Context(), "tenant-1", "bucket-a", from, from.Add(time.Hour), time.Hour)
		require.NoError(t, err)
		require.Empty(t, samples)
		require.Empty(t, seen.args, "no invocation should reach the upload service")
	})

	t.Run("tenant", func(t *testing.T) {
		svc, _, seen := setup(t, clock)
		samples, err := svc.Tenant(t.Context(), "tenant-1", from, from.Add(time.Hour), time.Hour)
		require.NoError(t, err)
		require.Empty(t, samples)
		require.Empty(t, seen.args, "no invocation should reach the upload service")
	})
}

// A range straddling the present keeps the part that has already happened.
func TestRangeEndingInTheFutureIsTrimmedNotDropped(t *testing.T) {
	now := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	svc, _, seen := setup(t, metricssvc.WithClock(func() time.Time { return now }))
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
	svc, _, _ := setup(t)
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
	svc, _, seen := setup(t, metricssvc.WithClock(func() time.Time { return now }))
	from := now.Truncate(time.Second)

	samples, err := svc.Bucket(t.Context(), "tenant-1", "bucket-a", from, from.Add(time.Hour), time.Hour)
	require.NoError(t, err)
	require.Empty(t, samples)
	require.Empty(t, seen.args, "From would have equalled To on the wire")
}
