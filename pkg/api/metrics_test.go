package api_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/fil-forge/hilt/internal/testutil"
	"github.com/fil-forge/hilt/pkg/api"
	metricssvc "github.com/fil-forge/hilt/pkg/api/service/metrics"
	"github.com/fil-forge/hilt/pkg/client/upload"
	bucketmemory "github.com/fil-forge/hilt/pkg/store/bucket/memory"
	delegationmemory "github.com/fil-forge/hilt/pkg/store/delegation/memory"
	"github.com/fil-forge/hilt/pkg/store/tenant"
	tenantmemory "github.com/fil-forge/hilt/pkg/store/tenant/memory"
	vaultmemory "github.com/fil-forge/hilt/pkg/vault/memory"
	metricscmds "github.com/fil-forge/libforge/commands/metrics"
	"github.com/fil-forge/ucantone/did"
	"github.com/fil-forge/ucantone/did/plc"
	ucanerrors "github.com/fil-forge/ucantone/errors"
	"github.com/fil-forge/ucantone/multikey/secp256k1"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

// fakeSampler stands in for the upload service: these tests exercise the HTTP
// layer and the aggregation, not the UCAN round trip.
type fakeSampler struct {
	// series is the run to return per space. A space with no entry returns none.
	series map[did.DID][]metricscmds.SampleItem
	// err, when set, is returned instead.
	err error
}

func (f *fakeSampler) SampleUsage(_ context.Context, space did.DID, _, _ time.Time, _ time.Duration, _ ...upload.MethodOption) (*metricscmds.SampleOK, error) {
	if f.err != nil {
		return nil, f.err
	}
	return &metricscmds.SampleOK{Samples: f.series[space]}, nil
}

type metricsDeps struct {
	tenants     *tenantmemory.Store
	buckets     *bucketmemory.Store
	vault       *vaultmemory.Store
	sampler     *fakeSampler
	delegations *delegationmemory.Store
}

func newMetricsDeps(t *testing.T) *metricsDeps {
	t.Helper()
	return &metricsDeps{
		tenants:     tenantmemory.New(),
		buckets:     bucketmemory.New(),
		vault:       vaultmemory.New(),
		sampler:     &fakeSampler{series: map[did.DID][]metricscmds.SampleItem{}},
		delegations: delegationmemory.New(),
	}
}

func (d *metricsDeps) service(t *testing.T) *metricssvc.Service {
	t.Helper()
	return metricssvc.New(zap.NewNop(), d.tenants, d.buckets, d.vault, d.sampler, d.delegations)
}

// addMetricsTenant records a tenant with its signing key and the given buckets,
// returning the bucket DIDs in the order named.
func addMetricsTenant(t *testing.T, d *metricsDeps, externalID string, bucketNames ...string) []did.DID {
	t.Helper()
	ctx := t.Context()
	signer, err := secp256k1.Generate()
	require.NoError(t, err)
	key := signer.KeyDID()
	tenantID, _, err := plc.New(signer,
		plc.WithRotationKeys(key),
		plc.WithVerificationMethods(map[string]did.DID{"hilt": key}),
	)
	require.NoError(t, err)
	require.NoError(t, d.tenants.Add(ctx, tenantID, externalID, testutil.RandomDID(t), tenant.Active))
	require.NoError(t, d.vault.Write(ctx, "/tenant/"+tenantID.String(), signer.Bytes()))

	ids := make([]did.DID, 0, len(bucketNames))
	for _, name := range bucketNames {
		id := testutil.RandomDID(t)
		require.NoError(t, d.buckets.Add(ctx, id, tenantID, name))
		ids = append(ids, id)
	}
	return ids
}

// metricsTarget builds a metrics request path with a valid range and window.
func metricsTarget(path string) string {
	return path + "?from=2026-01-01T00:00:00Z&to=2026-01-01T02:00:00Z&window=1h"
}

func decodeMetrics(t *testing.T, rec *httptest.ResponseRecorder) api.Metrics {
	t.Helper()
	var body api.Metrics
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
	return body
}

func TestGetBucketMetricsHandler(t *testing.T) {
	t.Run("returns the bucket's series", func(t *testing.T) {
		d := newMetricsDeps(t)
		ids := addMetricsTenant(t, d, "tenant-1", "bucket-a")
		d.sampler.series[ids[0]] = []metricscmds.SampleItem{
			{Timestamp: 1767225600, BytesStored: 1024, BytesIngested: 1024, UploadCount: 2},
			{Timestamp: 1767229200, BytesStored: 2048, BytesIngested: 1024, UploadCount: 3},
		}
		e := serve(api.NewGetBucketMetricsHandler(zap.NewNop(), d.service(t)))

		rec := doRequest(t, e, http.MethodGet, metricsTarget("/tenants/tenant-1/buckets/bucket-a/metrics"), nil)
		require.Equal(t, http.StatusOK, rec.Code)

		body := decodeMetrics(t, rec)
		require.Len(t, body.Storage.Samples, 2)
		require.Equal(t, uint64(1024), body.Storage.Samples[0].BytesUsed)
		// The object count is the upload count the service reports.
		require.Equal(t, uint64(2), body.Storage.Samples[0].ObjectCount)
		require.Equal(t, uint64(3), body.Storage.Samples[1].ObjectCount)
		require.Equal(t, "2026-01-01T00:00:00Z", body.Storage.Samples[0].Timestamp.UTC().Format(time.RFC3339))

		require.Len(t, body.Ingress.Samples, 2)
		require.Equal(t, uint64(1024), body.Ingress.Samples[0].BytesIngested)

		// Egress has no source here, and says so rather than reporting zero.
		require.NotNil(t, body.Egress.Samples)
		require.Empty(t, body.Egress.Samples)
	})

	t.Run("a bucket of another tenant is not found", func(t *testing.T) {
		d := newMetricsDeps(t)
		addMetricsTenant(t, d, "tenant-1", "bucket-a")
		addMetricsTenant(t, d, "tenant-2", "bucket-b")
		e := serve(api.NewGetBucketMetricsHandler(zap.NewNop(), d.service(t)))

		rec := doRequest(t, e, http.MethodGet, metricsTarget("/tenants/tenant-1/buckets/bucket-b/metrics"), nil)
		require.Equal(t, http.StatusNotFound, rec.Code)
		require.Equal(t, "BucketNotFound", decodeError(t, rec).Code)
	})

	t.Run("unknown tenant", func(t *testing.T) {
		d := newMetricsDeps(t)
		e := serve(api.NewGetBucketMetricsHandler(zap.NewNop(), d.service(t)))

		rec := doRequest(t, e, http.MethodGet, metricsTarget("/tenants/missing/buckets/bucket-a/metrics"), nil)
		require.Equal(t, http.StatusNotFound, rec.Code)
		require.Equal(t, "TenantNotFound", decodeError(t, rec).Code)
	})
}

func TestGetTenantMetricsHandler(t *testing.T) {
	t.Run("sums every bucket the tenant holds", func(t *testing.T) {
		d := newMetricsDeps(t)
		ids := addMetricsTenant(t, d, "tenant-1", "bucket-a", "bucket-b")
		d.sampler.series[ids[0]] = []metricscmds.SampleItem{
			{Timestamp: 1767225600, BytesStored: 1000, BytesIngested: 10, UploadCount: 1},
		}
		d.sampler.series[ids[1]] = []metricscmds.SampleItem{
			{Timestamp: 1767225600, BytesStored: 500, BytesIngested: 5, UploadCount: 2},
		}
		e := serve(api.NewGetTenantMetricsHandler(zap.NewNop(), d.service(t)))

		rec := doRequest(t, e, http.MethodGet, metricsTarget("/tenants/tenant-1/metrics"), nil)
		require.Equal(t, http.StatusOK, rec.Code)

		body := decodeMetrics(t, rec)
		// One grid, so the two buckets fold into one sample carrying both.
		require.Len(t, body.Storage.Samples, 1)
		require.Equal(t, uint64(1500), body.Storage.Samples[0].BytesUsed)
		require.Equal(t, uint64(3), body.Storage.Samples[0].ObjectCount)
		require.Len(t, body.Ingress.Samples, 1)
		require.Equal(t, uint64(15), body.Ingress.Samples[0].BytesIngested)
	})

	t.Run("a tenant with no buckets reports nothing", func(t *testing.T) {
		d := newMetricsDeps(t)
		addMetricsTenant(t, d, "tenant-1")
		e := serve(api.NewGetTenantMetricsHandler(zap.NewNop(), d.service(t)))

		rec := doRequest(t, e, http.MethodGet, metricsTarget("/tenants/tenant-1/metrics"), nil)
		require.Equal(t, http.StatusOK, rec.Code)

		body := decodeMetrics(t, rec)
		require.Empty(t, body.Storage.Samples)
		require.Empty(t, body.Ingress.Samples)
		require.Empty(t, body.Egress.Samples)
	})

	t.Run("unknown tenant", func(t *testing.T) {
		d := newMetricsDeps(t)
		e := serve(api.NewGetTenantMetricsHandler(zap.NewNop(), d.service(t)))

		rec := doRequest(t, e, http.MethodGet, metricsTarget("/tenants/missing/metrics"), nil)
		require.Equal(t, http.StatusNotFound, rec.Code)
		require.Equal(t, "TenantNotFound", decodeError(t, rec).Code)
	})
}

// The range and window are the caller's to get right, so a malformed one is a
// bad request and never reaches the upload service.
func TestMetricsQueryValidation(t *testing.T) {
	for name, tc := range map[string]struct {
		query string
		code  string
	}{
		"missing from":      {"?to=2026-01-01T02:00:00Z&window=1h", "InvalidRange"},
		"missing to":        {"?from=2026-01-01T00:00:00Z&window=1h", "InvalidRange"},
		"missing window":    {"?from=2026-01-01T00:00:00Z&to=2026-01-01T02:00:00Z", "InvalidWindow"},
		"unparseable from":  {"?from=yesterday&to=2026-01-01T02:00:00Z&window=1h", "InvalidRange"},
		"reversed range":    {"?from=2026-01-01T02:00:00Z&to=2026-01-01T00:00:00Z&window=1h", "InvalidRange"},
		"empty range":       {"?from=2026-01-01T00:00:00Z&to=2026-01-01T00:00:00Z&window=1h", "InvalidRange"},
		"window in minutes": {"?from=2026-01-01T00:00:00Z&to=2026-01-01T02:00:00Z&window=30m", "InvalidWindow"},
		"zero window":       {"?from=2026-01-01T00:00:00Z&to=2026-01-01T02:00:00Z&window=0h", "InvalidWindow"},
	} {
		t.Run(name, func(t *testing.T) {
			d := newMetricsDeps(t)
			addMetricsTenant(t, d, "tenant-1", "bucket-a")
			e := serve(api.NewGetTenantMetricsHandler(zap.NewNop(), d.service(t)))

			rec := doRequest(t, e, http.MethodGet, "/tenants/tenant-1/metrics"+tc.query, nil)
			require.Equal(t, http.StatusBadRequest, rec.Code)
			require.Equal(t, tc.code, decodeError(t, rec).Code)
		})
	}
}

// A failure the upload service names travels back with its name, so the status
// can say whether the caller should fix the request or retry it.
func TestMetricsUpstreamFailures(t *testing.T) {
	for name, tc := range map[string]struct {
		err    error
		status int
	}{
		"unusable range": {
			ucanerrors.New(metricscmds.InvalidRangeErrorName, "range is not usable"),
			http.StatusBadRequest,
		},
		"too many samples": {
			ucanerrors.New(metricscmds.TooManySamplesErrorName, "narrow the range"),
			http.StatusBadRequest,
		},
		"unstable reading": {
			ucanerrors.New(metricscmds.UsageUnstableErrorName, "usage changed throughout the read"),
			http.StatusServiceUnavailable,
		},
		"range too busy": {
			ucanerrors.New(metricscmds.RangeTooBusyErrorName, "too many changes"),
			http.StatusServiceUnavailable,
		},
	} {
		t.Run(name, func(t *testing.T) {
			d := newMetricsDeps(t)
			addMetricsTenant(t, d, "tenant-1", "bucket-a")
			d.sampler.err = tc.err
			e := serve(api.NewGetTenantMetricsHandler(zap.NewNop(), d.service(t)))

			rec := doRequest(t, e, http.MethodGet, metricsTarget("/tenants/tenant-1/metrics"), nil)
			require.Equal(t, tc.status, rec.Code)
			var named ucanerrors.Named
			require.ErrorAs(t, tc.err, &named)
			require.Equal(t, named.Name(), decodeError(t, rec).Code)
		})
	}

	t.Run("an unnamed failure is opaque", func(t *testing.T) {
		d := newMetricsDeps(t)
		addMetricsTenant(t, d, "tenant-1", "bucket-a")
		d.sampler.err = fmt.Errorf("dial tcp 10.0.0.1:443: connection refused")
		e := serve(api.NewGetTenantMetricsHandler(zap.NewNop(), d.service(t)))

		rec := doRequest(t, e, http.MethodGet, metricsTarget("/tenants/tenant-1/metrics"), nil)
		require.Equal(t, http.StatusInternalServerError, rec.Code)
		require.JSONEq(t, `{"message":"internal error"}`, rec.Body.String())
	})
}
