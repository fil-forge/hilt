package revocationqueue_test

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	htestutil "github.com/fil-forge/hilt/internal/testutil"
	"github.com/fil-forge/hilt/pkg/grant"
	"github.com/fil-forge/hilt/pkg/store/revocation"
	revocationpostgres "github.com/fil-forge/hilt/pkg/store/revocation/postgres"
	tenantstore "github.com/fil-forge/hilt/pkg/store/tenant"
	tenantpostgres "github.com/fil-forge/hilt/pkg/store/tenant/postgres"
	"github.com/fil-forge/hilt/pkg/tasks"
	"github.com/fil-forge/hilt/pkg/tasks/revocationqueue"
	"github.com/fil-forge/hilt/pkg/vault"
	vaultmemory "github.com/fil-forge/hilt/pkg/vault/memory"
	"github.com/fil-forge/libforge/taskrunner"
	"github.com/fil-forge/libforge/testutil"
	"github.com/fil-forge/ucantone/did"
	"github.com/fil-forge/ucantone/multikey"
	"github.com/fil-forge/ucantone/multikey/secp256k1"
	"github.com/fil-forge/ucantone/ucan"
	"github.com/ipfs/go-cid"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/attribute"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
)

// flakySwarf is a revocation service that fails every publish while failing
// is set, and counts the publishes it was asked for either way.
type flakySwarf struct {
	htestutil.FakeSwarf
	failing  atomic.Bool
	attempts atomic.Int64
}

func (f *flakySwarf) PublishBatch(ctx context.Context, revoker ucan.Issuer, revoked []ucan.Delegation) error {
	f.attempts.Add(1)
	if f.failing.Load() {
		return errors.New("revocation service unavailable")
	}
	return f.FakeSwarf.PublishBatch(ctx, revoker, revoked)
}

type deps struct {
	runner  *taskrunner.Runner
	queue   *revocationqueue.Queue
	owed    revocation.Store
	secrets *vaultmemory.Store
	swarf   *flakySwarf
	// tenant has a row in the tenant table and its signing key in the vault.
	tenant ucan.Issuer
}

func setup(t *testing.T) deps {
	t.Helper()
	ctx := t.Context()
	pool := htestutil.PostgresOrSkip(t)

	signer, err := secp256k1.Generate()
	require.NoError(t, err)
	tenantID := signer.KeyDID()
	require.NoError(t, tenantpostgres.New(pool).Add(ctx, tenantID, "tenant-1", tenantstore.Active))

	d := deps{
		owed:    revocationpostgres.New(pool),
		secrets: vaultmemory.New(),
		swarf:   &flakySwarf{},
		tenant:  multikey.NewIssuer(tenantID, signer),
	}
	require.NoError(t, d.secrets.Write(ctx, vault.TenantKeyPath(tenantID), signer.Bytes()))
	d.runner = htestutil.StartTaskRunner(t, pool, func(r *taskrunner.Runner) {
		d.queue, err = revocationqueue.New(r, revocationqueue.Deps{
			Owed:      d.owed,
			Secrets:   d.secrets,
			Publisher: d.swarf,
			// Retries come round within the test's patience.
			PublishRetry: taskrunner.RetryPolicy{First: 20 * time.Millisecond, Max: 50 * time.Millisecond, Multiplier: 2},
		})
		require.NoError(t, err)
	})
	return d
}

// issue returns n delegations issued by the tenant, each to a different key,
// expiring at expiresAt when it is set.
func issue(t *testing.T, tenant ucan.Issuer, n int, expiresAt *time.Time) []ucan.Delegation {
	t.Helper()
	var out []ucan.Delegation
	for len(out) < n {
		dels, err := grant.Issue(tenant, testutil.RandomDID(t), []did.DID{testutil.RandomDID(t)}, []string{"s3:GetObject"}, expiresAt)
		require.NoError(t, err)
		require.NotEmpty(t, dels)
		out = append(out, dels...)
	}
	return out[:n]
}

func links(dels []ucan.Delegation) []cid.Cid {
	out := make([]cid.Cid, len(dels))
	for i, d := range dels {
		out[i] = d.Link()
	}
	return out
}

// owe records the delegations as revocations the tenant owes and queues the
// tasks that publish them, as a change to the tenant does.
func (d deps) owe(t *testing.T, dels []ucan.Delegation) []taskrunner.TaskID {
	t.Helper()
	require.NoError(t, d.owed.Add(t.Context(), d.tenant.DID(), dels))
	ids, err := d.runner.SubmitAll(t.Context(), revocationqueue.PublishSpecs(d.tenant.DID(), len(dels)))
	require.NoError(t, err)
	return ids
}

// finish waits for the tasks and returns how each ended.
func (d deps) finish(t *testing.T, ids []taskrunner.TaskID) map[taskrunner.TaskID]taskrunner.Completion {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), htestutil.WaitTimeout)
	defer cancel()
	ended, err := d.runner.WaitAll(ctx, tasks.QueueRevocation, ids...)
	require.NoError(t, err)
	return ended
}

func (d deps) count(t *testing.T) int64 {
	t.Helper()
	stats, err := d.owed.Stats(t.Context())
	require.NoError(t, err)
	return stats.Count
}

func TestPublishSpecs(t *testing.T) {
	tenant := testutil.RandomDID(t)
	for owed, want := range map[int]int{
		-1:                               0,
		0:                                0,
		1:                                1,
		revocationqueue.BatchSize:        1,
		revocationqueue.BatchSize + 1:    2,
		3 * revocationqueue.BatchSize:    3,
		3*revocationqueue.BatchSize + 17: 4,
	} {
		specs := revocationqueue.PublishSpecs(tenant, owed)
		require.Len(t, specs, want, "%d owed", owed)
		for _, s := range specs {
			require.Equal(t, taskrunner.Spec{Queue: "queue-revocation", Subject: tenant.String(), Action: "publish"}, s)
		}
	}
}

func TestPublish(t *testing.T) {
	t.Run("publishes a batch signed by the tenant and deletes its rows", func(t *testing.T) {
		d := setup(t)
		dels := issue(t, d.tenant, 3, nil)
		ids := d.owe(t, dels)
		require.Len(t, ids, 1)

		for _, c := range d.finish(t, ids) {
			require.NoError(t, c.Err)
		}
		batches := d.swarf.Batches()
		require.Len(t, batches, 1, "one request for the whole batch")
		require.ElementsMatch(t, links(dels), d.swarf.Revoked())
		for _, r := range batches[0] {
			require.Equal(t, d.tenant.DID(), r.Revoker)
		}
		require.Zero(t, d.count(t))
	})

	t.Run("drains more than one batch, one task each", func(t *testing.T) {
		d := setup(t)
		dels := issue(t, d.tenant, 2*revocationqueue.BatchSize+1, nil)
		ids := d.owe(t, dels)
		require.Len(t, ids, 3)

		for _, c := range d.finish(t, ids) {
			require.NoError(t, c.Err)
		}
		var sizes []int
		for _, b := range d.swarf.Batches() {
			sizes = append(sizes, len(b))
		}
		require.Equal(t, []int{revocationqueue.BatchSize, revocationqueue.BatchSize, 1}, sizes)
		require.ElementsMatch(t, links(dels), d.swarf.Revoked(), "every delegation is revoked once")
		require.Zero(t, d.count(t))
	})

	t.Run("a task with nothing owed publishes nothing", func(t *testing.T) {
		d := setup(t)
		ids, err := d.runner.SubmitAll(t.Context(), revocationqueue.PublishSpecs(d.tenant.DID(), 1))
		require.NoError(t, err)
		for _, c := range d.finish(t, ids) {
			require.NoError(t, c.Err)
		}
		require.Zero(t, d.swarf.attempts.Load())
	})

	t.Run("a failed publish leaves the rows and is retried until it succeeds", func(t *testing.T) {
		d := setup(t)
		d.swarf.failing.Store(true)
		dels := issue(t, d.tenant, 2, nil)
		ids := d.owe(t, dels)

		// Several attempts fail, and the rows stay owed throughout.
		require.Eventually(t, func() bool { return d.swarf.attempts.Load() >= 3 }, htestutil.WaitTimeout, 10*time.Millisecond)
		require.EqualValues(t, 2, d.count(t))
		require.Empty(t, d.swarf.Revoked())
		pending, err := d.runner.Pending(t.Context(), tasks.QueueRevocation, []string{d.tenant.DID().String()})
		require.NoError(t, err)
		require.Equal(t, ids, pending[d.tenant.DID().String()], "the task is still pending, not failed")

		d.swarf.failing.Store(false)
		for _, c := range d.finish(t, ids) {
			require.NoError(t, c.Err)
		}
		require.ElementsMatch(t, links(dels), d.swarf.Revoked())
		require.Zero(t, d.count(t))
	})

	t.Run("fails for good when the tenant's key is not in the vault", func(t *testing.T) {
		d := setup(t)
		require.NoError(t, d.secrets.Delete(t.Context(), vault.TenantKeyPath(d.tenant.DID())))
		ids := d.owe(t, issue(t, d.tenant, 2, nil))

		// The action retries without limit, so the task ending at all means
		// it was failed for good.
		for _, c := range d.finish(t, ids) {
			var failed *taskrunner.HandlerError
			require.ErrorAs(t, c.Err, &failed)
			require.Contains(t, failed.Message, "signing key is not in the vault")
		}
		failed, err := d.runner.ListFailed(t.Context(), tasks.QueueRevocation, d.tenant.DID().String(), taskrunner.TaskID{}, 10)
		require.NoError(t, err)
		require.Len(t, failed, 1)
		require.Zero(t, d.swarf.attempts.Load())
		require.EqualValues(t, 2, d.count(t), "the rows stay owed")
	})

	t.Run("drops expired delegations without publishing them", func(t *testing.T) {
		d := setup(t)
		past := time.Now().Add(-time.Hour)
		expired, live := issue(t, d.tenant, 2, &past), issue(t, d.tenant, 1, nil)
		ids := d.owe(t, append(expired, live...))

		for _, c := range d.finish(t, ids) {
			require.NoError(t, c.Err)
		}
		require.Equal(t, links(live), d.swarf.Revoked())
		require.Zero(t, d.count(t))
	})

	t.Run("drops a batch that has all expired without the tenant's key", func(t *testing.T) {
		d := setup(t)
		require.NoError(t, d.secrets.Delete(t.Context(), vault.TenantKeyPath(d.tenant.DID())))
		past := time.Now().Add(-time.Hour)
		ids := d.owe(t, issue(t, d.tenant, 2, &past))

		for _, c := range d.finish(t, ids) {
			require.NoError(t, c.Err)
		}
		require.Zero(t, d.swarf.attempts.Load())
		require.Zero(t, d.count(t))
	})
}

func TestMetrics(t *testing.T) {
	d := setup(t)
	reader := sdkmetric.NewManualReader()
	registration, err := d.queue.RegisterMetrics(sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader)))
	require.NoError(t, err)

	collect := func() (owed int64, age float64) {
		t.Helper()
		var rm metricdata.ResourceMetrics
		require.NoError(t, reader.Collect(t.Context(), &rm))
		seen := 0
		for _, sm := range rm.ScopeMetrics {
			for _, m := range sm.Metrics {
				switch m.Name {
				case "hilt.revocations.owed":
					points := m.Data.(metricdata.Gauge[int64]).DataPoints
					require.Len(t, points, 1)
					require.Equal(t, attribute.NewSet(), points[0].Attributes)
					owed = points[0].Value
					seen++
				case "hilt.revocations.oldest_owed_age":
					points := m.Data.(metricdata.Gauge[float64]).DataPoints
					require.Len(t, points, 1)
					age = points[0].Value
					seen++
				}
			}
		}
		require.Equal(t, 2, seen, "both gauges report")
		return owed, age
	}

	owed, age := collect()
	require.Zero(t, owed)
	require.Zero(t, age)

	// Owed with the revocation service down, so the rows stay.
	d.swarf.failing.Store(true)
	d.owe(t, issue(t, d.tenant, 3, nil))
	time.Sleep(50 * time.Millisecond)
	owed, age = collect()
	require.EqualValues(t, 3, owed)
	require.Greater(t, age, 0.0)

	require.NoError(t, registration.Unregister())
}
