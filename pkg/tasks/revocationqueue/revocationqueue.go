// Package revocationqueue is queue-revocation: the publishing of the
// revocations a tenant owes, on the subject of the tenant's DID.
//
// A change to a tenant's authority records the delegations it withdraws as
// revocations owed and queues queue-revocation.publish tasks for them, one
// for each batch of [BatchSize] it recorded ([PublishSpecs]). A task
// publishes the tenant's oldest batch and deletes its rows in the task's
// commit. The runner refuses a task that queues its own action, so a task
// never queues the next one: the tenant's rows are all published once the
// tasks queued for them have run.
//
// Publishing is retried for as long as it fails, so an outage of the
// revocation service delays revocations and loses none. A revocation carries
// no nonce, so one published again after a crash is recorded once.
package revocationqueue

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/fil-forge/hilt/pkg/grant"
	"github.com/fil-forge/hilt/pkg/store/revocation"
	"github.com/fil-forge/hilt/pkg/tasks"
	"github.com/fil-forge/hilt/pkg/vault"
	"github.com/fil-forge/libforge/taskrunner"
	"github.com/fil-forge/ucantone/did"
	"github.com/fil-forge/ucantone/ucan"
	"github.com/fil-forge/ucantone/validator"
	"github.com/ipfs/go-cid"
	"go.opentelemetry.io/otel/metric"
	"go.uber.org/zap"
)

// BatchSize is the most revocations one queue-revocation.publish task
// publishes, in one request to the revocation service.
const BatchSize = 200

// publishRetry retries a failed publish without limit: after 1s, doubling to
// a minute. The tasks behind one waiting to retry run during its backoff,
// which costs nothing: each takes the tenant's oldest batch, whichever task
// recorded it.
var publishRetry = taskrunner.RetryPolicy{
	First:      time.Second,
	Max:        time.Minute,
	Multiplier: 2,
}

// statsTimeout bounds the read behind the gauges, which runs each time the
// metrics are collected.
const statsTimeout = 5 * time.Second

// Deps is what the queue's handler needs.
type Deps struct {
	// Owed holds the revocations still to publish.
	Owed revocation.Store
	// Secrets holds the tenants' signing keys.
	Secrets vault.Vault
	// Publisher is the revocation service.
	Publisher grant.RevocationPublisher
	// Logger is optional; defaults to zap.NewNop().
	Logger *zap.Logger
	// PublishRetry replaces the publish retry policy (zero keeps it).
	PublishRetry taskrunner.RetryPolicy
}

// Queue runs queue-revocation.
type Queue struct {
	owed      revocation.Store
	secrets   vault.Vault
	publisher grant.RevocationPublisher
	logger    *zap.Logger
}

// New registers the queue's handler with r, which must not have started.
func New(r *taskrunner.Runner, d Deps) (*Queue, error) {
	q := &Queue{owed: d.Owed, secrets: d.Secrets, publisher: d.Publisher, logger: d.Logger}
	if q.logger == nil {
		q.logger = zap.NewNop()
	}
	retry := publishRetry
	if d.PublishRetry != (taskrunner.RetryPolicy{}) {
		retry = d.PublishRetry
	}
	if err := r.Handle(tasks.QueueRevocation, tasks.ActionPublish, q.runPublish, taskrunner.WithRetry(retry)); err != nil {
		return nil, fmt.Errorf("registering %s.%s: %w", tasks.QueueRevocation, tasks.ActionPublish, err)
	}
	return q, nil
}

// PublishSpecs returns the queue-revocation.publish tasks that publish owed
// revocations of the tenant: one task for each batch of [BatchSize], none
// when owed is not positive. The caller submits them in the commit that
// records the revocations, so the tasks exist exactly when the rows do. The
// tasks carry no arguments: each reads what the tenant owes when it runs.
func PublishSpecs(tenant did.DID, owed int) []taskrunner.Spec {
	if owed <= 0 {
		return nil
	}
	specs := make([]taskrunner.Spec, (owed+BatchSize-1)/BatchSize)
	for i := range specs {
		specs[i] = taskrunner.Spec{
			Queue:   tasks.QueueRevocation,
			Subject: tenant.String(),
			Action:  tasks.ActionPublish,
		}
	}
	return specs
}

// runPublish is queue-revocation.publish. It publishes the revocations of the
// subject tenant's oldest [BatchSize] delegations owed one, signed by the
// tenant, and deletes their rows in the task's commit. A delegation that has
// expired needs no revocation and its row is deleted with the rest.
//
// A publish that fails is retried under the action's retry policy, and
// leaves the rows in place. The task fails for good when the tenant's
// signing key is not in the vault: nothing else can sign its revocations, so
// the rows stay and the copies of the delegations the gateway has cached run
// out on their own.
func (q *Queue) runPublish(ctx context.Context, ex *taskrunner.Exec, t taskrunner.Task) ([]byte, error) {
	tenant, err := did.Parse(t.Subject)
	if err != nil {
		return nil, taskrunner.Permanent(fmt.Errorf("parsing the tenant in the task's subject: %w", err))
	}
	log := q.logger.With(zap.Stringer("tenant", tenant), zap.Stringer("task", t.ID))

	owed, err := q.owed.Oldest(ctx, tenant, BatchSize)
	if err != nil {
		return nil, err
	}
	if len(owed) == 0 {
		return nil, nil
	}
	ids := make([]cid.Cid, len(owed))
	live := make([]ucan.Delegation, 0, len(owed))
	now := ucan.UnixTimestamp(time.Now().Unix())
	for i, d := range owed {
		ids[i] = d.Link()
		if validator.ValidateNotExpired(d, now) == nil {
			live = append(live, d)
		}
	}

	// The key is read only when something is left to sign, so a tenant whose
	// key is gone still sheds the rows of delegations that have expired.
	if len(live) > 0 {
		issuer, err := vault.TenantIssuer(ctx, q.secrets, tenant)
		if errors.Is(err, vault.ErrNotFound) {
			log.Error("revocations cannot be signed: the tenant's signing key is not in the vault", zap.Int("revocations", len(live)))
			return nil, taskrunner.Permanent(fmt.Errorf("the tenant's signing key is not in the vault: %w", err))
		}
		if err != nil {
			return nil, err
		}
		if err := grant.PublishRevocations(ctx, log, q.publisher, issuer, live); err != nil {
			log.Warn("publishing revocations failed; the task retries", zap.Int("revocations", len(live)), zap.Int("attempt", t.Attempt), zap.Error(err))
			return nil, err
		}
	}

	st := q.owed.DeleteStatement(ids)
	if err := ex.Write(ctx, st.SQL, st.Args...); err != nil {
		return nil, err
	}
	log.Info("published a batch of revocations owed", zap.Int("published", len(live)), zap.Int("expired", len(owed)-len(live)))
	return nil, nil
}

// RegisterMetrics reports the revocations owed through provider, read from
// the store each time the metrics are collected:
//
//   - hilt.revocations.owed: the number of revocations still to publish.
//   - hilt.revocations.oldest_owed_age: seconds since the oldest was
//     recorded, 0 when none is owed. Growth means revocations are not being
//     published, and access the gateway has cached outlives its withdrawal.
//
// Unregister the returned registration to stop reporting.
func (q *Queue) RegisterMetrics(provider metric.MeterProvider) (metric.Registration, error) {
	meter := provider.Meter("github.com/fil-forge/hilt/pkg/tasks/revocationqueue")
	owed, err := meter.Int64ObservableGauge("hilt.revocations.owed", metric.WithUnit("{revocation}"),
		metric.WithDescription("Revocations still to publish to the revocation service"))
	if err != nil {
		return nil, err
	}
	age, err := meter.Float64ObservableGauge("hilt.revocations.oldest_owed_age", metric.WithUnit("s"),
		metric.WithDescription("How long the oldest revocation still to publish has been owed; 0 when none is. Growth means revocations are not being published"))
	if err != nil {
		return nil, err
	}
	return meter.RegisterCallback(func(ctx context.Context, o metric.Observer) error {
		ctx, cancel := context.WithTimeout(ctx, statsTimeout)
		defer cancel()
		stats, err := q.owed.Stats(ctx)
		if err != nil {
			return err
		}
		o.ObserveInt64(owed, stats.Count)
		o.ObserveFloat64(age, stats.OldestAge.Seconds())
		return nil
	}, owed, age)
}
