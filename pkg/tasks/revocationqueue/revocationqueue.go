// Package revocationqueue is queue-revocation: the publishing of the
// revocations a tenant owes, on the subject of the tenant's DID.
//
// A change to a tenant's authority records the delegations it withdraws as
// revocations owed and queues one queue-revocation.publish task for the
// tenant ([PublishSpec]) in the same commit. The task publishes everything
// the tenant owes, a batch of [BatchSize] at a time, and deletes the rows in
// its commit ([Drain]). Tenant deletion runs the same task as a sync child of
// its own, before it deactivates the tenant's DID, and holds the tenant's
// subject here until it commits.
//
// Publishing is retried for as long as it fails, so an outage of the
// revocation service delays revocations and loses none. A revocation carries
// no nonce, so one published again by a retry or after a crash is recorded
// once.
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

// BatchSize is the most revocations published in one request to the
// revocation service.
const BatchSize = 200

// publishRetry retries a failed publish without limit: after 1s, doubling to
// a minute. The tasks behind one waiting to retry run during its backoff,
// which costs nothing: each publishes whatever the tenant owes when it runs,
// whichever change recorded it.
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

// ErrSigningKeyMissing is returned by [Drain] when the tenant owes a
// revocation and its signing key is not in the vault, so nothing can sign it.
var ErrSigningKeyMissing = errors.New("the tenant's signing key is not in the vault")

// PublishSpec returns the queue-revocation.publish task that publishes every
// revocation the tenant owes. The caller submits it in the commit that
// records revocations, so the task exists exactly when the rows do. It
// carries no arguments: it reads what the tenant owes when it runs.
func PublishSpec(tenant did.DID) taskrunner.Spec {
	return taskrunner.Spec{
		Queue:   tasks.QueueRevocation,
		Subject: tenant.String(),
		Action:  tasks.ActionPublish,
	}
}

// Drained counts what one [Drain] went through.
type Drained struct {
	// Published is the number of revocations the revocation service took.
	Published int
	// Expired is the number of delegations that had expired and needed no
	// revocation.
	Expired int
}

// Drain publishes every revocation the tenant owes, signed by the tenant, a
// batch of [BatchSize] at a time, oldest first. After each batch is published
// it hands the batch's CIDs to remove, which deletes their rows or records
// the delete for later. Each batch is read after the last row of the one
// before, so the rows of a batch need not be gone before the next is read. A
// delegation that has expired needs no revocation and is handed to remove
// with the rest.
//
// It stops at the first failure, with the batches before it published and
// handed to remove. It returns [ErrSigningKeyMissing] when a live delegation
// is owed and the tenant's key is not in the vault; the key is read only
// then, so a tenant whose key is gone still sheds the rows of delegations
// that have expired.
func Drain(
	ctx context.Context,
	log *zap.Logger,
	owed revocation.Store,
	secrets vault.Vault,
	publisher grant.RevocationPublisher,
	tenant did.DID,
	remove func(ctx context.Context, ids []cid.Cid) error,
) (Drained, error) {
	var (
		done   Drained
		after  revocation.Cursor
		issuer ucan.Issuer
	)
	for {
		batch, next, err := owed.Oldest(ctx, tenant, after, BatchSize)
		if err != nil {
			return done, err
		}
		if len(batch) == 0 {
			return done, nil
		}
		ids := make([]cid.Cid, len(batch))
		live := make([]ucan.Delegation, 0, len(batch))
		now := ucan.UnixTimestamp(time.Now().Unix())
		for i, d := range batch {
			ids[i] = d.Link()
			if validator.ValidateNotExpired(d, now) == nil {
				live = append(live, d)
			}
		}
		if len(live) > 0 {
			if issuer == nil {
				issuer, err = vault.TenantIssuer(ctx, secrets, tenant)
				if errors.Is(err, vault.ErrNotFound) {
					return done, fmt.Errorf("%w: %w", ErrSigningKeyMissing, err)
				}
				if err != nil {
					return done, err
				}
			}
			if err := grant.PublishRevocations(ctx, log, publisher, issuer, live); err != nil {
				return done, err
			}
		}
		if err := remove(ctx, ids); err != nil {
			return done, err
		}
		done.Published += len(live)
		done.Expired += len(batch) - len(live)
		if len(batch) < BatchSize {
			return done, nil
		}
		after = next
	}
}

// runPublish is queue-revocation.publish. It publishes every revocation the
// subject tenant owes ([Drain]) and deletes the rows in the task's commit.
// The deletes are not visible until then, which is why the batches are read
// by cursor.
//
// A publish that fails is retried under the action's retry policy, and
// leaves every row in place: the retry publishes from the start, and the
// revocation service records a repeated revocation once. The task fails for
// good when the tenant's signing key is not in the vault: nothing else can
// sign its revocations, so the rows stay and the copies of the delegations
// the gateway has cached run out on their own.
func (q *Queue) runPublish(ctx context.Context, ex *taskrunner.Exec, t taskrunner.Task) ([]byte, error) {
	tenant, err := did.Parse(t.Subject)
	if err != nil {
		return nil, taskrunner.Permanent(fmt.Errorf("parsing the tenant in the task's subject: %w", err))
	}
	log := q.logger.With(zap.Stringer("tenant", tenant), zap.Stringer("task", t.ID))

	done, err := Drain(ctx, log, q.owed, q.secrets, q.publisher, tenant, func(ctx context.Context, ids []cid.Cid) error {
		st := q.owed.DeleteStatement(ids)
		return ex.Write(ctx, st.SQL, st.Args...)
	})
	if errors.Is(err, ErrSigningKeyMissing) {
		log.Error("revocations cannot be signed: the tenant's signing key is not in the vault")
		return nil, taskrunner.Permanent(err)
	}
	if err != nil {
		log.Warn("publishing revocations failed; the task retries", zap.Int("published", done.Published), zap.Int("attempt", t.Attempt), zap.Error(err))
		return nil, err
	}
	if done.Published+done.Expired > 0 {
		log.Info("published the revocations owed", zap.Int("published", done.Published), zap.Int("expired", done.Expired))
	}
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
