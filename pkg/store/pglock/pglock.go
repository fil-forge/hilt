// Package pglock holds the Postgres locking and transaction helpers the stores
// share: the bounded wait every locking statement takes, the mapping of the
// server's lock_not_available back to [store.ErrLockTimeout], the transaction
// a store call joins, and the read-only snapshot a reader's calls join
// ([ReadSnapshot]).
package pglock

import (
	"context"
	"errors"
	"fmt"
	"strconv"

	"github.com/fil-forge/hilt/pkg/store"
	"github.com/jackc/pgerrcode"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// timeoutSetting is [store.LockTimeout] as Postgres spells it: a unitless
// lock_timeout is milliseconds.
var timeoutSetting = strconv.FormatInt(store.LockTimeout.Milliseconds(), 10)

// SetTimeout bounds every lock tx goes on to take at [store.LockTimeout].
// set_config with is_local is SET LOCAL, which SET itself cannot express with
// a bound parameter. The setting lasts until the outermost transaction ends,
// or until a savepoint tx rolls back.
func SetTimeout(ctx context.Context, tx pgx.Tx) error {
	if _, err := tx.Exec(ctx, `SELECT set_config('lock_timeout', $1, true)`, timeoutSetting); err != nil {
		return fmt.Errorf("setting lock timeout: %w", err)
	}
	return nil
}

// MapError returns [store.ErrLockTimeout] for the error Postgres raises when a
// statement gives up waiting for a lock, and for a deadlock it broke by
// aborting this transaction (Postgres reports one within its
// deadlock_timeout, before lock_timeout), and err unchanged otherwise. Either
// way nothing was committed and the caller retries.
func MapError(err error) error {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		switch pgErr.Code {
		case pgerrcode.LockNotAvailable:
			return fmt.Errorf("waited %s for a lock another write holds: %w", store.LockTimeout, store.ErrLockTimeout)
		case pgerrcode.DeadlockDetected:
			return fmt.Errorf("deadlocked with another write and was aborted: %w", store.ErrLockTimeout)
		}
	}
	return err
}

// Found maps a single-row read's result: no row is [store.ErrRecordNotFound],
// any other error is wrapped as "getting <recordType>", and a found row is returned
// as is.
func Found[T any](v T, err error, recordType string) (T, error) {
	var zero T
	if errors.Is(err, pgx.ErrNoRows) {
		return zero, store.ErrRecordNotFound
	}
	if err != nil {
		return zero, fmt.Errorf("getting %s: %w", recordType, err)
	}
	return v, nil
}

type txKey struct{}

// WithTx returns ctx carrying tx, for store calls to run inside a
// transaction the caller owns. A store call handed this ctx that opens its transaction with
// [Begin] joins tx instead, so what it writes commits with the enclosing write
// or not at all.
func WithTx(ctx context.Context, tx pgx.Tx) context.Context {
	return context.WithValue(ctx, txKey{}, tx)
}

// TxFrom returns the transaction ctx carries, if any.
func TxFrom(ctx context.Context) (pgx.Tx, bool) {
	tx, ok := ctx.Value(txKey{}).(pgx.Tx)
	return tx, ok
}

// Begin starts a store call's transaction. When ctx carries one (see [WithTx])
// it opens a savepoint inside it: Commit releases the savepoint, Rollback
// returns to it, and the enclosing write owns the commit. Otherwise it begins
// a new transaction on pool. A store's single-statement reads run through
// [Reader] instead.
func Begin(ctx context.Context, pool *pgxpool.Pool) (pgx.Tx, error) {
	if tx, ok := TxFrom(ctx); ok {
		return tx.Begin(ctx)
	}
	return pool.Begin(ctx)
}

// Querier is what a store's read runs on: a pool, or a transaction.
type Querier interface {
	// Query runs a statement that returns rows.
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
	// QueryRow runs a statement that returns at most one row.
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

// Reader returns what a store's read runs on: the transaction ctx carries
// (see [WithTx], [ReadSnapshot]), so that the read sees what the transaction
// sees, and pool otherwise. The rows a Query returns must be closed before
// the next statement on the same ctx, since a transaction runs one statement
// at a time.
func Reader(ctx context.Context, pool *pgxpool.Pool) Querier {
	if tx, ok := TxFrom(ctx); ok {
		return tx
	}
	return pool
}

// ReadSnapshot runs fn with ctx carrying a read-only, repeatable-read
// transaction on pool, which every store read made with that ctx joins
// ([Reader]). Postgres takes the transaction's snapshot at its first
// statement, so every read fn makes answers from the database as it was
// then: a write that commits while fn runs is seen by none of them, and one
// that committed before is seen by all. fn must not write, and its reads run
// one at a time. When ctx already carries a transaction, fn runs in that one.
func ReadSnapshot(ctx context.Context, pool *pgxpool.Pool, fn func(ctx context.Context) error) error {
	if _, ok := TxFrom(ctx); ok {
		return fn(ctx)
	}
	tx, err := pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return fmt.Errorf("beginning a read snapshot: %w", err)
	}
	// A read-only transaction has nothing to commit; ending it either way
	// releases its connection.
	defer tx.Rollback(context.WithoutCancel(ctx))
	return fn(WithTx(ctx, tx))
}

// Snapshots opens read snapshots ([ReadSnapshot]) on one pool, for a reader
// that holds no pool of its own.
type Snapshots struct {
	pool *pgxpool.Pool
}

// NewSnapshots returns the snapshots of pool.
func NewSnapshots(pool *pgxpool.Pool) *Snapshots {
	return &Snapshots{pool: pool}
}

// Read runs fn in a read snapshot of the pool, as [ReadSnapshot] does.
func (s *Snapshots) Read(ctx context.Context, fn func(ctx context.Context) error) error {
	return ReadSnapshot(ctx, s.pool, fn)
}
