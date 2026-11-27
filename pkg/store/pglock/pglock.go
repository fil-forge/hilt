// Package pglock holds the Postgres transaction helpers the stores share: the
// transaction a store call joins, and the read-only snapshot a reader's calls
// join ([ReadSnapshot]).
package pglock

import (
	"context"
	"errors"
	"fmt"

	"github.com/fil-forge/hilt/pkg/store"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

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
