// Package pglock holds the Postgres transaction helpers the stores share: the
// transaction a write's callback joins, and the mapping of a single-row read's
// result.
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

// WithTx returns ctx carrying tx for the callback a write runs inside its
// transaction. A store call handed this ctx that opens its transaction with
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
// a new transaction on pool. A query that does not go through Begin runs on
// the pool and does not see the transaction's uncommitted writes.
func Begin(ctx context.Context, pool *pgxpool.Pool) (pgx.Tx, error) {
	if tx, ok := TxFrom(ctx); ok {
		return tx.Begin(ctx)
	}
	return pool.Begin(ctx)
}
