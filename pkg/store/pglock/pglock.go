// Package pglock holds the Postgres transaction helpers the stores share: the
// transaction a write's callback joins, the connection a statement runs on,
// and the mapping of a single-row read's result.
package pglock

import (
	"context"
	"errors"
	"fmt"

	"github.com/fil-forge/hilt/pkg/store"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
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

// DBTX is what a store runs one statement on: a [pgx.Tx], whose statements run
// on the connection the transaction holds, or a [pgxpool.Pool], which lends
// each statement a connection of its own.
type DBTX interface {
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

// ResolveDBTX returns the transaction ctx carries (see [WithTx]), or pool
// when it carries none. A store runs every statement outside [Begin] on it, so
// a read inside a write's callback, or inside a read-only snapshot, uses the
// connection that transaction already holds. Taking a second connection from
// the pool instead would deadlock once concurrent writes hold every pooled
// connection and each waits for another.
func ResolveDBTX(ctx context.Context, pool *pgxpool.Pool) DBTX {
	if tx, ok := TxFrom(ctx); ok {
		return tx
	}
	return pool
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
