// Package pglock holds the Postgres locking and transaction helpers the stores share.
package pglock

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Advisory takes the transaction-scoped advisory lock identified by
// (namespace, hashtext(key)) inside tx: pg_advisory_xact_lock, exclusive, for a
// writer; pg_advisory_xact_lock_shared for a reader. Postgres identifies an
// advisory lock by its key pair and nothing else, so each caller passes its own
// namespace to keep its locks apart from every other advisory lock taken on the
// same database. The lock is released when tx commits or rolls back, and there
// is nothing to unlock.
func Advisory(ctx context.Context, tx pgx.Tx, namespace int32, key string, shared bool) error {
	fn := "pg_advisory_xact_lock"
	if shared {
		fn = "pg_advisory_xact_lock_shared"
	}
	if _, err := tx.Exec(ctx, fmt.Sprintf(`SELECT %s($1, hashtext($2))`, fn), namespace, key); err != nil {
		return fmt.Errorf("taking advisory lock: %w", err)
	}
	return nil
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
