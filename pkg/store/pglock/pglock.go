// Package pglock holds the Postgres locking helpers the stores share.
package pglock

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5"
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
