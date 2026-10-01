// Package pglock holds the Postgres locking helpers the stores share.
package pglock

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5"
)

// TenantNamespace is the first key of the per-tenant advisory lock; the
// second is the tenant DID. A policy write holds it shared for its
// transaction; a principal add holds it exclusive for its upsert. Row locks
// cannot order the two, because the add's row does not exist until it
// commits: without the lock a principal added after the write's callback
// listed the tenant's principals, and before the write committed, could
// create an access key that finds no policy to grant from and is never
// rotated. Under it the add commits either before the listing, so the write
// rotates the new principal's keys, or after the commit, so the key's
// creation reads the committed policy.
const TenantNamespace int32 = 0x54454e54 // "TENT"

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
