// Package pglock holds the Postgres locking helpers the stores share: the
// bounded wait every locking statement takes, and the mapping of the server's
// lock_not_available back to [store.ErrLockTimeout].
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
)

// timeoutSetting is [store.LockTimeout] as Postgres spells it: a unitless
// lock_timeout is milliseconds.
var timeoutSetting = strconv.FormatInt(store.LockTimeout.Milliseconds(), 10)

// SetTimeout bounds every lock tx goes on to take at [store.LockTimeout].
// set_config with is_local is SET LOCAL, which SET itself cannot express with
// a bound parameter. The setting is reverted when tx ends.
func SetTimeout(ctx context.Context, tx pgx.Tx) error {
	if _, err := tx.Exec(ctx, `SELECT set_config('lock_timeout', $1, true)`, timeoutSetting); err != nil {
		return fmt.Errorf("setting lock timeout: %w", err)
	}
	return nil
}

// MapError returns [store.ErrLockTimeout] for the error Postgres raises when a
// statement gives up waiting for a lock, and for a deadlock it broke by
// aborting this transaction (a principal row held FOR UPDATE against the
// policy index's FOR KEY SHARE on it can form one; Postgres reports it within
// its deadlock_timeout, before lock_timeout), and err unchanged otherwise.
// Either way nothing was committed and the caller retries.
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
