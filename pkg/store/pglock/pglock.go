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
// statement gives up waiting for a lock, and err unchanged otherwise.
func MapError(err error) error {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == pgerrcode.LockNotAvailable {
		return fmt.Errorf("waited %s for a lock another write holds: %w", store.LockTimeout, store.ErrLockTimeout)
	}
	return err
}
