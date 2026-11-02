package pglock_test

import (
	"context"
	"testing"

	"github.com/fil-forge/hilt/internal/testutil"
	"github.com/fil-forge/hilt/pkg/store/pglock"
	"github.com/stretchr/testify/require"
)

// A write that joins the transaction its ctx carries commits with that
// transaction: an enclosing rollback takes the joined write with it, and a
// joined rollback leaves the enclosing transaction usable.
func TestBeginJoinsTheTransactionInContext(t *testing.T) {
	pool := testutil.PostgresOrSkip(t)
	ctx := context.Background()
	_, err := pool.Exec(ctx, `CREATE TABLE IF NOT EXISTS pglock_test (id TEXT PRIMARY KEY)`)
	require.NoError(t, err)

	count := func(id string) int {
		var n int
		require.NoError(t, pool.QueryRow(ctx, `SELECT count(*) FROM pglock_test WHERE id = $1`, id).Scan(&n))
		return n
	}

	t.Run("an enclosing rollback discards a joined write", func(t *testing.T) {
		outer, err := pool.Begin(ctx)
		require.NoError(t, err)
		inner, err := pglock.Begin(pglock.WithTx(ctx, outer), pool)
		require.NoError(t, err)
		_, err = inner.Exec(ctx, `INSERT INTO pglock_test (id) VALUES ('joined')`)
		require.NoError(t, err)
		require.NoError(t, inner.Commit(ctx))
		require.NoError(t, outer.Rollback(ctx))
		require.Equal(t, 0, count("joined"))
	})

	t.Run("a joined rollback leaves the enclosing transaction usable", func(t *testing.T) {
		outer, err := pool.Begin(ctx)
		require.NoError(t, err)
		defer outer.Rollback(ctx)
		inner, err := pglock.Begin(pglock.WithTx(ctx, outer), pool)
		require.NoError(t, err)
		_, err = inner.Exec(ctx, `INSERT INTO pglock_test (id) VALUES ('dropped')`)
		require.NoError(t, err)
		require.NoError(t, inner.Rollback(ctx))
		_, err = outer.Exec(ctx, `INSERT INTO pglock_test (id) VALUES ('kept')`)
		require.NoError(t, err)
		require.NoError(t, outer.Commit(ctx))
		require.Equal(t, 0, count("dropped"))
		require.Equal(t, 1, count("kept"))
	})

	t.Run("without a transaction in ctx Begin opens its own", func(t *testing.T) {
		tx, err := pglock.Begin(ctx, pool)
		require.NoError(t, err)
		_, err = tx.Exec(ctx, `INSERT INTO pglock_test (id) VALUES ('own')`)
		require.NoError(t, err)
		require.NoError(t, tx.Commit(ctx))
		require.Equal(t, 1, count("own"))
	})
}

// AdvisoryAll takes every key's lock in one statement and holds them until
// the transaction ends.
func TestAdvisoryAllHoldsEveryKey(t *testing.T) {
	pool := testutil.PostgresOrSkip(t)
	ctx := context.Background()
	const namespace int32 = 0x54455354 // "TEST"
	keys := []string{"a", "b", "c"}

	// held probes the key from a connection of its own, which a session lock
	// needs: it must be released on the connection that took it.
	probe, err := pool.Acquire(ctx)
	require.NoError(t, err)
	defer probe.Release()
	held := func(key string) bool {
		var free bool
		require.NoError(t, probe.QueryRow(ctx, `SELECT pg_try_advisory_lock($1, hashtext($2))`, namespace, key).Scan(&free))
		if free {
			_, err := probe.Exec(ctx, `SELECT pg_advisory_unlock($1, hashtext($2))`, namespace, key)
			require.NoError(t, err)
		}
		return !free
	}
	heldAll := func() map[string]bool {
		out := map[string]bool{}
		for _, k := range keys {
			out[k] = held(k)
		}
		return out
	}

	tx, err := pool.Begin(ctx)
	require.NoError(t, err)
	require.NoError(t, pglock.AdvisoryAll(ctx, tx, namespace, keys))
	require.Equal(t, map[string]bool{"a": true, "b": true, "c": true}, heldAll())

	require.NoError(t, tx.Commit(ctx))
	require.Equal(t, map[string]bool{"a": false, "b": false, "c": false}, heldAll())
}
