package store

import (
	"context"
	"fmt"
	"time"
)

// Page is a generic type representing a paginated response from the store.
type Page[T any] struct {
	Cursor  *string
	Results []T
}

type PaginationConfig struct {
	// Cursor is an optional string that indicates where to start the page. This
	// is typically the ID of the last item from the previous page.
	Cursor *string
	// Limit is an optional integer that specifies the maximum number of items to
	// return in the page. If not provided, a default limit may be applied by the
	// implementation.
	Limit *int
}

type PaginationOption func(cfg *PaginationConfig)

func WithLimit(limit int) PaginationOption {
	return func(cfg *PaginationConfig) {
		cfg.Limit = &limit
	}
}

func WithCursor(cursor string) PaginationOption {
	return func(cfg *PaginationConfig) {
		cfg.Cursor = &cursor
	}
}

type GetPageFunc[T any] func(ctx context.Context, options PaginationConfig) (Page[T], error)

func Collect[T any](ctx context.Context, getPage GetPageFunc[T]) ([]T, error) {
	var items []T
	paginationOptions := PaginationConfig{}
	i := 0
	for {
		page, err := getPage(ctx, paginationOptions)
		if err != nil {
			return nil, fmt.Errorf("getting page %d: %w", i, err)
		}
		items = append(items, page.Results...)
		if page.Cursor == nil || len(page.Results) == 0 {
			break
		}
		paginationOptions.Cursor = page.Cursor
		i++
	}
	return items, nil
}

// ReadConfig is the row lock a read takes. The zero value takes none.
type ReadConfig struct {
	// Share reads the row with SELECT ... FOR SHARE. A write in flight on the
	// same row (held FOR UPDATE inside its transaction) blocks the read until it
	// commits or rolls back, so the read is answered from the committed state.
	// The read needs no transaction of its own: a FOR SHARE in autocommit mode
	// still waits on a conflicting FOR UPDATE. Without it a read never waits and
	// may be answered from a snapshot that predates an in-flight write.
	//
	// The memory backends give the same guarantee with their own locks: a
	// share-locked read there waits for a write in flight on the same record.
	Share bool
}

type ReadOption func(cfg *ReadConfig)

// WithShareLock reads with [ReadConfig.Share].
func WithShareLock() ReadOption {
	return func(cfg *ReadConfig) {
		cfg.Share = true
	}
}

// NewReadConfig applies opts to the zero ReadConfig.
func NewReadConfig(opts ...ReadOption) ReadConfig {
	var cfg ReadConfig
	for _, opt := range opts {
		opt(&cfg)
	}
	return cfg
}

// LockTimeout bounds how long a locking statement in a Postgres store waits
// for a conflicting lock before giving up with [ErrLockTimeout].
//
// Writes hold their locks across a caller-supplied callback that publishes to
// the revocation service, and a removal's callback opens further transactions
// that lock other rows. Two such writes can therefore wait on each other
// through an application-level edge Postgres cannot see in its own deadlock
// graph, and an unbounded wait would hang both and pin their pool connections.
// The bound turns that into an error the caller can retry.
const LockTimeout = 10 * time.Second

// IdleTransactionTimeout is how long Postgres lets a store's connection sit in
// an open transaction with no statement running before it ends the session,
// rolling the transaction back and releasing its locks.
//
// A write's transaction stays open across its callback, which is bounded (see
// [LockTimeout] and the rotation's own deadline), so a healthy write is never
// idle this long. One that is (a transaction never committed or rolled back,
// or a callback that hangs) would otherwise hold its row and advisory locks
// until the connection closes, and every write needing them would fail with
// [ErrLockTimeout] for as long as the process runs. The bound turns that into
// one failed write.
const IdleTransactionTimeout = time.Minute
