// Package postgres provides a PostgreSQL-backed implementation of accesskey.Store.
package postgres

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/fil-forge/hilt/pkg/store"
	"github.com/fil-forge/hilt/pkg/store/accesskey"
	"github.com/fil-forge/hilt/pkg/store/pglock"
	"github.com/fil-forge/ucantone/did"
	"github.com/jackc/pgerrcode"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

type Store struct {
	pool *pgxpool.Pool
}

var _ accesskey.Store = (*Store)(nil)

func New(pool *pgxpool.Pool) *Store {
	return &Store{pool: pool}
}

// Initialize is a no-op. Schema is managed by the shared goose migrations.
func (s *Store) Initialize(ctx context.Context) error { return nil }

const selectColumns = `SELECT id, tenant_id, name, buckets, permissions, principal_id, expires_at, created_at FROM access_key`

// Add inserts the row in a short transaction so its wait is bounded at
// [store.LockTimeout]: the principal foreign key takes FOR KEY SHARE on the
// principal row, which a removal in progress holds FOR UPDATE across its
// callback. A longer wait returns [store.ErrLockTimeout] and nothing is
// written.
func (s *Store) Add(ctx context.Context, in accesskey.Input) (err error) {
	if err := in.Validate(); err != nil {
		return err
	}
	defer func() { err = pglock.MapError(err) }()
	// A service key stores its lists, an empty bucket list meaning every bucket
	// of the tenant. A principal-bound key holds no authority of its own and
	// stores NULL for both; the schema's CHECK constraint enforces the split.
	var bucketStrs, permissions []string
	if in.Principal == nil {
		bucketStrs = make([]string, len(in.Buckets))
		for i, b := range in.Buckets {
			bucketStrs[i] = b.String()
		}
		permissions = in.Permissions
		if permissions == nil {
			permissions = []string{}
		}
	}
	var expires *time.Time
	if in.ExpiresAt != nil {
		e := in.ExpiresAt.UTC()
		expires = &e
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("beginning transaction: %w", err)
	}
	defer tx.Rollback(ctx) // no-op once committed; rolls back on any early return

	if err := pglock.SetTimeout(ctx, tx); err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `
		INSERT INTO access_key (id, tenant_id, name, buckets, permissions, principal_id, expires_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
	`, in.ID.String(), in.Tenant.String(), in.Name, bucketStrs, permissions, in.Principal, expires)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) {
			switch pgErr.Code {
			case pgerrcode.UniqueViolation:
				// The primary key, or one of the two partial unique name indexes.
				return store.ErrRecordExists
			case pgerrcode.ForeignKeyViolation:
				if in.Principal != nil {
					return fmt.Errorf("principal %q is not a principal of tenant %s: %w", *in.Principal, in.Tenant, store.ErrInvalidArgument)
				}
				return fmt.Errorf("tenant %s does not exist: %w", in.Tenant, store.ErrInvalidArgument)
			case pgerrcode.CheckViolation:
				return fmt.Errorf("a principal-bound access key holds NULL permissions and buckets, a service key non-NULL permissions: %w", store.ErrInvalidArgument)
			}
		}
		return fmt.Errorf("adding access key: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("committing transaction: %w", err)
	}
	return nil
}

// Get reads the row, with FOR SHARE when [store.LockShare] is requested so the
// read waits on a Delete that holds the row FOR UPDATE. The share-locked read
// runs in a short transaction of its own so its wait is bounded at
// [store.LockTimeout]; a longer wait returns [store.ErrLockTimeout].
func (s *Store) Get(ctx context.Context, id did.DID, locks ...store.LockMode) (rec accesskey.Record, err error) {
	defer func() { err = pglock.MapError(err) }()
	query := selectColumns + ` WHERE id = $1`
	if !slices.Contains(locks, store.LockShare) {
		rec, err = scanRecord(s.pool.QueryRow(ctx, query, id.String()))
		return pglock.Found(rec, err, "access key")
	}

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return accesskey.Record{}, fmt.Errorf("beginning transaction: %w", err)
	}
	defer tx.Rollback(ctx) // a read commits nothing; rolling back releases the lock
	if err := pglock.SetTimeout(ctx, tx); err != nil {
		return accesskey.Record{}, err
	}
	rec, err = scanRecord(tx.QueryRow(ctx, query+` FOR SHARE`, id.String()))
	return pglock.Found(rec, err, "access key")
}

func (s *Store) ListByTenant(ctx context.Context, tenant did.DID, opts ...accesskey.ListOption) ([]accesskey.Record, error) {
	cfg := accesskey.NewListConfig(opts...)
	query := selectColumns + ` WHERE tenant_id = $1`
	args := []any{tenant.String()}
	if cfg.Principal != nil {
		args = append(args, *cfg.Principal)
		query += fmt.Sprintf(` AND principal_id = $%d`, len(args))
	}
	query += ` ORDER BY id ASC`

	rows, err := s.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("listing access keys by tenant: %w", err)
	}
	defer rows.Close()

	var recs []accesskey.Record
	for rows.Next() {
		rec, err := scanRecord(rows)
		if err != nil {
			return nil, err
		}
		recs = append(recs, rec)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterating access keys: %w", err)
	}
	return recs, nil
}

// Delete removes the row in a short transaction so its wait on a row another
// write holds is bounded at [store.LockTimeout]; a longer wait returns
// [store.ErrLockTimeout] for the caller to retry rather than holding its pool
// connection indefinitely.
func (s *Store) Delete(ctx context.Context, id did.DID) (err error) {
	defer func() { err = pglock.MapError(err) }()
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("beginning transaction: %w", err)
	}
	defer tx.Rollback(ctx) // no-op once committed; rolls back on any early return

	if err := pglock.SetTimeout(ctx, tx); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `DELETE FROM access_key WHERE id = $1`, id.String()); err != nil {
		return fmt.Errorf("deleting access key: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("committing transaction: %w", err)
	}
	return nil
}

func scanRecord(row pgx.Row) (accesskey.Record, error) {
	var (
		idStr      string
		tenantStr  string
		name       string
		bucketStrs []string
		perms      []string
		principal  *string
		expiresAt  *time.Time
		createdAt  time.Time
	)
	if err := row.Scan(&idStr, &tenantStr, &name, &bucketStrs, &perms, &principal, &expiresAt, &createdAt); err != nil {
		return accesskey.Record{}, err
	}
	id, err := did.Parse(idStr)
	if err != nil {
		return accesskey.Record{}, fmt.Errorf("parsing access key DID: %w", err)
	}
	tenant, err := did.Parse(tenantStr)
	if err != nil {
		return accesskey.Record{}, fmt.Errorf("parsing tenant DID: %w", err)
	}
	rec := accesskey.Record{
		ID:          id,
		Tenant:      tenant,
		Name:        name,
		Permissions: perms,
		Principal:   principal,
		ExpiresAt:   expiresAt,
		CreatedAt:   createdAt,
	}
	if len(bucketStrs) > 0 {
		buckets := make([]did.DID, len(bucketStrs))
		for i, b := range bucketStrs {
			d, err := did.Parse(b)
			if err != nil {
				return accesskey.Record{}, fmt.Errorf("parsing bucket DID: %w", err)
			}
			buckets[i] = d
		}
		rec.Buckets = buckets
	}
	return rec, nil
}
