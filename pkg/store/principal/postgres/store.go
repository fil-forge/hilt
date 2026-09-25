// Package postgres provides a PostgreSQL-backed implementation of
// principal.Store.
package postgres

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/fil-forge/hilt/pkg/store"
	"github.com/fil-forge/hilt/pkg/store/principal"
	"github.com/fil-forge/ucantone/did"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type Store struct {
	pool *pgxpool.Pool
}

var _ principal.Store = (*Store)(nil)

func New(pool *pgxpool.Pool) *Store {
	return &Store{pool: pool}
}

// Initialize is a no-op. Schema is managed by the shared goose migrations.
func (s *Store) Initialize(ctx context.Context) error { return nil }

func (s *Store) Add(ctx context.Context, tenant did.DID, externalID string) error {
	if tenant == did.Undef {
		return fmt.Errorf("principal tenant is required: %w", store.ErrInvalidArgument)
	}
	if externalID == "" {
		return fmt.Errorf("principal external ID is required: %w", store.ErrInvalidArgument)
	}
	// The upsert revives a tombstone under the same id; it touches nothing when
	// the row is live, and the zero row count reports the duplicate. The row
	// lock it takes waits for an in-flight Delete of the same principal.
	tag, err := s.pool.Exec(ctx, `
		INSERT INTO principal (tenant_id, external_id)
		VALUES ($1, $2)
		ON CONFLICT (tenant_id, external_id) DO UPDATE
			SET deleted_at = NULL, created_at = NOW()
			WHERE principal.deleted_at IS NOT NULL
	`, tenant.String(), externalID)
	if err != nil {
		return fmt.Errorf("adding principal: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return store.ErrRecordExists
	}
	return nil
}

// Get reads the row, with FOR SHARE when [store.LockShare] is requested so the
// read waits on a Delete that holds the row FOR UPDATE.
func (s *Store) Get(ctx context.Context, tenant did.DID, externalID string, locks ...store.LockMode) (principal.Record, error) {
	query := `
		SELECT tenant_id, external_id, created_at
		FROM principal
		WHERE tenant_id = $1 AND external_id = $2 AND deleted_at IS NULL
	`
	if slices.Contains(locks, store.LockShare) {
		query += ` FOR SHARE`
	}
	rec, err := scanRecord(s.pool.QueryRow(ctx, query, tenant.String(), externalID))
	if errors.Is(err, pgx.ErrNoRows) {
		return principal.Record{}, store.ErrRecordNotFound
	}
	if err != nil {
		return principal.Record{}, fmt.Errorf("getting principal: %w", err)
	}
	return rec, nil
}

func (s *Store) ListByTenant(ctx context.Context, tenant did.DID) ([]principal.Record, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT tenant_id, external_id, created_at
		FROM principal
		WHERE tenant_id = $1 AND deleted_at IS NULL
		ORDER BY external_id ASC
	`, tenant.String())
	if err != nil {
		return nil, fmt.Errorf("listing principals by tenant: %w", err)
	}
	defer rows.Close()

	var recs []principal.Record
	for rows.Next() {
		rec, err := scanRecord(rows)
		if err != nil {
			return nil, fmt.Errorf("scanning principal: %w", err)
		}
		recs = append(recs, rec)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterating principals: %w", err)
	}
	return recs, nil
}

// Delete runs in one transaction: it locks the row FOR UPDATE, runs
// beforeCommit while holding the lock, sets deleted_at and commits. A locked
// read of the row (see [Store.Get]) waits for the commit or the rollback.
func (s *Store) Delete(ctx context.Context, tenant did.DID, externalID string, beforeCommit func(ctx context.Context) error) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("beginning transaction: %w", err)
	}
	defer tx.Rollback(ctx) // no-op once committed; rolls back on any early return

	var deleted bool
	err = tx.QueryRow(ctx, `
		SELECT deleted_at IS NOT NULL
		FROM principal
		WHERE tenant_id = $1 AND external_id = $2
		FOR UPDATE
	`, tenant.String(), externalID).Scan(&deleted)
	if errors.Is(err, pgx.ErrNoRows) || (err == nil && deleted) {
		return nil // idempotent: nothing to publish and nothing to remove
	}
	if err != nil {
		return fmt.Errorf("locking principal: %w", err)
	}

	if beforeCommit != nil {
		if err := beforeCommit(ctx); err != nil {
			return fmt.Errorf("before deleting principal: %w", err)
		}
	}

	if _, err := tx.Exec(ctx, `
		UPDATE principal
		SET deleted_at = NOW()
		WHERE tenant_id = $1 AND external_id = $2
	`, tenant.String(), externalID); err != nil {
		return fmt.Errorf("deleting principal: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("committing transaction: %w", err)
	}
	return nil
}

// Lock runs in one transaction: it locks the live rows FOR UPDATE in external
// ID order, runs fn while holding them and commits. Sorting keeps two Lock
// calls over overlapping principals from deadlocking.
func (s *Store) Lock(ctx context.Context, tenant did.DID, externalIDs []string, fn func(ctx context.Context) error) error {
	if len(externalIDs) == 0 {
		return fn(ctx)
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("beginning transaction: %w", err)
	}
	defer tx.Rollback(ctx) // no-op once committed; rolls back on any early return

	if _, err := tx.Exec(ctx, `
		SELECT 1
		FROM principal
		WHERE tenant_id = $1 AND external_id = ANY($2) AND deleted_at IS NULL
		ORDER BY external_id ASC
		FOR UPDATE
	`, tenant.String(), externalIDs); err != nil {
		return fmt.Errorf("locking principals: %w", err)
	}
	if err := fn(ctx); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("committing transaction: %w", err)
	}
	return nil
}

func (s *Store) DeleteByTenant(ctx context.Context, tenant did.DID) error {
	if _, err := s.pool.Exec(ctx, `DELETE FROM principal WHERE tenant_id = $1`, tenant.String()); err != nil {
		return fmt.Errorf("deleting principals by tenant: %w", err)
	}
	return nil
}

func scanRecord(row pgx.Row) (principal.Record, error) {
	var (
		tenantStr  string
		externalID string
		createdAt  time.Time
	)
	if err := row.Scan(&tenantStr, &externalID, &createdAt); err != nil {
		return principal.Record{}, err
	}
	tenant, err := did.Parse(tenantStr)
	if err != nil {
		return principal.Record{}, fmt.Errorf("parsing tenant DID: %w", err)
	}
	return principal.Record{Tenant: tenant, ExternalID: externalID, CreatedAt: createdAt}, nil
}
