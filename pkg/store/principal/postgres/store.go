// Package postgres provides a PostgreSQL-backed implementation of
// principal.Store.
package postgres

import (
	"context"
	"fmt"
	"time"

	"github.com/fil-forge/hilt/pkg/store"
	"github.com/fil-forge/hilt/pkg/store/pglock"
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
	// the row is live, and the zero row count reports the duplicate.
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

func (s *Store) Get(ctx context.Context, tenant did.DID, externalID string) (principal.Record, error) {
	rec, err := scanRecord(pglock.Reader(ctx, s.pool).QueryRow(ctx, `
		SELECT tenant_id, external_id, created_at
		FROM principal
		WHERE tenant_id = $1 AND external_id = $2 AND deleted_at IS NULL
	`, tenant.String(), externalID))
	return pglock.Found(rec, err, "principal")
}

func (s *Store) ListByTenant(ctx context.Context, tenant did.DID) ([]principal.Record, error) {
	rows, err := pglock.Reader(ctx, s.pool).Query(ctx, `
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

func (s *Store) ListIDsByTenant(ctx context.Context, tenant did.DID) ([]string, error) {
	rows, err := pglock.Reader(ctx, s.pool).Query(ctx, `
		SELECT external_id
		FROM principal
		WHERE tenant_id = $1 AND deleted_at IS NULL
		ORDER BY external_id ASC
	`, tenant.String())
	if err != nil {
		return nil, fmt.Errorf("listing principal ids by tenant: %w", err)
	}
	ids, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		return nil, fmt.Errorf("scanning principal ids: %w", err)
	}
	return ids, nil
}

func (s *Store) TombstoneStatement(tenant did.DID, externalID string) store.Statement {
	return store.Statement{
		SQL: `
			UPDATE principal
			SET deleted_at = NOW()
			WHERE tenant_id = $1 AND external_id = $2 AND deleted_at IS NULL`,
		Args: []any{tenant.String(), externalID},
	}
}

// DeleteByTenant removes every principal of the tenant in a short transaction
// so its wait is bounded at [store.LockTimeout]: a row a task's commit holds
// blocks the delete, and a longer wait returns [store.ErrLockTimeout] with
// nothing written.
func (s *Store) DeleteByTenant(ctx context.Context, tenant did.DID) (err error) {
	defer func() { err = pglock.MapError(err) }()
	tx, err := pglock.Begin(ctx, s.pool)
	if err != nil {
		return fmt.Errorf("beginning transaction: %w", err)
	}
	defer tx.Rollback(ctx) // no-op once committed; rolls back on any early return

	if err := pglock.SetTimeout(ctx, tx); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `DELETE FROM principal WHERE tenant_id = $1`, tenant.String()); err != nil {
		return fmt.Errorf("deleting principals by tenant: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("committing transaction: %w", err)
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
