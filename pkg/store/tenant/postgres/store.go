// Package postgres provides a PostgreSQL-backed implementation of tenant.Store.
package postgres

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/fil-forge/hilt/pkg/store"
	"github.com/fil-forge/hilt/pkg/store/pglock"
	"github.com/fil-forge/hilt/pkg/store/tenant"
	"github.com/fil-forge/ucantone/did"
	"github.com/jackc/pgerrcode"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

type Store struct {
	pool *pgxpool.Pool
}

var _ tenant.Store = (*Store)(nil)

func New(pool *pgxpool.Pool) *Store {
	return &Store{pool: pool}
}

// Initialize is a no-op. Schema is managed by the shared goose migrations.
func (s *Store) Initialize(ctx context.Context) error { return nil }

func (s *Store) Add(ctx context.Context, id did.DID, externalID string, status tenant.Status) error {
	if id == did.Undef {
		return fmt.Errorf("tenant ID is required: %w", store.ErrInvalidArgument)
	}
	if !status.Valid() {
		return fmt.Errorf("invalid tenant status %q: %w", status, store.ErrInvalidArgument)
	}
	_, err := s.pool.Exec(ctx, `
		INSERT INTO tenant (id, external_id, status)
		VALUES ($1, $2, $3)
	`, id.String(), externalID, string(status))
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == pgerrcode.UniqueViolation {
			return store.ErrRecordExists
		}
		return fmt.Errorf("adding tenant: %w", err)
	}
	return nil
}

func (s *Store) Get(ctx context.Context, id did.DID) (tenant.Record, error) {
	row := s.pool.QueryRow(ctx, `
		SELECT id, external_id, status, created_at, updated_at
		FROM tenant
		WHERE id = $1
	`, id.String())
	rec, err := scanRecord(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return tenant.Record{}, store.ErrRecordNotFound
	}
	if err != nil {
		return tenant.Record{}, fmt.Errorf("getting tenant: %w", err)
	}
	return rec, nil
}

func (s *Store) GetByExternalID(ctx context.Context, externalID string) (tenant.Record, error) {
	row := s.pool.QueryRow(ctx, `
		SELECT id, external_id, status, created_at, updated_at
		FROM tenant
		WHERE external_id = $1
	`, externalID)
	rec, err := scanRecord(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return tenant.Record{}, store.ErrRecordNotFound
	}
	if err != nil {
		return tenant.Record{}, fmt.Errorf("getting tenant by external id: %w", err)
	}
	return rec, nil
}

func (s *Store) SetStatus(ctx context.Context, id did.DID, status tenant.Status) error {
	return s.ChangeStatus(ctx, id, status, nil)
}

func (s *Store) ChangeStatus(ctx context.Context, id did.DID, status tenant.Status, beforeCommit func(context.Context, tenant.Record) error) (err error) {
	if !status.Valid() {
		return fmt.Errorf("invalid tenant status %q: %w", status, store.ErrInvalidArgument)
	}
	defer func() { err = pglock.MapError(err) }()
	tx, err := pglock.Begin(ctx, s.pool)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if err := pglock.SetTimeout(ctx, tx); err != nil {
		return err
	}
	if err := pglock.Advisory(ctx, tx, tenant.LockNamespace, id.String(), false); err != nil {
		return err
	}
	rec, err := scanRecord(tx.QueryRow(ctx, `SELECT id, external_id, status, created_at, updated_at FROM tenant WHERE id = $1 FOR UPDATE`, id.String()))
	if errors.Is(err, pgx.ErrNoRows) {
		return store.ErrRecordNotFound
	}
	if err != nil {
		return err
	}
	if beforeCommit != nil {
		if err := beforeCommit(pglock.WithTx(ctx, tx), rec); err != nil {
			return err
		}
	}
	tag, err := tx.Exec(ctx, `
		UPDATE tenant
		SET status = $1, updated_at = NOW()
		WHERE id = $2
	`, string(status), id.String())
	if err != nil {
		return fmt.Errorf("setting tenant status: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return store.ErrRecordNotFound
	}
	return tx.Commit(ctx)
}

func (s *Store) WithReadLock(ctx context.Context, id did.DID, fn func(context.Context, tenant.Record) error) (err error) {
	defer func() { err = pglock.MapError(err) }()
	tx, err := pglock.Begin(ctx, s.pool)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if err := pglock.SetTimeout(ctx, tx); err != nil {
		return err
	}
	if err := pglock.Advisory(ctx, tx, tenant.LockNamespace, id.String(), true); err != nil {
		return err
	}
	rec, err := scanRecord(tx.QueryRow(ctx, `SELECT id, external_id, status, created_at, updated_at FROM tenant WHERE id = $1 FOR SHARE`, id.String()))
	if errors.Is(err, pgx.ErrNoRows) {
		return store.ErrRecordNotFound
	}
	if err != nil {
		return err
	}
	if err := fn(pglock.WithTx(ctx, tx), rec); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (s *Store) Delete(ctx context.Context, id did.DID) (err error) {
	defer func() { err = pglock.MapError(err) }()
	tx, err := pglock.Begin(ctx, s.pool)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if err := pglock.SetTimeout(ctx, tx); err != nil {
		return err
	}
	if err := pglock.Advisory(ctx, tx, tenant.LockNamespace, id.String(), false); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `DELETE FROM tenant WHERE id = $1`, id.String()); err != nil {
		return fmt.Errorf("deleting tenant: %w", err)
	}
	return tx.Commit(ctx)
}

func scanRecord(row pgx.Row) (tenant.Record, error) {
	var (
		idStr      string
		externalID *string
		status     string
		createdAt  time.Time
		updatedAt  time.Time
	)
	if err := row.Scan(&idStr, &externalID, &status, &createdAt, &updatedAt); err != nil {
		return tenant.Record{}, err
	}
	id, err := did.Parse(idStr)
	if err != nil {
		return tenant.Record{}, fmt.Errorf("parsing tenant DID: %w", err)
	}
	rec := tenant.Record{
		ID:        id,
		Status:    tenant.Status(status),
		CreatedAt: createdAt,
		UpdatedAt: updatedAt,
	}
	if externalID != nil {
		rec.ExternalID = *externalID
	}
	return rec, nil
}
