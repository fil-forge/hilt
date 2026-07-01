// Package postgres provides a PostgreSQL-backed implementation of tenant.Store.
package postgres

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/fil-forge/hilt/pkg/store"
	"github.com/fil-forge/hilt/pkg/store/tenant"
	"github.com/fil-forge/ucantone/did"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

const uniqueViolation = "23505"

type Store struct {
	pool *pgxpool.Pool
}

var _ tenant.Store = (*Store)(nil)

func New(pool *pgxpool.Pool) *Store {
	return &Store{pool: pool}
}

// Initialize is a no-op. Schema is managed by the shared goose migrations.
func (s *Store) Initialize(ctx context.Context) error { return nil }

func (s *Store) Add(ctx context.Context, id did.DID, provider did.DID, name string, status tenant.Status) error {
	_, err := s.pool.Exec(ctx, `
		INSERT INTO tenant (id, provider_id, name, status)
		VALUES ($1, $2, $3, $4)
	`, id.String(), provider.String(), name, string(status))
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == uniqueViolation {
			return store.ErrRecordExists
		}
		return fmt.Errorf("adding tenant: %w", err)
	}
	return nil
}

func (s *Store) Get(ctx context.Context, id did.DID) (tenant.Record, error) {
	row := s.pool.QueryRow(ctx, `
		SELECT id, provider_id, name, status, created_at, updated_at
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

func (s *Store) SetStatus(ctx context.Context, id did.DID, status tenant.Status) error {
	tag, err := s.pool.Exec(ctx, `
		UPDATE tenant
		SET status = $1, updated_at = $2
		WHERE id = $3
	`, string(status), time.Now().UTC(), id.String())
	if err != nil {
		return fmt.Errorf("setting tenant status: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return store.ErrRecordNotFound
	}
	return nil
}

type rowScanner interface {
	Scan(dest ...any) error
}

func scanRecord(row rowScanner) (tenant.Record, error) {
	var (
		idStr      string
		providerID *string
		name       *string
		status     string
		createdAt  time.Time
		updatedAt  *time.Time
	)
	if err := row.Scan(&idStr, &providerID, &name, &status, &createdAt, &updatedAt); err != nil {
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
	}
	if providerID != nil && *providerID != "" {
		provider, err := did.Parse(*providerID)
		if err != nil {
			return tenant.Record{}, fmt.Errorf("parsing provider DID: %w", err)
		}
		rec.Provider = provider
	}
	if name != nil {
		rec.Name = *name
	}
	if updatedAt != nil {
		rec.UpdatedAt = *updatedAt
	}
	return rec, nil
}
