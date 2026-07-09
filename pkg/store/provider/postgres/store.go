// Package postgres provides a PostgreSQL-backed implementation of provider.Store.
package postgres

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/fil-forge/hilt/pkg/store"
	"github.com/fil-forge/hilt/pkg/store/provider"
	"github.com/fil-forge/ucantone/did"
	"github.com/jackc/pgerrcode"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

type Store struct {
	pool *pgxpool.Pool
}

var _ provider.Store = (*Store)(nil)

func New(pool *pgxpool.Pool) *Store {
	return &Store{pool: pool}
}

// Initialize is a no-op. Schema is managed by the shared goose migrations.
func (s *Store) Initialize(ctx context.Context) error { return nil }

func (s *Store) Add(ctx context.Context, id did.DID, region string) error {
	if id == did.Undef {
		return fmt.Errorf("provider ID is required: %w", store.ErrInvalidArgument)
	}
	if region == "" {
		return fmt.Errorf("provider region is required: %w", store.ErrInvalidArgument)
	}
	_, err := s.pool.Exec(ctx, `
		INSERT INTO provider (id, region)
		VALUES ($1, $2)
	`, id.String(), region)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == pgerrcode.UniqueViolation {
			return store.ErrRecordExists
		}
		return fmt.Errorf("adding provider: %w", err)
	}
	return nil
}

func (s *Store) GetByRegion(ctx context.Context, region string) (provider.Record, error) {
	row := s.pool.QueryRow(ctx, `
		SELECT id, region, created_at, updated_at
		FROM provider
		WHERE region = $1
	`, region)
	rec, err := scanRecord(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return provider.Record{}, store.ErrRecordNotFound
	}
	if err != nil {
		return provider.Record{}, fmt.Errorf("getting provider by region: %w", err)
	}
	return rec, nil
}

type rowScanner interface {
	Scan(dest ...any) error
}

func scanRecord(row rowScanner) (provider.Record, error) {
	var (
		idStr     string
		region    *string
		createdAt time.Time
		updatedAt *time.Time
	)
	if err := row.Scan(&idStr, &region, &createdAt, &updatedAt); err != nil {
		return provider.Record{}, err
	}
	id, err := did.Parse(idStr)
	if err != nil {
		return provider.Record{}, fmt.Errorf("parsing provider DID: %w", err)
	}
	rec := provider.Record{
		ID:        id,
		CreatedAt: createdAt,
	}
	if region != nil {
		rec.Region = *region
	}
	if updatedAt != nil {
		rec.UpdatedAt = *updatedAt
	}
	return rec, nil
}
