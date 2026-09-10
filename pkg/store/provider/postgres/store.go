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

func (s *Store) Add(ctx context.Context, id did.DID, region string, policy *did.DID) error {
	if id == did.Undef {
		return fmt.Errorf("provider ID is required: %w", store.ErrInvalidArgument)
	}
	if region == "" {
		return fmt.Errorf("provider region is required: %w", store.ErrInvalidArgument)
	}
	var policyStr *string
	if policy != nil {
		if *policy == did.Undef {
			return fmt.Errorf("provider policy must be defined when set: %w", store.ErrInvalidArgument)
		}
		str := policy.String()
		policyStr = &str
	}
	_, err := s.pool.Exec(ctx, `
		INSERT INTO provider (id, region, policy)
		VALUES ($1, $2, $3)
	`, id.String(), region, policyStr)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == pgerrcode.UniqueViolation {
			return store.ErrRecordExists
		}
		return fmt.Errorf("adding provider: %w", err)
	}
	return nil
}

func (s *Store) Get(ctx context.Context, id did.DID) (provider.Record, error) {
	row := s.pool.QueryRow(ctx, `
		SELECT id, region, policy, created_at, updated_at
		FROM provider
		WHERE id = $1
	`, id.String())
	rec, err := scanRecord(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return provider.Record{}, store.ErrRecordNotFound
	}
	if err != nil {
		return provider.Record{}, fmt.Errorf("getting provider: %w", err)
	}
	return rec, nil
}

func (s *Store) SetPolicy(ctx context.Context, id did.DID, policy did.DID) error {
	if policy == did.Undef {
		return fmt.Errorf("provider policy is required: %w", store.ErrInvalidArgument)
	}
	tag, err := s.pool.Exec(ctx, `
		UPDATE provider
		SET policy = $2, updated_at = NOW()
		WHERE id = $1
	`, id.String(), policy.String())
	if err != nil {
		return fmt.Errorf("setting provider policy: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return store.ErrRecordNotFound
	}
	return nil
}

func (s *Store) GetByRegion(ctx context.Context, region string) (provider.Record, error) {
	row := s.pool.QueryRow(ctx, `
		SELECT id, region, policy, created_at, updated_at
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

func (s *Store) List(ctx context.Context) ([]provider.Record, error) {
	// COLLATE "C" orders by bytes. The database's default collation is locale
	// aware and case-insensitive at its primary level, which would order the
	// mixed-case base58 of did:key strings differently from the memory store.
	rows, err := s.pool.Query(ctx, `
		SELECT id, region, policy, created_at, updated_at
		FROM provider
		ORDER BY id COLLATE "C" ASC
	`)
	if err != nil {
		return nil, fmt.Errorf("listing providers: %w", err)
	}
	defer rows.Close()

	recs := []provider.Record{}
	for rows.Next() {
		rec, err := scanRecord(rows)
		if err != nil {
			return nil, err
		}
		recs = append(recs, rec)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterating providers: %w", err)
	}
	return recs, nil
}

func scanRecord(row pgx.Row) (provider.Record, error) {
	var (
		idStr     string
		region    *string
		policyStr *string
		createdAt time.Time
		updatedAt time.Time
	)
	if err := row.Scan(&idStr, &region, &policyStr, &createdAt, &updatedAt); err != nil {
		return provider.Record{}, err
	}
	id, err := did.Parse(idStr)
	if err != nil {
		return provider.Record{}, fmt.Errorf("parsing provider DID: %w", err)
	}
	rec := provider.Record{
		ID:        id,
		CreatedAt: createdAt,
		UpdatedAt: updatedAt,
	}
	if policyStr != nil {
		policy, err := did.Parse(*policyStr)
		if err != nil {
			return provider.Record{}, fmt.Errorf("parsing provider policy DID: %w", err)
		}
		rec.Policy = &policy
	}
	if region != nil {
		rec.Region = *region
	}
	return rec, nil
}
