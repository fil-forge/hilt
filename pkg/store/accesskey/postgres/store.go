// Package postgres provides a PostgreSQL-backed implementation of accesskey.Store.
package postgres

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/fil-forge/hilt/pkg/store"
	"github.com/fil-forge/hilt/pkg/store/accesskey"
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

func (s *Store) Add(ctx context.Context, id did.DID, tenant did.DID, name string, buckets []did.DID, permissions []string, expiresAt *time.Time) error {
	bucketStrs := make([]string, len(buckets))
	for i, b := range buckets {
		bucketStrs[i] = b.String()
	}
	if permissions == nil {
		permissions = []string{}
	}
	var expires *time.Time
	if expiresAt != nil {
		e := expiresAt.UTC()
		expires = &e
	}
	_, err := s.pool.Exec(ctx, `
		INSERT INTO access_key (id, tenant_id, name, buckets, permissions, expires_at)
		VALUES ($1, $2, $3, $4, $5, $6)
	`, id.String(), tenant.String(), name, bucketStrs, permissions, expires)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == pgerrcode.UniqueViolation {
			return store.ErrRecordExists
		}
		return fmt.Errorf("adding access key: %w", err)
	}
	return nil
}

func (s *Store) Get(ctx context.Context, id did.DID) (accesskey.Record, error) {
	row := s.pool.QueryRow(ctx, `
		SELECT id, tenant_id, name, buckets, permissions, expires_at, created_at
		FROM access_key
		WHERE id = $1
	`, id.String())
	rec, err := scanRecord(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return accesskey.Record{}, store.ErrRecordNotFound
	}
	if err != nil {
		return accesskey.Record{}, fmt.Errorf("getting access key: %w", err)
	}
	return rec, nil
}

func (s *Store) ListByTenant(ctx context.Context, tenant did.DID) ([]accesskey.Record, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, tenant_id, name, buckets, permissions, expires_at, created_at
		FROM access_key
		WHERE tenant_id = $1
		ORDER BY id ASC
	`, tenant.String())
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

func (s *Store) Delete(ctx context.Context, id did.DID) error {
	if _, err := s.pool.Exec(ctx, `DELETE FROM access_key WHERE id = $1`, id.String()); err != nil {
		return fmt.Errorf("deleting access key: %w", err)
	}
	return nil
}

func scanRecord(row pgx.Row) (accesskey.Record, error) {
	var (
		idStr      string
		tenantID   *string
		name       *string
		bucketStrs []string
		perms      []string
		expiresAt  *time.Time
		createdAt  time.Time
	)
	if err := row.Scan(&idStr, &tenantID, &name, &bucketStrs, &perms, &expiresAt, &createdAt); err != nil {
		return accesskey.Record{}, err
	}

	id, err := did.Parse(idStr)
	if err != nil {
		return accesskey.Record{}, fmt.Errorf("parsing access key DID: %w", err)
	}
	rec := accesskey.Record{
		ID:          id,
		Permissions: perms,
		ExpiresAt:   expiresAt,
		CreatedAt:   createdAt,
	}
	if tenantID != nil && *tenantID != "" {
		tenant, err := did.Parse(*tenantID)
		if err != nil {
			return accesskey.Record{}, fmt.Errorf("parsing tenant DID: %w", err)
		}
		rec.Tenant = tenant
	}
	if name != nil {
		rec.Name = *name
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
