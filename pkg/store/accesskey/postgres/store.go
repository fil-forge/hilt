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
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

const uniqueViolation = "23505"

type Store struct {
	pool *pgxpool.Pool
}

var _ accesskey.Store = (*Store)(nil)

func New(pool *pgxpool.Pool) *Store {
	return &Store{pool: pool}
}

// Initialize is a no-op. Schema is managed by the shared goose migrations.
func (s *Store) Initialize(ctx context.Context) error { return nil }

func (s *Store) Add(ctx context.Context, id did.DID, tenant did.DID, name string, buckets []did.DID, permissions []string) error {
	bucketStrs := make([]string, len(buckets))
	for i, b := range buckets {
		bucketStrs[i] = b.String()
	}
	if permissions == nil {
		permissions = []string{}
	}
	_, err := s.pool.Exec(ctx, `
		INSERT INTO access_key (id, tenant_id, name, buckets, permissions)
		VALUES ($1, $2, $3, $4, $5)
	`, id.String(), tenant.String(), name, bucketStrs, permissions)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == uniqueViolation {
			return store.ErrRecordExists
		}
		return fmt.Errorf("adding access key: %w", err)
	}
	return nil
}

func (s *Store) Get(ctx context.Context, id did.DID) (accesskey.Record, error) {
	row := s.pool.QueryRow(ctx, `
		SELECT id, tenant_id, name, buckets, permissions, created_at
		FROM access_key
		WHERE id = $1
	`, id.String())

	var (
		idStr      string
		tenantID   *string
		name       *string
		bucketStrs []string
		perms      []string
		createdAt  time.Time
	)
	err := row.Scan(&idStr, &tenantID, &name, &bucketStrs, &perms, &createdAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return accesskey.Record{}, store.ErrRecordNotFound
	}
	if err != nil {
		return accesskey.Record{}, fmt.Errorf("getting access key: %w", err)
	}

	parsedID, err := did.Parse(idStr)
	if err != nil {
		return accesskey.Record{}, fmt.Errorf("parsing access key DID: %w", err)
	}
	rec := accesskey.Record{
		ID:          parsedID,
		Name:        "",
		Permissions: perms,
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
