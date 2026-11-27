// Package postgres provides a PostgreSQL-backed implementation of bucket.Store.
package postgres

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/fil-forge/hilt/pkg/store"
	"github.com/fil-forge/hilt/pkg/store/bucket"
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

var _ bucket.Store = (*Store)(nil)

func New(pool *pgxpool.Pool) *Store {
	return &Store{pool: pool}
}

// Initialize is a no-op. Schema is managed by the shared goose migrations.
func (s *Store) Initialize(ctx context.Context) error { return nil }

func (s *Store) Add(ctx context.Context, id did.DID, tenant did.DID, provider did.DID, name string) error {
	if id == did.Undef {
		return fmt.Errorf("bucket ID is required: %w", store.ErrInvalidArgument)
	}
	if tenant == did.Undef {
		return fmt.Errorf("bucket tenant is required: %w", store.ErrInvalidArgument)
	}
	if provider == did.Undef {
		return fmt.Errorf("bucket provider is required: %w", store.ErrInvalidArgument)
	}
	if err := bucket.ValidateName(name); err != nil {
		return err
	}
	_, err := s.pool.Exec(ctx, `
		INSERT INTO bucket (id, tenant_id, provider_id, name)
		VALUES ($1, $2, $3, $4)
	`, id.String(), tenant.String(), provider.String(), name)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == pgerrcode.UniqueViolation {
			return store.ErrRecordExists
		}
		return fmt.Errorf("adding bucket: %w", err)
	}
	return nil
}

func (s *Store) GetByName(ctx context.Context, name string) (bucket.Record, error) {
	row := pglock.Reader(ctx, s.pool).QueryRow(ctx, `
		SELECT id, tenant_id, provider_id, name, created_at
		FROM bucket
		WHERE name = $1
	`, name)
	rec, err := scanRecord(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return bucket.Record{}, store.ErrRecordNotFound
	}
	if err != nil {
		return bucket.Record{}, fmt.Errorf("getting bucket by name: %w", err)
	}
	return rec, nil
}

const defaultListLimit = 1000

func (s *Store) ListByTenant(ctx context.Context, tenant did.DID, opts ...bucket.ListOption) (store.Page[bucket.Record], error) {
	cfg := bucket.ListConfig{}
	for _, opt := range opts {
		opt(&cfg)
	}
	if len(cfg.IDs) > 0 && len(cfg.Names) > 0 {
		return store.Page[bucket.Record]{}, bucket.ErrConflictingFilters
	}
	limit := defaultListLimit
	if cfg.Limit != nil && *cfg.Limit > 0 {
		limit = *cfg.Limit
	}

	// $1 = tenant, $2 = limit+1; further filters use dynamic placeholders.
	args := []any{tenant.String(), limit + 1}
	query := `
		SELECT id, tenant_id, provider_id, name, created_at
		FROM bucket
		WHERE tenant_id = $1
	`
	if len(cfg.IDs) > 0 {
		ids := make([]string, len(cfg.IDs))
		for i, id := range cfg.IDs {
			ids[i] = id.String()
		}
		args = append(args, ids)
		query += fmt.Sprintf(" AND id = ANY($%d)", len(args))
	}
	if len(cfg.Names) > 0 {
		args = append(args, cfg.Names)
		query += fmt.Sprintf(" AND name = ANY($%d)", len(args))
	}
	if cfg.Prefix != "" {
		// starts_with matches literally — a LIKE pattern would treat %/_ in the
		// caller-supplied prefix as wildcards.
		args = append(args, cfg.Prefix)
		query += fmt.Sprintf(" AND starts_with(name, $%d)", len(args))
	}
	if cfg.Provider.Defined() {
		args = append(args, cfg.Provider.String())
		query += fmt.Sprintf(" AND provider_id = $%d", len(args))
	}
	if cfg.Cursor != nil {
		args = append(args, *cfg.Cursor)
		query += fmt.Sprintf(" AND name > $%d", len(args))
	}
	query += ` ORDER BY name ASC LIMIT $2`

	rows, err := pglock.Reader(ctx, s.pool).Query(ctx, query, args...)
	if err != nil {
		return store.Page[bucket.Record]{}, fmt.Errorf("listing buckets by tenant: %w", err)
	}
	defer rows.Close()

	recs := make([]bucket.Record, 0, limit)
	for rows.Next() {
		rec, err := scanRecord(rows)
		if err != nil {
			return store.Page[bucket.Record]{}, err
		}
		recs = append(recs, rec)
	}
	if err := rows.Err(); err != nil {
		return store.Page[bucket.Record]{}, fmt.Errorf("iterating buckets: %w", err)
	}

	var cursor *string
	if len(recs) > limit {
		last := recs[limit-1].Name
		cursor = &last
		recs = recs[:limit]
	}
	return store.Page[bucket.Record]{Cursor: cursor, Results: recs}, nil
}

// Delete removes the bucket row, and with it, by cascade, its policy and the
// policy's index rows, and records who the bucket belonged to (see
// [Store.Owner]), in one statement, so the bucket is never gone without its
// owner recorded.
func (s *Store) Delete(ctx context.Context, id did.DID) error {
	if _, err := s.pool.Exec(ctx, fmt.Sprintf(deleteSQL, ""), id.String()); err != nil {
		return fmt.Errorf("deleting bucket: %w", err)
	}
	return nil
}

// deleteSQL deletes the bucket $1, with the condition the caller appends,
// and records its owner.
const deleteSQL = `
		WITH gone AS (
			DELETE FROM bucket WHERE id = $1 %s RETURNING id, tenant_id, provider_id
		)
		INSERT INTO deleted_bucket (id, tenant_id, provider_id)
		SELECT id, tenant_id, provider_id FROM gone
		ON CONFLICT (id) DO NOTHING`

func (s *Store) DeleteStatement(tenant, id did.DID) store.Statement {
	return store.Statement{
		SQL:  fmt.Sprintf(deleteSQL, `AND tenant_id = $2`),
		Args: []any{id.String(), tenant.String()},
	}
}

func (s *Store) Owner(ctx context.Context, id did.DID) (bucket.Owner, error) {
	var (
		tenantStr, providerStr string
		deleted                bool
	)
	// A bucket ID is in one table or the other: it is generated at creation
	// and never reused.
	err := s.pool.QueryRow(ctx, `
		SELECT tenant_id, provider_id, FALSE FROM bucket WHERE id = $1
		UNION ALL
		SELECT tenant_id, provider_id, TRUE FROM deleted_bucket WHERE id = $1
		LIMIT 1
	`, id.String()).Scan(&tenantStr, &providerStr, &deleted)
	if errors.Is(err, pgx.ErrNoRows) {
		return bucket.Owner{}, store.ErrRecordNotFound
	}
	if err != nil {
		return bucket.Owner{}, fmt.Errorf("getting bucket owner: %w", err)
	}
	tenant, err := did.Parse(tenantStr)
	if err != nil {
		return bucket.Owner{}, fmt.Errorf("parsing tenant DID: %w", err)
	}
	provider, err := did.Parse(providerStr)
	if err != nil {
		return bucket.Owner{}, fmt.Errorf("parsing provider DID: %w", err)
	}
	return bucket.Owner{Tenant: tenant, Provider: provider, Deleted: deleted}, nil
}

func scanRecord(row pgx.Row) (bucket.Record, error) {
	var (
		idStr      string
		tenantID   *string
		providerID *string
		name       *string
		createdAt  time.Time
	)
	if err := row.Scan(&idStr, &tenantID, &providerID, &name, &createdAt); err != nil {
		return bucket.Record{}, err
	}
	id, err := did.Parse(idStr)
	if err != nil {
		return bucket.Record{}, fmt.Errorf("parsing bucket DID: %w", err)
	}
	rec := bucket.Record{
		ID:        id,
		CreatedAt: createdAt,
	}
	if tenantID != nil && *tenantID != "" {
		tenant, err := did.Parse(*tenantID)
		if err != nil {
			return bucket.Record{}, fmt.Errorf("parsing tenant DID: %w", err)
		}
		rec.Tenant = tenant
	}
	if providerID != nil && *providerID != "" {
		provider, err := did.Parse(*providerID)
		if err != nil {
			return bucket.Record{}, fmt.Errorf("parsing provider DID: %w", err)
		}
		rec.Provider = provider
	}
	if name != nil {
		rec.Name = *name
	}
	return rec, nil
}
