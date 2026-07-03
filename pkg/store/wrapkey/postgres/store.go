// Package postgres provides a PostgreSQL-backed implementation of wrapkey.Store.
package postgres

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/fil-forge/hilt/pkg/store"
	"github.com/fil-forge/hilt/pkg/store/wrapkey"
	"github.com/fil-forge/ucantone/did"
	"github.com/jackc/pgerrcode"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

type Store struct {
	pool *pgxpool.Pool
}

var _ wrapkey.Store = (*Store)(nil)

func New(pool *pgxpool.Pool) *Store {
	return &Store{pool: pool}
}

func (s *Store) Add(ctx context.Context, rec wrapkey.Record) error {
	createdAt := rec.CreatedAt
	if createdAt.IsZero() {
		createdAt = time.Now().UTC()
	}
	_, err := s.pool.Exec(ctx, `
		INSERT INTO wrap_key (tenant_id, version, kid, status, epoch, vault_key, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
	`, rec.Tenant.String(), rec.Version, rec.KID, string(rec.Status), rec.Epoch, rec.VaultKey, createdAt)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == pgerrcode.UniqueViolation {
			// The (tenant, version) primary key, the unique kid, or the
			// single-active-key partial index was violated.
			return store.ErrRecordExists
		}
		return fmt.Errorf("adding wrap key: %w", err)
	}
	return nil
}

func (s *Store) GetActive(ctx context.Context, tenant did.DID) (wrapkey.Record, error) {
	row := s.pool.QueryRow(ctx, `
		SELECT tenant_id, version, kid, status, epoch, vault_key, created_at, archived_at
		FROM wrap_key
		WHERE tenant_id = $1 AND status = 'active'
	`, tenant.String())
	rec, err := scanRecord(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return wrapkey.Record{}, store.ErrRecordNotFound
	}
	if err != nil {
		return wrapkey.Record{}, fmt.Errorf("getting active wrap key: %w", err)
	}
	return rec, nil
}

func (s *Store) Get(ctx context.Context, tenant did.DID, version int) (wrapkey.Record, error) {
	row := s.pool.QueryRow(ctx, `
		SELECT tenant_id, version, kid, status, epoch, vault_key, created_at, archived_at
		FROM wrap_key
		WHERE tenant_id = $1 AND version = $2
	`, tenant.String(), version)
	rec, err := scanRecord(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return wrapkey.Record{}, store.ErrRecordNotFound
	}
	if err != nil {
		return wrapkey.Record{}, fmt.Errorf("getting wrap key: %w", err)
	}
	return rec, nil
}

func (s *Store) GetByKID(ctx context.Context, kid string) (wrapkey.Record, error) {
	row := s.pool.QueryRow(ctx, `
		SELECT tenant_id, version, kid, status, epoch, vault_key, created_at, archived_at
		FROM wrap_key
		WHERE kid = $1
	`, kid)
	rec, err := scanRecord(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return wrapkey.Record{}, store.ErrRecordNotFound
	}
	if err != nil {
		return wrapkey.Record{}, fmt.Errorf("getting wrap key by kid: %w", err)
	}
	return rec, nil
}

func (s *Store) List(ctx context.Context, tenant did.DID) ([]wrapkey.Record, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT tenant_id, version, kid, status, epoch, vault_key, created_at, archived_at
		FROM wrap_key
		WHERE tenant_id = $1
		ORDER BY version DESC
	`, tenant.String())
	if err != nil {
		return nil, fmt.Errorf("listing wrap keys: %w", err)
	}
	defer rows.Close()

	var recs []wrapkey.Record
	for rows.Next() {
		rec, err := scanRecord(rows)
		if err != nil {
			return nil, fmt.Errorf("scanning wrap key: %w", err)
		}
		recs = append(recs, rec)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterating wrap keys: %w", err)
	}
	return recs, nil
}

func (s *Store) Archive(ctx context.Context, tenant did.DID, version int) error {
	tag, err := s.pool.Exec(ctx, `
		UPDATE wrap_key
		SET status = 'archived', archived_at = $1
		WHERE tenant_id = $2 AND version = $3
	`, time.Now().UTC(), tenant.String(), version)
	if err != nil {
		return fmt.Errorf("archiving wrap key: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return store.ErrRecordNotFound
	}
	return nil
}

func (s *Store) DeleteByTenant(ctx context.Context, tenant did.DID) error {
	_, err := s.pool.Exec(ctx, `
		DELETE FROM wrap_key
		WHERE tenant_id = $1
	`, tenant.String())
	if err != nil {
		return fmt.Errorf("deleting wrap keys: %w", err)
	}
	return nil
}

type rowScanner interface {
	Scan(dest ...any) error
}

func scanRecord(row rowScanner) (wrapkey.Record, error) {
	var (
		tenantStr  string
		version    int
		kid        string
		status     string
		epoch      int
		vaultKey   string
		createdAt  time.Time
		archivedAt *time.Time
	)
	if err := row.Scan(&tenantStr, &version, &kid, &status, &epoch, &vaultKey, &createdAt, &archivedAt); err != nil {
		return wrapkey.Record{}, err
	}
	tenant, err := did.Parse(tenantStr)
	if err != nil {
		return wrapkey.Record{}, fmt.Errorf("parsing tenant DID: %w", err)
	}
	rec := wrapkey.Record{
		Tenant:    tenant,
		Version:   version,
		KID:       kid,
		Status:    wrapkey.Status(status),
		Epoch:     epoch,
		VaultKey:  vaultKey,
		CreatedAt: createdAt,
	}
	if archivedAt != nil {
		rec.ArchivedAt = *archivedAt
	}
	return rec, nil
}
