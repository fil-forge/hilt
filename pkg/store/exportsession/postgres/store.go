// Package postgres provides a PostgreSQL-backed implementation of
// exportsession.Store.
package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/fil-forge/hilt/pkg/store"
	"github.com/fil-forge/hilt/pkg/store/exportsession"
	"github.com/fil-forge/ucantone/did"
	"github.com/ipfs/go-cid"
	"github.com/jackc/pgerrcode"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// openStates is the non-terminal predicate; it must match the partial indexes
// in the export_session migration.
const openStates = `state NOT IN ('released', 'aborted')`

const columns = `id, tenant_id, bucket_id, customer_key, state, root_cid, pinned_at, audit, created_at, updated_at, expires_at`

type Store struct {
	pool *pgxpool.Pool
}

var _ exportsession.Store = (*Store)(nil)

func New(pool *pgxpool.Pool) *Store {
	return &Store{pool: pool}
}

func (s *Store) Add(ctx context.Context, input exportsession.Input) error {
	if input.ID == "" || input.CustomerKey == "" {
		return store.ErrInvalidArgument
	}
	_, err := s.pool.Exec(ctx, `
		INSERT INTO export_session (id, tenant_id, bucket_id, customer_key, state, expires_at)
		VALUES ($1, $2, $3, $4, $5, $6)
	`, input.ID, input.Tenant.String(), input.Bucket.String(), input.CustomerKey, exportsession.Opened, input.ExpiresAt)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == pgerrcode.UniqueViolation {
			return store.ErrRecordExists
		}
		return fmt.Errorf("adding export session: %w", err)
	}
	return nil
}

func (s *Store) Get(ctx context.Context, id string) (exportsession.Record, error) {
	row := s.pool.QueryRow(ctx, `SELECT `+columns+` FROM export_session WHERE id = $1`, id)
	rec, err := scanRecord(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return exportsession.Record{}, store.ErrRecordNotFound
	}
	if err != nil {
		return exportsession.Record{}, fmt.Errorf("getting export session: %w", err)
	}
	return rec, nil
}

func (s *Store) Transition(ctx context.Context, id string, from, to exportsession.State) error {
	if !exportsession.ValidTransition(from, to) || to == exportsession.Pinned {
		return store.ErrInvalidArgument
	}
	tag, err := s.pool.Exec(ctx, `
		UPDATE export_session
		SET state = $3, updated_at = NOW()
		WHERE id = $1 AND state = $2
	`, id, from, to)
	if err != nil {
		return fmt.Errorf("transitioning export session: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return store.ErrRecordNotFound
	}
	return nil
}

func (s *Store) Pin(ctx context.Context, id string, root cid.Cid) error {
	if !root.Defined() {
		return store.ErrInvalidArgument
	}
	tag, err := s.pool.Exec(ctx, `
		UPDATE export_session
		SET state = $2, root_cid = $3, pinned_at = NOW(), updated_at = NOW()
		WHERE id = $1 AND state = $4
	`, id, exportsession.Pinned, root.String(), exportsession.PoPVerified)
	if err != nil {
		return fmt.Errorf("pinning export session: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return store.ErrRecordNotFound
	}
	return nil
}

func (s *Store) AppendAudit(ctx context.Context, id string, entry []byte) error {
	if !json.Valid(entry) {
		return store.ErrInvalidArgument
	}
	tag, err := s.pool.Exec(ctx, `
		UPDATE export_session
		SET audit = audit || jsonb_build_array($2::jsonb), updated_at = NOW()
		WHERE id = $1
	`, id, string(entry))
	if err != nil {
		return fmt.Errorf("appending export session audit: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return store.ErrRecordNotFound
	}
	return nil
}

func (s *Store) HasOpen(ctx context.Context, tenant did.DID) (bool, error) {
	var open bool
	err := s.pool.QueryRow(ctx,
		`SELECT EXISTS (SELECT 1 FROM export_session WHERE tenant_id = $1 AND `+openStates+`)`,
		tenant.String()).Scan(&open)
	if err != nil {
		return false, fmt.Errorf("checking open export sessions: %w", err)
	}
	return open, nil
}

func (s *Store) HasOpenForBucket(ctx context.Context, bucket did.DID) (bool, error) {
	var open bool
	err := s.pool.QueryRow(ctx,
		`SELECT EXISTS (SELECT 1 FROM export_session WHERE bucket_id = $1 AND `+openStates+`)`,
		bucket.String()).Scan(&open)
	if err != nil {
		return false, fmt.Errorf("checking open export sessions for bucket: %w", err)
	}
	return open, nil
}

func (s *Store) DeleteByTenant(ctx context.Context, tenant did.DID) error {
	_, err := s.pool.Exec(ctx, `DELETE FROM export_session WHERE tenant_id = $1`, tenant.String())
	if err != nil {
		return fmt.Errorf("deleting export sessions: %w", err)
	}
	return nil
}

func scanRecord(row pgx.Row) (exportsession.Record, error) {
	var (
		id, tenantStr, bucketStr string
		customerKey, state       string
		rootStr                  *string
		pinnedAt                 *time.Time
		audit                    []byte
		createdAt, updatedAt     time.Time
		expiresAt                time.Time
	)
	if err := row.Scan(&id, &tenantStr, &bucketStr, &customerKey, &state, &rootStr, &pinnedAt,
		&audit, &createdAt, &updatedAt, &expiresAt); err != nil {
		return exportsession.Record{}, err
	}
	tenant, err := did.Parse(tenantStr)
	if err != nil {
		return exportsession.Record{}, fmt.Errorf("parsing tenant DID: %w", err)
	}
	bucket, err := did.Parse(bucketStr)
	if err != nil {
		return exportsession.Record{}, fmt.Errorf("parsing bucket DID: %w", err)
	}
	rec := exportsession.Record{
		ID:          id,
		Tenant:      tenant,
		Bucket:      bucket,
		CustomerKey: customerKey,
		State:       exportsession.State(state),
		Audit:       audit,
		CreatedAt:   createdAt,
		UpdatedAt:   updatedAt,
		ExpiresAt:   expiresAt,
	}
	if rootStr != nil {
		if rec.Root, err = cid.Parse(*rootStr); err != nil {
			return exportsession.Record{}, fmt.Errorf("parsing root CID: %w", err)
		}
	}
	if pinnedAt != nil {
		rec.PinnedAt = *pinnedAt
	}
	return rec, nil
}
