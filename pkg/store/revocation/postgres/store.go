// Package postgres provides a PostgreSQL-backed implementation of
// revocation.Store.
package postgres

import (
	"context"
	"fmt"
	"time"

	"github.com/fil-forge/hilt/pkg/store"
	"github.com/fil-forge/hilt/pkg/store/pglock"
	"github.com/fil-forge/hilt/pkg/store/revocation"
	"github.com/fil-forge/ucantone/did"
	"github.com/fil-forge/ucantone/ucan"
	"github.com/fil-forge/ucantone/ucan/delegation"
	"github.com/ipfs/go-cid"
	"github.com/jackc/pgx/v5/pgxpool"
)

type Store struct {
	pool *pgxpool.Pool
}

var _ revocation.Store = (*Store)(nil)

func New(pool *pgxpool.Pool) *Store {
	return &Store{pool: pool}
}

func (s *Store) Add(ctx context.Context, tenant did.DID, delegations []ucan.Delegation) error {
	st, err := s.AddStatement(tenant, delegations)
	if err != nil {
		return err
	}
	if len(delegations) == 0 {
		return nil
	}
	if err := s.exec(ctx, st); err != nil {
		return fmt.Errorf("recording %d revocations owed: %w", len(delegations), err)
	}
	return nil
}

// AddStatement builds one statement for the whole batch. Each column travels
// as one array parameter, so the statement's size stays the same however many
// delegations it records.
func (s *Store) AddStatement(tenant did.DID, delegations []ucan.Delegation) (store.Statement, error) {
	if tenant == did.Undef {
		return store.Statement{}, fmt.Errorf("tenant is required: %w", store.ErrInvalidArgument)
	}
	ids := make([]string, len(delegations))
	datas := make([][]byte, len(delegations))
	for i, d := range delegations {
		if d == nil {
			return store.Statement{}, fmt.Errorf("delegations must not be nil: %w", store.ErrInvalidArgument)
		}
		if d.Issuer() != tenant {
			return store.Statement{}, fmt.Errorf("delegation %s was not issued by the tenant: %w", d.Link(), store.ErrInvalidArgument)
		}
		data, err := delegation.Encode(d)
		if err != nil {
			return store.Statement{}, fmt.Errorf("encoding delegation %s: %w", d.Link(), err)
		}
		ids[i], datas[i] = d.Link().String(), data
	}
	return store.Statement{
		SQL: `
			INSERT INTO revocation_owed (id, tenant_id, data)
			SELECT r.id, $1, r.data FROM unnest($2::text[], $3::bytea[]) AS r(id, data)
			ON CONFLICT (id) DO NOTHING`,
		Args: []any{tenant.String(), ids, datas},
	}, nil
}

func (s *Store) Oldest(ctx context.Context, tenant did.DID, after revocation.Cursor, limit int) ([]ucan.Delegation, revocation.Cursor, error) {
	// The zero cursor's time is before every row's, so one query text serves
	// the first page and the rest, on the (tenant_id, recorded_at, id) index.
	rows, err := s.pool.Query(ctx, `
		SELECT id, recorded_at, data FROM revocation_owed
		WHERE tenant_id = $1 AND (recorded_at, id) > ($2, $3)
		ORDER BY recorded_at, id
		LIMIT $4
	`, tenant.String(), after.RecordedAt, after.ID, limit)
	if err != nil {
		return nil, after, fmt.Errorf("reading revocations owed: %w", err)
	}
	defer rows.Close()
	var out []ucan.Delegation
	next := after
	for rows.Next() {
		var data []byte
		if err := rows.Scan(&next.ID, &next.RecordedAt, &data); err != nil {
			return nil, after, fmt.Errorf("reading revocations owed: %w", err)
		}
		d, err := delegation.Decode(data)
		if err != nil {
			return nil, after, fmt.Errorf("decoding a delegation owed a revocation: %w", err)
		}
		out = append(out, d)
	}
	if err := rows.Err(); err != nil {
		return nil, after, fmt.Errorf("reading revocations owed: %w", err)
	}
	return out, next, nil
}

func (s *Store) Delete(ctx context.Context, ids []cid.Cid) error {
	if len(ids) == 0 {
		return nil
	}
	if err := s.exec(ctx, s.DeleteStatement(ids)); err != nil {
		return fmt.Errorf("deleting %d revocations owed: %w", len(ids), err)
	}
	return nil
}

func (s *Store) DeleteStatement(ids []cid.Cid) store.Statement {
	strs := make([]string, len(ids))
	for i, id := range ids {
		strs[i] = id.String()
	}
	return store.Statement{
		SQL:  `DELETE FROM revocation_owed WHERE id = ANY($1::text[])`,
		Args: []any{strs},
	}
}

func (s *Store) Stats(ctx context.Context) (revocation.Stats, error) {
	var (
		count int64
		age   float64
	)
	// The age is taken on the database's clock, which stamped the rows.
	err := s.pool.QueryRow(ctx, `
		SELECT COUNT(*), COALESCE(EXTRACT(EPOCH FROM (NOW() - MIN(recorded_at))), 0)::float8
		FROM revocation_owed
	`).Scan(&count, &age)
	if err != nil {
		return revocation.Stats{}, fmt.Errorf("counting revocations owed: %w", err)
	}
	return revocation.Stats{Count: count, OldestAge: time.Duration(age * float64(time.Second))}, nil
}

// exec runs st in the transaction ctx carries, or in one of its own.
func (s *Store) exec(ctx context.Context, st store.Statement) error {
	tx, err := pglock.Begin(ctx, s.pool)
	if err != nil {
		return fmt.Errorf("beginning transaction: %w", err)
	}
	defer tx.Rollback(ctx) // no-op once committed; rolls back on any early return
	if _, err := tx.Exec(ctx, st.SQL, st.Args...); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("committing transaction: %w", err)
	}
	return nil
}
