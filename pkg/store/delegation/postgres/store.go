// Package postgres provides a PostgreSQL-backed implementation of
// delegation.Store. Encoded delegation payloads are stored directly in the
// delegation table's data column.
package postgres

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/fil-forge/hilt/pkg/store"
	dlgstore "github.com/fil-forge/hilt/pkg/store/delegation"
	"github.com/fil-forge/ucantone/did"
	"github.com/fil-forge/ucantone/ucan"
	"github.com/fil-forge/ucantone/ucan/delegation"
	"github.com/ipfs/go-cid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

const defaultListLimit = 1000

type Store struct {
	pool *pgxpool.Pool
}

var _ dlgstore.Store = (*Store)(nil)

func New(pool *pgxpool.Pool) *Store {
	return &Store{pool: pool}
}

// Initialize is a no-op. Schema is managed by the shared goose migrations.
func (s *Store) Initialize(ctx context.Context) error { return nil }

func (s *Store) PutBatch(ctx context.Context, delegations []ucan.Delegation) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("beginning transaction: %w", err)
	}
	defer tx.Rollback(ctx) // no-op once committed; rolls back on any early return

	for _, d := range delegations {
		data, err := delegation.Encode(d)
		if err != nil {
			return fmt.Errorf("encoding delegation %s: %w", d.Link(), err)
		}

		var subject *string
		if d.Subject().Defined() {
			str := d.Subject().String()
			subject = &str
		}

		var expiresAt *time.Time
		if exp := d.Expiration(); exp != nil {
			t := time.Unix(int64(*exp), 0).UTC()
			expiresAt = &t
		}

		if _, err := tx.Exec(ctx, `
			INSERT INTO delegation (id, issuer, audience, subject, command, data, expires_at)
			VALUES ($1, $2, $3, $4, $5, $6, $7)
			ON CONFLICT (id) DO NOTHING
		`, d.Link().String(), d.Issuer().String(), d.Audience().String(), subject, d.Command().String(), data, expiresAt); err != nil {
			return fmt.Errorf("storing delegation %s: %w", d.Link(), err)
		}
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("committing transaction: %w", err)
	}
	return nil
}

func (s *Store) ListByAudience(ctx context.Context, audience did.DID, opts ...store.PaginationOption) (store.Page[ucan.Delegation], error) {
	cfg := store.PaginationConfig{}
	for _, opt := range opts {
		opt(&cfg)
	}
	limit := defaultListLimit
	if cfg.Limit != nil && *cfg.Limit > 0 {
		limit = *cfg.Limit
	}

	args := []any{audience.String(), limit + 1}
	query := `
		SELECT id, data
		FROM delegation
		WHERE audience = $1
	`
	if cfg.Cursor != nil {
		args = append(args, *cfg.Cursor)
		query += ` AND id > $3`
	}
	query += ` ORDER BY id ASC LIMIT $2`

	rows, err := s.pool.Query(ctx, query, args...)
	if err != nil {
		return store.Page[ucan.Delegation]{}, fmt.Errorf("querying delegations by audience: %w", err)
	}
	defer rows.Close()

	type row struct {
		id   string
		data []byte
	}
	var raw []row
	for rows.Next() {
		var r row
		if err := rows.Scan(&r.id, &r.data); err != nil {
			return store.Page[ucan.Delegation]{}, fmt.Errorf("scanning delegation: %w", err)
		}
		raw = append(raw, r)
	}
	if err := rows.Err(); err != nil {
		return store.Page[ucan.Delegation]{}, fmt.Errorf("iterating delegations: %w", err)
	}

	var cursor *string
	if len(raw) > limit {
		last := raw[limit-1].id
		cursor = &last
		raw = raw[:limit]
	}

	results := make([]ucan.Delegation, 0, len(raw))
	for _, r := range raw {
		dlg, err := delegation.Decode(r.data)
		if err != nil {
			return store.Page[ucan.Delegation]{}, fmt.Errorf("decoding delegation %s: %w", r.id, err)
		}
		results = append(results, dlg)
	}
	return store.Page[ucan.Delegation]{Cursor: cursor, Results: results}, nil
}

func (s *Store) DeleteByAudience(ctx context.Context, audience did.DID) error {
	if _, err := s.pool.Exec(ctx, `DELETE FROM delegation WHERE audience = $1`, audience.String()); err != nil {
		return fmt.Errorf("deleting delegations by audience: %w", err)
	}
	return nil
}

// ProofChain builds the proof chain from aud toward sub for cmd in a single
// recursive query. The walk follows edges audience -> issuer, matching the
// fixed subject (or NULL powerline delegations) and requiring each delegation's
// command to prove the child's command (the segment-boundary prefix test from
// command.Command.Proves). A delegation whose subject equals its issuer is the
// trust root and terminates a path. The shortest complete path is returned
// root-first, mirroring the in-memory store's use of libforge's ProofChain.
func (s *Store) ProofChain(ctx context.Context, aud did.DID, cmd ucan.Command, sub did.DID) ([]ucan.Delegation, []cid.Cid, error) {
	if !sub.Defined() {
		return nil, nil, fmt.Errorf("missing proof chain subject")
	}

	// The CTE accumulates encoded payloads (datas) and link ids along each path.
	// ids are used only for cycle protection. A path is "complete" once it
	// reaches a root (subject = issuer); such rows are not expanded further. The
	// command-proves test is expressed as an exact match, Top ("/"), or a
	// segment-boundary prefix, matching command.Command.Proves.
	const query = `
WITH RECURSIVE chain AS (
    SELECT d.issuer, d.command,
           (d.subject IS NOT NULL AND d.subject = d.issuer) AS complete,
           ARRAY[d.data] AS datas, ARRAY[d.id] AS ids, 1 AS depth
    FROM delegation d
    WHERE d.audience = $1
      AND (d.subject = $3 OR d.subject IS NULL)
      AND ( d.command = $2 OR d.command = '/'
            OR (length($2) > length(d.command)
                AND substr($2, 1, length(d.command)) = d.command
                AND substr($2, length(d.command) + 1, 1) = '/') )
  UNION ALL
    SELECT d.issuer, d.command,
           (d.subject IS NOT NULL AND d.subject = d.issuer),
           c.datas || d.data, c.ids || d.id, c.depth + 1
    FROM delegation d
    JOIN chain c ON d.audience = c.issuer
    WHERE NOT c.complete
      AND (d.subject = $3 OR d.subject IS NULL)
      AND ( d.command = c.command OR d.command = '/'
            OR (length(c.command) > length(d.command)
                AND substr(c.command, 1, length(d.command)) = d.command
                AND substr(c.command, length(d.command) + 1, 1) = '/') )
      AND d.id <> ALL(c.ids)
)
SELECT datas FROM chain WHERE complete ORDER BY depth ASC LIMIT 1
`

	var datas [][]byte
	err := s.pool.QueryRow(ctx, query, aud.String(), cmd.String(), sub.String()).Scan(&datas)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil, nil
		}
		return nil, nil, fmt.Errorf("building proof chain: %w", err)
	}

	// The path is accumulated leaf -> root; invocation order is root-first.
	slices.Reverse(datas)

	proofs := make([]ucan.Delegation, 0, len(datas))
	links := make([]cid.Cid, 0, len(datas))
	for _, data := range datas {
		dlg, err := delegation.Decode(data)
		if err != nil {
			return nil, nil, fmt.Errorf("decoding proof chain delegation: %w", err)
		}
		proofs = append(proofs, dlg)
		links = append(links, dlg.Link())
	}
	return proofs, links, nil
}
