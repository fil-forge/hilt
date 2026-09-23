// Package postgres provides a PostgreSQL-backed implementation of
// delegation.Store. Encoded delegation payloads are stored directly in the
// delegation table's data column. Every write that mutates an audience's set
// (PutBatch, Replace, DeleteByAudience) runs in a transaction holding that
// audience's advisory lock, so the writes of one audience serialize.
package postgres

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/fil-forge/hilt/pkg/store"
	dlgstore "github.com/fil-forge/hilt/pkg/store/delegation"
	"github.com/fil-forge/hilt/pkg/store/pglock"
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

// PutBatch stores the batch in one transaction holding the advisory lock of
// every audience it touches, so a concurrent Replace of any of them sees the
// whole batch or none of it.
func (s *Store) PutBatch(ctx context.Context, delegations []ucan.Delegation) error {
	// Validate the whole batch before storing anything.
	if slices.Contains(delegations, nil) {
		return fmt.Errorf("delegations must not be nil: %w", store.ErrInvalidArgument)
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("beginning transaction: %w", err)
	}
	defer tx.Rollback(ctx) // no-op once committed; rolls back on any early return

	audiences := make([]string, 0, len(delegations))
	for _, d := range delegations {
		audiences = append(audiences, d.Audience().String())
	}
	if err := lockAudiences(ctx, tx, audiences...); err != nil {
		return pglock.MapError(err)
	}

	for _, d := range delegations {
		if err := insert(ctx, tx, d); err != nil {
			return err
		}
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("committing transaction: %w", err)
	}
	return nil
}

// insert stores one delegation inside tx, leaving an already-stored one alone.
func insert(ctx context.Context, tx pgx.Tx, d ucan.Delegation) error {
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
	return nil
}

// lockNamespace is the first key of the advisory lock every audience-mutating
// write takes per audience. Postgres identifies an advisory lock by its key
// pair and nothing else, so the fixed first key keeps this store's locks apart
// from any other advisory lock taken on the same database; the second key is
// hashtext(audience DID).
const lockNamespace int32 = 0x44454c47 // "DELG"

// lockAudiences bounds tx's lock waits at [store.LockTimeout] and takes the
// exclusive advisory lock of each distinct audience, in sorted order. The order is what keeps two
// transactions locking overlapping audiences from deadlocking: they queue for
// the shared audiences in the same sequence. The locks are released when tx
// commits or rolls back.
func lockAudiences(ctx context.Context, tx pgx.Tx, audiences ...string) error {
	if err := pglock.SetTimeout(ctx, tx); err != nil {
		return err
	}
	slices.Sort(audiences)
	for _, aud := range slices.Compact(audiences) {
		if err := pglock.Advisory(ctx, tx, lockNamespace, aud, false); err != nil {
			return fmt.Errorf("locking delegation audience: %w", err)
		}
	}
	return nil
}

// Replace runs in one transaction that takes the audiences' advisory locks
// (released when the transaction ends), reads the current sets, calls next,
// deletes the sets and inserts next's result. Another write of any of the
// audiences waits on the lock until the first commits or rolls back, so it
// sees the settled state; the holder runs next while it holds the locks, so
// the wait is bounded at [store.LockTimeout] and a longer one returns
// [store.ErrLockTimeout].
func (s *Store) Replace(ctx context.Context, audiences []did.DID, next func(ctx context.Context, current map[did.DID][]ucan.Delegation) (map[did.DID][]ucan.Delegation, error)) error {
	return pglock.MapError(s.replace(ctx, audiences, next))
}

func (s *Store) replace(ctx context.Context, audiences []did.DID, next func(ctx context.Context, current map[did.DID][]ucan.Delegation) (map[did.DID][]ucan.Delegation, error)) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("beginning transaction: %w", err)
	}
	defer tx.Rollback(ctx) // no-op once committed; rolls back on any early return

	strs := make([]string, len(audiences))
	for i, aud := range audiences {
		strs[i] = aud.String()
	}
	if err := lockAudiences(ctx, tx, strs...); err != nil {
		return err
	}

	current := make(map[did.DID][]ucan.Delegation, len(audiences))
	for _, aud := range audiences {
		current[aud] = nil
	}
	rows, err := tx.Query(ctx, `SELECT id, data FROM delegation WHERE audience = ANY($1) ORDER BY id ASC`, strs)
	if err != nil {
		return fmt.Errorf("querying delegations by audience: %w", err)
	}
	for rows.Next() {
		var id string
		var data []byte
		if err := rows.Scan(&id, &data); err != nil {
			rows.Close()
			return fmt.Errorf("scanning delegation: %w", err)
		}
		dlg, err := delegation.Decode(data)
		if err != nil {
			rows.Close()
			return fmt.Errorf("decoding delegation %s: %w", id, err)
		}
		current[dlg.Audience()] = append(current[dlg.Audience()], dlg)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return fmt.Errorf("iterating delegations: %w", err)
	}

	replacement, err := next(ctx, current)
	if err != nil {
		return err
	}
	for _, aud := range audiences {
		if slices.Contains(replacement[aud], nil) {
			return fmt.Errorf("delegations must not be nil: %w", store.ErrInvalidArgument)
		}
	}

	if _, err := tx.Exec(ctx, `DELETE FROM delegation WHERE audience = ANY($1)`, strs); err != nil {
		return fmt.Errorf("deleting delegations by audience: %w", err)
	}
	for _, aud := range audiences {
		for _, d := range replacement[aud] {
			if err := insert(ctx, tx, d); err != nil {
				return err
			}
		}
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("committing transaction: %w", err)
	}
	return nil
}

// listColumn is a delegation column a list query may filter on. The named type
// keeps the value a package-controlled constant rather than caller input, since it
// is interpolated into the query text.
type listColumn string

const (
	byAudience listColumn = "audience"
	bySubject  listColumn = "subject"
)

func (s *Store) ListByAudience(ctx context.Context, audience did.DID, opts ...store.PaginationOption) (store.Page[ucan.Delegation], error) {
	return s.listBy(ctx, byAudience, audience.String(), opts)
}

func (s *Store) ListBySubject(ctx context.Context, subject did.DID, opts ...store.PaginationOption) (store.Page[ucan.Delegation], error) {
	if !subject.Defined() {
		return store.Page[ucan.Delegation]{}, fmt.Errorf("cannot list powerline delegations: %w", store.ErrInvalidArgument)
	}
	// Powerline delegations store a NULL subject, which never matches an equality
	// filter, so they are excluded for free.
	return s.listBy(ctx, bySubject, subject.String(), opts)
}

// listBy returns a page of delegations whose column equals value, ordered by id so
// the keyset cursor is stable.
func (s *Store) listBy(ctx context.Context, column listColumn, value string, opts []store.PaginationOption) (store.Page[ucan.Delegation], error) {
	cfg := store.PaginationConfig{}
	for _, opt := range opts {
		opt(&cfg)
	}
	limit := defaultListLimit
	if cfg.Limit != nil && *cfg.Limit > 0 {
		limit = *cfg.Limit
	}

	args := []any{value, limit + 1}
	query := `
		SELECT id, data
		FROM delegation
		WHERE ` + string(column) + ` = $1
	`
	if cfg.Cursor != nil {
		args = append(args, *cfg.Cursor)
		query += ` AND id > $3`
	}
	query += ` ORDER BY id ASC LIMIT $2`

	rows, err := s.pool.Query(ctx, query, args...)
	if err != nil {
		return store.Page[ucan.Delegation]{}, fmt.Errorf("querying delegations by %s: %w", column, err)
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

// DeleteByAudience removes the audience's delegations in one transaction
// holding its advisory lock, so a concurrent Replace of the audience does not
// reinsert what this call deleted.
func (s *Store) DeleteByAudience(ctx context.Context, audience did.DID) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("beginning transaction: %w", err)
	}
	defer tx.Rollback(ctx) // no-op once committed; rolls back on any early return

	if err := lockAudiences(ctx, tx, audience.String()); err != nil {
		return pglock.MapError(err)
	}
	if _, err := tx.Exec(ctx, `DELETE FROM delegation WHERE audience = $1`, audience.String()); err != nil {
		return pglock.MapError(fmt.Errorf("deleting delegations by audience: %w", err))
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("committing transaction: %w", err)
	}
	return nil
}

// DeleteBySubject locks the audiences holding delegations over the subject
// before deleting them, so it does not interleave with a Replace of one of
// those audiences.
func (s *Store) DeleteBySubject(ctx context.Context, subject did.DID) error {
	if !subject.Defined() {
		return fmt.Errorf("cannot delete powerline delegations: %w", store.ErrInvalidArgument)
	}
	return pglock.MapError(s.deleteBySubject(ctx, subject))
}

func (s *Store) deleteBySubject(ctx context.Context, subject did.DID) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("beginning transaction: %w", err)
	}
	defer tx.Rollback(ctx) // no-op once committed; rolls back on any early return

	rows, err := tx.Query(ctx, `SELECT DISTINCT audience FROM delegation WHERE subject = $1`, subject.String())
	if err != nil {
		return fmt.Errorf("querying delegation audiences by subject: %w", err)
	}
	audiences, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		return fmt.Errorf("scanning delegation audiences: %w", err)
	}
	if err := lockAudiences(ctx, tx, audiences...); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `DELETE FROM delegation WHERE subject = $1`, subject.String()); err != nil {
		return fmt.Errorf("deleting delegations by subject: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("committing transaction: %w", err)
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
		return nil, nil, fmt.Errorf("missing proof chain subject: %w", store.ErrInvalidArgument)
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
