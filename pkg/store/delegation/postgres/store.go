// Package postgres provides a PostgreSQL-backed implementation of
// delegation.Store. Encoded delegation payloads are stored directly in the
// delegation table's data column. The statements a task writes through take
// no lock: the tasks that change a tenant's grants run one at a time on the
// tenant's queue.
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

// PutBatch stores the batch in one statement.
func (s *Store) PutBatch(ctx context.Context, delegations []ucan.Delegation) error {
	// Validate the whole batch before storing anything.
	if slices.Contains(delegations, nil) {
		return fmt.Errorf("delegations must not be nil: %w", store.ErrInvalidArgument)
	}
	if len(delegations) == 0 {
		return nil
	}
	st, err := insertStatement(delegations)
	if err != nil {
		return err
	}
	if _, err := s.pool.Exec(ctx, st.SQL, st.Args...); err != nil {
		return fmt.Errorf("storing %d delegations: %w", len(delegations), err)
	}
	return nil
}

// insertStatement builds the insert of the delegations, leaving an
// already-stored one alone. Each column travels as one array parameter, so
// the statement's size and its round trip stay the same however many
// delegations a key or a policy change carries.
func insertStatement(dels []ucan.Delegation) (store.Statement, error) {
	var (
		ids        = make([]string, len(dels))
		issuers    = make([]string, len(dels))
		audiences  = make([]string, len(dels))
		subjects   = make([]*string, len(dels))
		commands   = make([]string, len(dels))
		datas      = make([][]byte, len(dels))
		expiresAts = make([]*time.Time, len(dels))
	)
	for i, d := range dels {
		data, err := delegation.Encode(d)
		if err != nil {
			return store.Statement{}, fmt.Errorf("encoding delegation %s: %w", d.Link(), err)
		}
		ids[i], issuers[i], audiences[i], commands[i], datas[i] = d.Link().String(), d.Issuer().String(), d.Audience().String(), d.Command().String(), data
		if d.Subject().Defined() {
			str := d.Subject().String()
			subjects[i] = &str
		}
		if exp := d.Expiration(); exp != nil {
			t := time.Unix(int64(*exp), 0).UTC()
			expiresAts[i] = &t
		}
	}
	return store.Statement{
		SQL: `
		INSERT INTO delegation (id, issuer, audience, subject, command, data, expires_at)
		SELECT d.* FROM unnest($1::text[], $2::text[], $3::text[], $4::text[], $5::text[], $6::bytea[], $7::timestamptz[])
			AS d(id, issuer, audience, subject, command, data, expires_at)
		ON CONFLICT (id) DO NOTHING`,
		Args: []any{ids, issuers, audiences, subjects, commands, datas, expiresAts},
	}, nil
}

func (s *Store) PutStatement(delegations []ucan.Delegation) (store.Statement, error) {
	if slices.Contains(delegations, nil) {
		return store.Statement{}, fmt.Errorf("delegations must not be nil: %w", store.ErrInvalidArgument)
	}
	return insertStatement(delegations)
}

func (s *Store) ListKeyGrants(ctx context.Context, tenant did.DID) ([]ucan.Delegation, error) {
	rows, err := pglock.Reader(ctx, s.pool).Query(ctx, `
		SELECT d.id, d.data FROM delegation d
		JOIN access_key k ON k.id = d.audience
		WHERE k.tenant_id = $1 AND d.issuer = $1
		ORDER BY d.id ASC`, tenant.String())
	if err != nil {
		return nil, fmt.Errorf("listing the grants of the tenant's access keys: %w", err)
	}
	defer rows.Close()
	var out []ucan.Delegation
	for rows.Next() {
		var id string
		var data []byte
		if err := rows.Scan(&id, &data); err != nil {
			return nil, fmt.Errorf("scanning delegation: %w", err)
		}
		dlg, err := delegation.Decode(data)
		if err != nil {
			return nil, fmt.Errorf("decoding delegation %s: %w", id, err)
		}
		out = append(out, dlg)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterating delegations: %w", err)
	}
	return out, nil
}

func (s *Store) DeleteTenantStatement(tenant did.DID) store.Statement {
	return store.Statement{
		SQL: `
		DELETE FROM delegation d
		WHERE d.issuer = $1 OR d.audience = $1
		   OR d.audience IN (SELECT k.id FROM access_key k WHERE k.tenant_id = $1)
		   OR d.subject IN (SELECT b.id FROM bucket b WHERE b.tenant_id = $1)`,
		Args: []any{tenant.String()},
	}
}

// withdrawSQL moves the rows of delegation d the condition the caller
// appends selects, with the tenant as $1 and the alias k free for a joined
// access_key, to revocation_owed.
const withdrawSQL = `
	WITH withdrawn AS (
		DELETE FROM delegation d
		%s
		RETURNING d.id, d.data
	)
	INSERT INTO revocation_owed (id, tenant_id, data)
	SELECT w.id, $1, w.data FROM withdrawn w
	ON CONFLICT (id) DO NOTHING`

func (s *Store) WithdrawKeyGrantsStatement(tenant did.DID) store.Statement {
	return store.Statement{
		SQL: fmt.Sprintf(withdrawSQL, `USING access_key k
		WHERE k.tenant_id = $1 AND d.audience = k.id AND d.issuer = $1`),
		Args: []any{tenant.String()},
	}
}

func (s *Store) WithdrawGrantsOverStatement(tenant, subject did.DID, principals []string) store.Statement {
	return store.Statement{
		SQL: fmt.Sprintf(withdrawSQL, `USING access_key k
		WHERE k.tenant_id = $1 AND k.principal_id = ANY($3)
		  AND d.audience = k.id AND d.subject = $2 AND d.issuer = $1`),
		Args: []any{tenant.String(), subject.String(), principals},
	}
}

// WithdrawGrantsOfKeyStatement does not read the key's row: the delegations
// are the audience's, whether or not the key still exists.
func (s *Store) WithdrawGrantsOfKeyStatement(tenant, key did.DID) store.Statement {
	return store.Statement{
		SQL:  fmt.Sprintf(withdrawSQL, `WHERE d.audience = $2 AND d.issuer = $1`),
		Args: []any{tenant.String(), key.String()},
	}
}

func (s *Store) WithdrawSubjectStatements(tenant, subject did.DID) []store.Statement {
	return []store.Statement{
		{
			SQL:  fmt.Sprintf(withdrawSQL, `WHERE d.subject = $2 AND d.issuer = $1`),
			Args: []any{tenant.String(), subject.String()},
		},
		{
			SQL:  `DELETE FROM delegation WHERE subject = $1`,
			Args: []any{subject.String()},
		},
	}
}

// dueGrant is the condition under which the delegation d, of the access key
// k, is a grant due for renewal before $1: the tenant issued it, it expires
// before $1 and ahead of its key, and the key holds no later delegation from
// the tenant over the same subject. A grant expires on a whole second, so a
// key's expiry is compared to the second.
//
// The later delegation may be for any command. Every write issues a key all
// its commands over a subject at once, so a key's grants over one subject
// share an expiry, and one that a later issue left out is a command the key
// no longer holds there, as after a change to the commands an S3 action maps
// to. Matching on the command too would keep such a grant due for good.
const dueGrant = `
	d.issuer = k.tenant_id
	AND d.expires_at < $1
	AND (k.expires_at IS NULL OR d.expires_at < date_trunc('second', k.expires_at))
	AND NOT EXISTS (
		SELECT 1 FROM delegation n
		WHERE n.audience = d.audience AND n.issuer = d.issuer
		  AND n.subject IS NOT DISTINCT FROM d.subject
		  AND (n.expires_at IS NULL OR n.expires_at > d.expires_at)
	)`

func (s *Store) TenantsWithGrantsDue(ctx context.Context, before time.Time) ([]did.DID, error) {
	rows, err := pglock.Reader(ctx, s.pool).Query(ctx, `
		SELECT DISTINCT k.tenant_id
		FROM delegation d JOIN access_key k ON k.id = d.audience
		WHERE `+dueGrant+`
		ORDER BY k.tenant_id`, before)
	if err != nil {
		return nil, fmt.Errorf("querying the tenants with grants due: %w", err)
	}
	strs, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		return nil, fmt.Errorf("scanning the tenants with grants due: %w", err)
	}
	ids := make([]did.DID, len(strs))
	for i, str := range strs {
		if ids[i], err = did.Parse(str); err != nil {
			return nil, fmt.Errorf("parsing tenant %q: %w", str, err)
		}
	}
	return ids, nil
}

func (s *Store) GrantsDue(ctx context.Context, tenant did.DID, before time.Time) ([]dlgstore.DueGrant, error) {
	rows, err := pglock.Reader(ctx, s.pool).Query(ctx, `
		SELECT DISTINCT k.id, d.subject
		FROM delegation d JOIN access_key k ON k.id = d.audience
		WHERE k.tenant_id = $2 AND `+dueGrant+`
		ORDER BY k.id, d.subject`, before, tenant.String())
	if err != nil {
		return nil, fmt.Errorf("querying the grants due: %w", err)
	}
	defer rows.Close()
	var out []dlgstore.DueGrant
	for rows.Next() {
		var key string
		var subject *string
		if err := rows.Scan(&key, &subject); err != nil {
			return nil, fmt.Errorf("scanning a grant due: %w", err)
		}
		due := dlgstore.DueGrant{Subject: did.Undef}
		if due.Key, err = did.Parse(key); err != nil {
			return nil, fmt.Errorf("parsing key %q: %w", key, err)
		}
		if subject != nil {
			if due.Subject, err = did.Parse(*subject); err != nil {
				return nil, fmt.Errorf("parsing subject %q: %w", *subject, err)
			}
		}
		out = append(out, due)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterating the grants due: %w", err)
	}
	return out, nil
}

// DeleteExpired runs outside the tenants' task queues. The tasks either
// withdraw a key's delegations, which an expired one needs nothing from, or
// store ones that have not expired, so neither can conflict with it.
func (s *Store) DeleteExpired(ctx context.Context, before time.Time) (int64, error) {
	tag, err := s.pool.Exec(ctx, `
		DELETE FROM delegation d
		WHERE d.expires_at < $1
		  AND NOT EXISTS (
			SELECT 1 FROM access_key k
			WHERE k.id = d.audience AND `+dueGrant+`
		  )`, before)
	if err != nil {
		return 0, fmt.Errorf("deleting expired delegations: %w", err)
	}
	return tag.RowsAffected(), nil
}

// listColumn is a delegation column a list query may filter on. The named type
// keeps the value a package-controlled constant rather than caller input, since it
// is interpolated into the query text.
type listColumn string

const byAudience listColumn = "audience"

func (s *Store) ListByAudience(ctx context.Context, audience did.DID, opts ...store.PaginationOption) (store.Page[ucan.Delegation], error) {
	return s.listBy(ctx, byAudience, audience.String(), opts)
}

// listBy returns a page of the unexpired delegations whose column equals
// value, ordered by id so the keyset cursor is stable.
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
		  AND (expires_at IS NULL OR expires_at > now())
	`
	if cfg.Cursor != nil {
		args = append(args, *cfg.Cursor)
		query += ` AND id > $3`
	}
	query += ` ORDER BY id ASC LIMIT $2`

	rows, err := pglock.Reader(ctx, s.pool).Query(ctx, query, args...)
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

// ProofChain builds the proof chain from aud toward sub for cmd in a single
// recursive query. The walk follows edges audience -> issuer, matching the
// fixed subject (or NULL powerline delegations) and requiring each delegation's
// command to prove the child's command (the segment-boundary prefix test from
// command.Command.Proves). A delegation whose subject equals its issuer is the
// trust root and terminates a path. Expired delegations are left out. The
// shortest complete path is returned root-first, as libforge's ProofChain
// returns it, and of the shortest the one whose first delegation to expire
// expires last.
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
           ARRAY[d.data] AS datas, ARRAY[d.id] AS ids, 1 AS depth,
           coalesce(d.expires_at, 'infinity') AS expires
    FROM delegation d
    WHERE d.audience = $1
      AND (d.expires_at IS NULL OR d.expires_at > now())
      AND (d.subject = $3 OR d.subject IS NULL)
      AND ( d.command = $2 OR d.command = '/'
            OR (length($2) > length(d.command)
                AND substr($2, 1, length(d.command)) = d.command
                AND substr($2, length(d.command) + 1, 1) = '/') )
  UNION ALL
    SELECT d.issuer, d.command,
           (d.subject IS NOT NULL AND d.subject = d.issuer),
           c.datas || d.data, c.ids || d.id, c.depth + 1,
           least(c.expires, coalesce(d.expires_at, 'infinity'))
    FROM delegation d
    JOIN chain c ON d.audience = c.issuer
    WHERE NOT c.complete
      AND (d.expires_at IS NULL OR d.expires_at > now())
      AND (d.subject = $3 OR d.subject IS NULL)
      AND ( d.command = c.command OR d.command = '/'
            OR (length(c.command) > length(d.command)
                AND substr(c.command, 1, length(d.command)) = d.command
                AND substr(c.command, length(d.command) + 1, 1) = '/') )
      AND d.id <> ALL(c.ids)
)
SELECT datas FROM chain WHERE complete ORDER BY depth ASC, expires DESC LIMIT 1
`

	var datas [][]byte
	err := pglock.Reader(ctx, s.pool).QueryRow(ctx, query, aud.String(), cmd.String(), sub.String()).Scan(&datas)
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
