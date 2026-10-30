// Package postgres provides a PostgreSQL-backed implementation of the bucket
// policy store over the bucket_policy and bucket_policy_principal tables.
package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	s3bkt "github.com/fil-forge/libforge/commands/s3/bucket"

	"github.com/fil-forge/hilt/pkg/bucketpolicy"
	"github.com/fil-forge/hilt/pkg/store"
	bucketpolicystore "github.com/fil-forge/hilt/pkg/store/bucketpolicy"
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

var _ bucketpolicystore.Store = (*Store)(nil)

func New(pool *pgxpool.Pool) *Store {
	return &Store{pool: pool}
}

// Initialize is a no-op. Schema is managed by the shared goose migrations.
func (s *Store) Initialize(ctx context.Context) error { return nil }

const selectColumns = `SELECT bucket_id, document, updated_at FROM bucket_policy`

func (s *Store) Get(ctx context.Context, bucket did.DID) (bucketpolicystore.Record, error) {
	rec, err := scanRecord(pglock.ResolveQuerier(ctx, s.pool).QueryRow(ctx, selectColumns+` WHERE bucket_id = $1`, bucket.String()))
	return pglock.Found(rec, err, "policy")
}

// Put runs in one transaction: it checks the bucket and the named principals
// (see [requireLivePrincipals]), reads the current row, runs beforeCommit,
// writes the row and rewrites its index rows, and commits. It takes no lock of
// its own. Writing the row waits only on another write to the same bucket that
// has already written its row and not yet committed, and then replaces it, so
// the index rows the later write leaves are its own.
//
// A bucket with no row fails with store.ErrRecordNotFound before beforeCommit
// runs. beforeCommit runs before the row and index writes, so a callback that
// has published can still see a later write fail; the RFC treats such a record
// as harmless.
func (s *Store) Put(ctx context.Context, in bucketpolicystore.Input, beforeCommit func(ctx context.Context, old *bucketpolicystore.Record) error) error {
	if in.Bucket == did.Undef {
		return fmt.Errorf("policy bucket is required: %w", store.ErrInvalidArgument)
	}
	if in.Tenant == did.Undef {
		return fmt.Errorf("policy tenant is required: %w", store.ErrInvalidArgument)
	}

	tx, err := pglock.Begin(ctx, s.pool)
	if err != nil {
		return fmt.Errorf("beginning transaction: %w", err)
	}
	defer tx.Rollback(ctx) // no-op once committed; rolls back on any early return

	named, _ := bucketpolicy.Named(in.Policy)
	if err := requireLivePrincipals(ctx, tx, in.Tenant, named); err != nil {
		return err
	}
	var one int
	if err := tx.QueryRow(ctx, `SELECT 1 FROM bucket WHERE id = $1`, in.Bucket.String()).Scan(&one); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return fmt.Errorf("bucket %s does not exist: %w", in.Bucket, store.ErrRecordNotFound)
		}
		return fmt.Errorf("looking up bucket: %w", err)
	}
	old, err := readRow(ctx, tx, in.Bucket)
	if err != nil {
		return err
	}
	if beforeCommit != nil {
		if err := beforeCommit(pglock.WithTx(ctx, tx), old); err != nil {
			return fmt.Errorf("before writing policy: %w", err)
		}
	}

	if _, err := tx.Exec(ctx, `
		INSERT INTO bucket_policy (bucket_id, document)
		VALUES ($1, $2)
		ON CONFLICT (bucket_id) DO UPDATE SET document = EXCLUDED.document, updated_at = NOW()
	`, in.Bucket.String(), bucketpolicy.Canonical(in.Policy)); err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == pgerrcode.ForeignKeyViolation {
			return fmt.Errorf("bucket %s does not exist: %w", in.Bucket, store.ErrInvalidArgument)
		}
		return fmt.Errorf("writing policy: %w", err)
	}

	if err := writeIndex(ctx, tx, in.Bucket, in.Tenant, in.Policy); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("committing transaction: %w", err)
	}
	return nil
}

// Delete runs in one transaction under the same contract as [Store.Put].
func (s *Store) Delete(ctx context.Context, bucket did.DID, beforeCommit func(ctx context.Context, old bucketpolicystore.Record) error) error {
	tx, err := pglock.Begin(ctx, s.pool)
	if err != nil {
		return fmt.Errorf("beginning transaction: %w", err)
	}
	defer tx.Rollback(ctx) // no-op once committed; rolls back on any early return

	old, err := readRow(ctx, tx, bucket)
	if err != nil {
		return err
	}
	if old == nil {
		return store.ErrRecordNotFound
	}
	if beforeCommit != nil {
		if err := beforeCommit(pglock.WithTx(ctx, tx), *old); err != nil {
			return fmt.Errorf("before deleting policy: %w", err)
		}
	}
	if err := deleteRows(ctx, tx, bucket); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("committing transaction: %w", err)
	}
	return nil
}

// DeleteByBucket removes the bucket's policy unconditionally, running
// beforeCommit inside the same transaction first.
func (s *Store) DeleteByBucket(ctx context.Context, bucket did.DID, beforeCommit func(ctx context.Context) error) error {
	tx, err := pglock.Begin(ctx, s.pool)
	if err != nil {
		return fmt.Errorf("beginning transaction: %w", err)
	}
	defer tx.Rollback(ctx)

	if beforeCommit != nil {
		if err := beforeCommit(pglock.WithTx(ctx, tx)); err != nil {
			return err
		}
	}
	if err := deleteRows(ctx, tx, bucket); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("committing transaction: %w", err)
	}
	return nil
}

// ListByPrincipal answers from the index: a policy is listed when
// bucket_policy_principal holds a row for the principal or a wildcard row
// (NULL principal) under the tenant.
func (s *Store) ListByPrincipal(ctx context.Context, tenant did.DID, principal string) ([]bucketpolicystore.Record, error) {
	rows, err := pglock.ResolveQuerier(ctx, s.pool).Query(ctx, selectColumns+` p
		WHERE EXISTS (
			SELECT 1 FROM bucket_policy_principal i
			WHERE i.bucket_id = p.bucket_id
			  AND i.tenant_id = $1
			  AND (i.principal_id = $2 OR i.principal_id IS NULL)
		)
		ORDER BY bucket_id ASC`, tenant.String(), principal)
	if err != nil {
		return nil, fmt.Errorf("listing policies by principal: %w", err)
	}
	defer rows.Close()
	return collectRecords(rows)
}

// collectRecords scans every row of a policy listing.
func collectRecords(rows pgx.Rows) ([]bucketpolicystore.Record, error) {
	var recs []bucketpolicystore.Record
	for rows.Next() {
		rec, err := scanRecord(rows)
		if err != nil {
			return nil, fmt.Errorf("scanning policy: %w", err)
		}
		recs = append(recs, rec)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterating policies: %w", err)
	}
	return recs, nil
}

// readRow reads the bucket's policy row within tx. It returns nil when the
// bucket has no policy.
func readRow(ctx context.Context, tx pgx.Tx, bucket did.DID) (*bucketpolicystore.Record, error) {
	rec, err := scanRecord(tx.QueryRow(ctx, selectColumns+` WHERE bucket_id = $1`, bucket.String()))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("reading policy: %w", err)
	}
	return &rec, nil
}

// bucketFKConstraint names bucket_policy_principal's foreign key onto
// (bucket.id, bucket.tenant_id), as migration 00007 declares it. Both foreign
// keys of an index row raise the same error code, so the constraint name is
// what tells a bucket of another tenant from a principal of another tenant.
const bucketFKConstraint = "bucket_policy_principal_bucket_fkey"

// writeIndex replaces the bucket's index rows with one per named principal
// and, when the document names the wildcard, one with a NULL principal.
func writeIndex(ctx context.Context, tx pgx.Tx, bucket, tenant did.DID, doc s3bkt.PolicyDocument) error {
	if _, err := tx.Exec(ctx, `DELETE FROM bucket_policy_principal WHERE bucket_id = $1`, bucket.String()); err != nil {
		return fmt.Errorf("clearing policy index: %w", err)
	}
	named, wildcard := bucketpolicy.Named(doc)
	ids := make([]*string, 0, len(named)+1)
	for i := range named {
		ids = append(ids, &named[i])
	}
	if wildcard {
		ids = append(ids, nil)
	}
	for _, p := range ids {
		if _, err := tx.Exec(ctx, `
			INSERT INTO bucket_policy_principal (bucket_id, tenant_id, principal_id)
			VALUES ($1, $2, $3)
		`, bucket.String(), tenant.String(), p); err != nil {
			var pgErr *pgconn.PgError
			if errors.As(err, &pgErr) && pgErr.Code == pgerrcode.ForeignKeyViolation {
				if pgErr.ConstraintName == bucketFKConstraint {
					return fmt.Errorf("bucket %s is not a bucket of tenant %s: %w", bucket, tenant, store.ErrInvalidArgument)
				}
				if p != nil {
					return fmt.Errorf("principal %q is not a principal of tenant %s: %w", *p, tenant, store.ErrInvalidArgument)
				}
			}
			return fmt.Errorf("indexing policy principal: %w", err)
		}
	}
	return nil
}

// deleteRows removes the bucket's policy and index rows. The index rows
// reference the bucket, not the policy, so they are removed explicitly.
//
// The policy row goes first, the order [Store.Put] writes the two tables in,
// so a Put and a Delete of one bucket wait on each other's rows in the same
// order and cannot deadlock.
func deleteRows(ctx context.Context, tx pgx.Tx, bucket did.DID) error {
	if _, err := tx.Exec(ctx, `DELETE FROM bucket_policy WHERE bucket_id = $1`, bucket.String()); err != nil {
		return fmt.Errorf("deleting policy: %w", err)
	}
	if _, err := tx.Exec(ctx, `DELETE FROM bucket_policy_principal WHERE bucket_id = $1`, bucket.String()); err != nil {
		return fmt.Errorf("deleting policy index: %w", err)
	}
	return nil
}

func scanRecord(row pgx.Row) (bucketpolicystore.Record, error) {
	var (
		bucketStr string
		document  []byte
		updatedAt time.Time
	)
	if err := row.Scan(&bucketStr, &document, &updatedAt); err != nil {
		return bucketpolicystore.Record{}, err
	}
	bucket, err := did.Parse(bucketStr)
	if err != nil {
		return bucketpolicystore.Record{}, fmt.Errorf("parsing bucket DID: %w", err)
	}
	var doc s3bkt.PolicyDocument
	if err := json.Unmarshal(document, &doc); err != nil {
		return bucketpolicystore.Record{}, fmt.Errorf("decoding policy document: %w", err)
	}
	return bucketpolicystore.Record{Bucket: bucket, Policy: doc, UpdatedAt: updatedAt}, nil
}

// requireLivePrincipals refuses the write when a named principal is missing
// or removed. The row's foreign key cannot, because a tombstone still
// satisfies it. A principal removed after this read can still end up named in
// the committed document; evaluation skips a removed principal.
func requireLivePrincipals(ctx context.Context, tx pgx.Tx, tenant did.DID, named []string) error {
	if len(named) == 0 {
		return nil
	}
	rows, err := tx.Query(ctx, `
		SELECT external_id, deleted_at IS NOT NULL
		FROM principal
		WHERE tenant_id = $1 AND external_id = ANY($2)
	`, tenant.String(), named)
	if err != nil {
		return fmt.Errorf("checking policy principals: %w", err)
	}
	defer rows.Close()
	live := make(map[string]bool, len(named))
	for rows.Next() {
		var id string
		var removed bool
		if err := rows.Scan(&id, &removed); err != nil {
			return fmt.Errorf("scanning policy principal: %w", err)
		}
		if removed {
			return fmt.Errorf("principal %q of tenant %s was removed: %w", id, tenant, store.ErrInvalidArgument)
		}
		live[id] = true
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("checking policy principals: %w", err)
	}
	for _, p := range named {
		if !live[p] {
			return fmt.Errorf("principal %q is not a principal of tenant %s: %w", p, tenant, store.ErrInvalidArgument)
		}
	}
	return nil
}
