// Package postgres provides a PostgreSQL-backed implementation of the bucket
// policy store over the bucket_policy and bucket_policy_principal tables.
package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"time"

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

const selectColumns = `SELECT bucket_id, document, etag, updated_at FROM bucket_policy`

// lockNamespace is the first of the two 32-bit keys of the advisory lock this
// store takes per bucket with [pglock.Advisory]; the second is the bucket DID.
// A writer holds it, exclusive, across its row lock, precondition check,
// beforeCommit callback and writes; a share-locked reader takes it shared.
//
// The lock exists because a row lock cannot cover a create: there is no row
// to lock until the INSERT commits, and an uncommitted INSERT is invisible to
// a FOR SHARE reader, so without it a reader arriving between the publish and
// the commit would answer "no policy" from the old state.
const lockNamespace int32 = 0x504f4c49 // "POLI"

// Get reads the row. With [store.LockShare] the read runs in a short
// transaction that waits on the bucket's advisory lock (held by an in-flight
// Put or Delete until it commits or rolls back) and then reads the row FOR
// SHARE, so it is answered from the settled state; a wait longer than
// [store.LockTimeout] returns [store.ErrLockTimeout].
func (s *Store) Get(ctx context.Context, bucket did.DID, locks ...store.LockMode) (rec bucketpolicystore.Record, err error) {
	defer func() { err = pglock.MapError(err) }()
	query := selectColumns + ` WHERE bucket_id = $1`
	if !slices.Contains(locks, store.LockShare) {
		rec, err = scanRecord(s.pool.QueryRow(ctx, query, bucket.String()))
		return pglock.Found(rec, err, "policy")
	}

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return bucketpolicystore.Record{}, fmt.Errorf("beginning transaction: %w", err)
	}
	defer tx.Rollback(ctx) // a read commits nothing; rolling back releases the locks
	if err := pglock.SetTimeout(ctx, tx); err != nil {
		return bucketpolicystore.Record{}, err
	}
	if err := pglock.Advisory(ctx, tx, lockNamespace, bucket.String(), true); err != nil {
		return bucketpolicystore.Record{}, err
	}
	rec, err = scanRecord(tx.QueryRow(ctx, fmt.Sprintf(`%s FOR SHARE`, query), bucket.String()))
	return pglock.Found(rec, err, "policy")
}

// Put runs in one transaction: it takes the bucket's advisory lock, locks the
// current row FOR UPDATE when there is one, checks the precondition, runs
// beforeCommit while holding the locks, writes the row and rewrites its index
// rows, and commits. A share-locked read of the bucket (see [Store.Get])
// waits for the commit or the rollback, on a create as much as on a replace.
// Two concurrent creates serialize on the advisory lock; the second finds the
// first's row and fails its precondition.
//
// beforeCommit runs before the row and index writes, so a callback that has
// published sees its write fail if the bucket or a named principal does not
// exist; the RFC treats such a record as harmless.
//
// Every index row write takes a FOR KEY SHARE lock on the bucket row, which its
// foreign key onto (id, tenant_id) requires: the write waits on an in-flight
// change to that pair and is refused when the bucket is not the tenant's.
// Every lock the transaction takes is bounded at [store.LockTimeout]. The
// index rows reference the principal table, so writing them waits on any
// principal removal holding one of the named rows; without the bound that
// wait is an application-level cycle Postgres cannot break.
func (s *Store) Put(ctx context.Context, in bucketpolicystore.Input, beforeCommit func(ctx context.Context, old *bucketpolicystore.Record) error) (etag string, err error) {
	defer func() { err = pglock.MapError(err) }()
	if in.Bucket == did.Undef {
		return "", fmt.Errorf("policy bucket is required: %w", store.ErrInvalidArgument)
	}
	if in.Tenant == did.Undef {
		return "", fmt.Errorf("policy tenant is required: %w", store.ErrInvalidArgument)
	}

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return "", fmt.Errorf("beginning transaction: %w", err)
	}
	defer tx.Rollback(ctx) // no-op once committed; rolls back on any early return

	if err := pglock.SetTimeout(ctx, tx); err != nil {
		return "", err
	}
	if err := pglock.Advisory(ctx, tx, lockNamespace, in.Bucket.String(), false); err != nil {
		return "", err
	}
	old, err := lockRow(ctx, tx, in.Bucket)
	if err != nil {
		return "", err
	}
	if err := bucketpolicystore.CheckPrecondition(old, in.IfMatch); err != nil {
		return "", err
	}
	if beforeCommit != nil {
		if err := beforeCommit(ctx, old); err != nil {
			return "", fmt.Errorf("before writing policy: %w", err)
		}
	}

	canonical := bucketpolicy.Canonical(in.Policy)
	etag = bucketpolicy.ETag(in.Policy)
	if old == nil {
		_, err = tx.Exec(ctx, `
			INSERT INTO bucket_policy (bucket_id, document, etag)
			VALUES ($1, $2, $3)
		`, in.Bucket.String(), canonical, etag)
	} else {
		_, err = tx.Exec(ctx, `
			UPDATE bucket_policy
			SET document = $2, etag = $3, updated_at = NOW()
			WHERE bucket_id = $1
		`, in.Bucket.String(), canonical, etag)
	}
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) {
			switch pgErr.Code {
			case pgerrcode.UniqueViolation:
				return "", fmt.Errorf("policy was created concurrently: %w", store.ErrPreconditionFailed)
			case pgerrcode.ForeignKeyViolation:
				return "", fmt.Errorf("bucket %s does not exist: %w", in.Bucket, store.ErrInvalidArgument)
			}
		}
		return "", fmt.Errorf("writing policy: %w", err)
	}

	if err := writeIndex(ctx, tx, in.Bucket, in.Tenant, in.Policy); err != nil {
		return "", err
	}
	if err := tx.Commit(ctx); err != nil {
		return "", fmt.Errorf("committing transaction: %w", err)
	}
	return etag, nil
}

// Delete runs in one transaction under the same contract as [Store.Put].
func (s *Store) Delete(ctx context.Context, bucket did.DID, ifMatch string, beforeCommit func(ctx context.Context, old bucketpolicystore.Record) error) (err error) {
	defer func() { err = pglock.MapError(err) }()
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("beginning transaction: %w", err)
	}
	defer tx.Rollback(ctx) // no-op once committed; rolls back on any early return

	if err := pglock.SetTimeout(ctx, tx); err != nil {
		return err
	}
	if err := pglock.Advisory(ctx, tx, lockNamespace, bucket.String(), false); err != nil {
		return err
	}
	old, err := lockRow(ctx, tx, bucket)
	if err != nil {
		return err
	}
	if old == nil {
		return store.ErrRecordNotFound
	}
	if old.ETag != ifMatch {
		return fmt.Errorf("policy ETag is %s: %w", old.ETag, store.ErrPreconditionFailed)
	}
	if beforeCommit != nil {
		if err := beforeCommit(ctx, *old); err != nil {
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

// DeleteByBucket removes the bucket's policy unconditionally, under the
// bucket's advisory lock so it serializes with a Put or Delete in flight the
// way the memory backend's mutex does.
func (s *Store) DeleteByBucket(ctx context.Context, bucket did.DID) (err error) {
	defer func() { err = pglock.MapError(err) }()
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("beginning transaction: %w", err)
	}
	defer tx.Rollback(ctx)

	if err := pglock.SetTimeout(ctx, tx); err != nil {
		return err
	}
	if err := pglock.Advisory(ctx, tx, lockNamespace, bucket.String(), false); err != nil {
		return err
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
// (NULL principal) under the tenant. With [store.LockShare] the rows are read
// FOR SHARE in a short transaction, so the read waits on an in-flight Put or
// Delete of a policy that already has a row; a concurrent create is not
// covered, since no row exists to lock until it commits (Get takes the bucket's
// advisory lock for that, which a listing across buckets cannot). The wait is
// bounded at [store.LockTimeout]; a longer wait returns [store.ErrLockTimeout].
func (s *Store) ListByPrincipal(ctx context.Context, tenant did.DID, principal string, locks ...store.LockMode) (recs []bucketpolicystore.Record, err error) {
	defer func() { err = pglock.MapError(err) }()
	query := selectColumns + ` p
		WHERE EXISTS (
			SELECT 1 FROM bucket_policy_principal i
			WHERE i.bucket_id = p.bucket_id
			  AND i.tenant_id = $1
			  AND (i.principal_id = $2 OR i.principal_id IS NULL)
		)
		ORDER BY bucket_id ASC`
	if !slices.Contains(locks, store.LockShare) {
		rows, err := s.pool.Query(ctx, query, tenant.String(), principal)
		if err != nil {
			return nil, fmt.Errorf("listing policies by principal: %w", err)
		}
		defer rows.Close()
		return collectRecords(rows)
	}

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("beginning transaction: %w", err)
	}
	defer tx.Rollback(ctx) // a read commits nothing; rolling back releases the locks
	if err := pglock.SetTimeout(ctx, tx); err != nil {
		return nil, err
	}
	rows, err := tx.Query(ctx, query+` FOR SHARE`, tenant.String(), principal)
	if err != nil {
		return nil, fmt.Errorf("listing policies by principal: %w", err)
	}
	defer rows.Close() // runs before the deferred rollback
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

// lockRow reads the bucket's policy row FOR UPDATE within tx. It returns nil
// when the bucket has no policy.
func lockRow(ctx context.Context, tx pgx.Tx, bucket did.DID) (*bucketpolicystore.Record, error) {
	rec, err := scanRecord(tx.QueryRow(ctx, selectColumns+` WHERE bucket_id = $1 FOR UPDATE`, bucket.String()))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("locking policy: %w", err)
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
func writeIndex(ctx context.Context, tx pgx.Tx, bucket, tenant did.DID, doc bucketpolicy.Policy) error {
	if _, err := tx.Exec(ctx, `DELETE FROM bucket_policy_principal WHERE bucket_id = $1`, bucket.String()); err != nil {
		return fmt.Errorf("clearing policy index: %w", err)
	}
	named, wildcard := bucketpolicy.Named(doc)
	if err := requireLivePrincipals(ctx, tx, tenant, named); err != nil {
		return err
	}
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
func deleteRows(ctx context.Context, tx pgx.Tx, bucket did.DID) error {
	if _, err := tx.Exec(ctx, `DELETE FROM bucket_policy_principal WHERE bucket_id = $1`, bucket.String()); err != nil {
		return fmt.Errorf("deleting policy index: %w", err)
	}
	if _, err := tx.Exec(ctx, `DELETE FROM bucket_policy WHERE bucket_id = $1`, bucket.String()); err != nil {
		return fmt.Errorf("deleting policy: %w", err)
	}
	return nil
}

func scanRecord(row pgx.Row) (bucketpolicystore.Record, error) {
	var (
		bucketStr string
		document  []byte
		etag      string
		updatedAt time.Time
	)
	if err := row.Scan(&bucketStr, &document, &etag, &updatedAt); err != nil {
		return bucketpolicystore.Record{}, err
	}
	bucket, err := did.Parse(bucketStr)
	if err != nil {
		return bucketpolicystore.Record{}, fmt.Errorf("parsing bucket DID: %w", err)
	}
	var doc bucketpolicy.Policy
	if err := json.Unmarshal(document, &doc); err != nil {
		return bucketpolicystore.Record{}, fmt.Errorf("decoding policy document: %w", err)
	}
	return bucketpolicystore.Record{Bucket: bucket, Policy: doc, ETag: etag, UpdatedAt: updatedAt}, nil
}

// requireLivePrincipals locks the named principals FOR SHARE inside tx and
// refuses the write when one is missing or removed. A removal holds the row FOR
// UPDATE while it strips its policies, so this read waits for it to commit and
// then sees the tombstone: the caller's validation ran against live rows, but
// only this check, inside the writing transaction, keeps a statement naming a
// removed principal out of the store. The row's foreign key cannot, because a
// tombstone still satisfies it.
func requireLivePrincipals(ctx context.Context, tx pgx.Tx, tenant did.DID, named []string) error {
	if len(named) == 0 {
		return nil
	}
	rows, err := tx.Query(ctx, `
		SELECT external_id, deleted_at IS NOT NULL
		FROM principal
		WHERE tenant_id = $1 AND external_id = ANY($2)
		FOR SHARE
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
