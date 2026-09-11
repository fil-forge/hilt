// Package postgres provides a PostgreSQL-backed implementation of the bucket
// policy store over the bucket_policy and bucket_policy_principal tables.
package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
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
// store takes per bucket (see [advisoryLock]). Postgres identifies an advisory
// lock by its key pair and nothing else, so the fixed first key keeps this
// store's locks apart from any other advisory lock taken on the same database
// by this process or anything else; the second key is hashtext(bucket DID).
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
func (s *Store) Get(ctx context.Context, bucket did.DID, opts ...store.ReadOption) (bucketpolicystore.Record, error) {
	rec, err := s.get(ctx, bucket, opts...)
	return rec, pglock.MapError(err)
}

func (s *Store) get(ctx context.Context, bucket did.DID, opts ...store.ReadOption) (bucketpolicystore.Record, error) {
	query := selectColumns + ` WHERE bucket_id = $1`
	if store.NewReadConfig(opts...).Lock != store.LockShare {
		rec, err := scanRecord(s.pool.QueryRow(ctx, query, bucket.String()))
		return getResult(rec, err)
	}

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return bucketpolicystore.Record{}, fmt.Errorf("beginning transaction: %w", err)
	}
	defer tx.Rollback(ctx) // a read commits nothing; rolling back releases the locks
	if err := pglock.SetTimeout(ctx, tx); err != nil {
		return bucketpolicystore.Record{}, err
	}
	if err := advisoryLock(ctx, tx, bucket, true); err != nil {
		return bucketpolicystore.Record{}, err
	}
	rec, err := scanRecord(tx.QueryRow(ctx, query+` FOR SHARE`, bucket.String()))
	return getResult(rec, err)
}

func getResult(rec bucketpolicystore.Record, err error) (bucketpolicystore.Record, error) {
	if errors.Is(err, pgx.ErrNoRows) {
		return bucketpolicystore.Record{}, store.ErrRecordNotFound
	}
	if err != nil {
		return bucketpolicystore.Record{}, fmt.Errorf("getting policy: %w", err)
	}
	return rec, nil
}

// advisoryLock takes the bucket's advisory lock inside tx, keyed by
// (lockNamespace, hashtext(bucket DID)): pg_advisory_xact_lock, exclusive,
// for a writer; pg_advisory_xact_lock_shared for a share-locked reader. The
// lock is transaction-scoped: Postgres releases it when tx commits or rolls
// back, and there is nothing to unlock. A writer holds it across its row lock,
// precondition check, beforeCommit callback and writes, so a reader arriving
// mid-write waits for the outcome even when the write is a create and no row
// exists yet.
func advisoryLock(ctx context.Context, tx pgx.Tx, bucket did.DID, shared bool) error {
	fn := "pg_advisory_xact_lock"
	if shared {
		fn = "pg_advisory_xact_lock_shared"
	}
	if _, err := tx.Exec(ctx, `SELECT `+fn+`($1, hashtext($2))`, lockNamespace, bucket.String()); err != nil {
		return fmt.Errorf("locking policy bucket: %w", err)
	}
	return nil
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
// Every lock the transaction takes is bounded at [store.LockTimeout]. The
// index rows reference the principal table, so writing them waits on any
// principal removal holding one of the named rows; without the bound that
// wait is an application-level cycle Postgres cannot break.
func (s *Store) Put(ctx context.Context, in bucketpolicystore.Input, beforeCommit func(ctx context.Context, old *bucketpolicystore.Record) error) (string, error) {
	etag, err := s.put(ctx, in, beforeCommit)
	return etag, pglock.MapError(err)
}

func (s *Store) put(ctx context.Context, in bucketpolicystore.Input, beforeCommit func(ctx context.Context, old *bucketpolicystore.Record) error) (string, error) {
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
	if err := advisoryLock(ctx, tx, in.Bucket, false); err != nil {
		return "", err
	}
	old, err := lockRow(ctx, tx, in.Bucket)
	if err != nil {
		return "", err
	}
	if err := checkPrecondition(old, in.IfMatch); err != nil {
		return "", err
	}
	if beforeCommit != nil {
		if err := beforeCommit(ctx, old); err != nil {
			return "", fmt.Errorf("before writing policy: %w", err)
		}
	}

	canonical := bucketpolicy.Canonical(in.Policy)
	etag := bucketpolicy.ETag(in.Policy)
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
func (s *Store) Delete(ctx context.Context, bucket did.DID, ifMatch string, beforeCommit func(ctx context.Context, old bucketpolicystore.Record) error) error {
	return pglock.MapError(s.delete(ctx, bucket, ifMatch, beforeCommit))
}

func (s *Store) delete(ctx context.Context, bucket did.DID, ifMatch string, beforeCommit func(ctx context.Context, old bucketpolicystore.Record) error) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("beginning transaction: %w", err)
	}
	defer tx.Rollback(ctx) // no-op once committed; rolls back on any early return

	if err := pglock.SetTimeout(ctx, tx); err != nil {
		return err
	}
	if err := advisoryLock(ctx, tx, bucket, false); err != nil {
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

func (s *Store) DeleteByBucket(ctx context.Context, bucket did.DID) error {
	return pglock.MapError(s.deleteByBucket(ctx, bucket))
}

func (s *Store) deleteByBucket(ctx context.Context, bucket did.DID) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("beginning transaction: %w", err)
	}
	defer tx.Rollback(ctx)

	if err := pglock.SetTimeout(ctx, tx); err != nil {
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
// Delete of any listed policy and its wait is bounded at [store.LockTimeout];
// a longer wait returns [store.ErrLockTimeout].
func (s *Store) ListByPrincipal(ctx context.Context, tenant did.DID, principal string, opts ...store.ReadOption) ([]bucketpolicystore.Record, error) {
	recs, err := s.listByPrincipal(ctx, tenant, principal, opts...)
	return recs, pglock.MapError(err)
}

func (s *Store) listByPrincipal(ctx context.Context, tenant did.DID, principal string, opts ...store.ReadOption) ([]bucketpolicystore.Record, error) {
	query := selectColumns + ` p
		WHERE EXISTS (
			SELECT 1 FROM bucket_policy_principal i
			WHERE i.bucket_id = p.bucket_id
			  AND i.tenant_id = $1
			  AND (i.principal = $2 OR i.principal IS NULL)
		)
		ORDER BY bucket_id ASC`
	if store.NewReadConfig(opts...).Lock != store.LockShare {
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

// checkPrecondition applies the If-Match / If-None-Match rule: a nil ifMatch
// requires no current policy; a non-nil one must equal the current ETag.
func checkPrecondition(old *bucketpolicystore.Record, ifMatch *string) error {
	switch {
	case ifMatch == nil && old != nil:
		return fmt.Errorf("policy already exists with ETag %s: %w", old.ETag, store.ErrPreconditionFailed)
	case ifMatch != nil && old == nil:
		return fmt.Errorf("bucket has no policy: %w", store.ErrPreconditionFailed)
	case ifMatch != nil && old.ETag != *ifMatch:
		return fmt.Errorf("policy ETag is %s: %w", old.ETag, store.ErrPreconditionFailed)
	}
	return nil
}

// writeIndex replaces the bucket's index rows with one per named principal
// and, when the document names the wildcard, one with a NULL principal.
func writeIndex(ctx context.Context, tx pgx.Tx, bucket, tenant did.DID, doc bucketpolicy.Policy) error {
	if _, err := tx.Exec(ctx, `DELETE FROM bucket_policy_principal WHERE bucket_id = $1`, bucket.String()); err != nil {
		return fmt.Errorf("clearing policy index: %w", err)
	}
	named, wildcard := bucketpolicy.Named(doc)
	for _, p := range named {
		if _, err := tx.Exec(ctx, `
			INSERT INTO bucket_policy_principal (bucket_id, tenant_id, principal)
			VALUES ($1, $2, $3)
		`, bucket.String(), tenant.String(), p); err != nil {
			var pgErr *pgconn.PgError
			if errors.As(err, &pgErr) && pgErr.Code == pgerrcode.ForeignKeyViolation {
				return fmt.Errorf("principal %q is not a principal of tenant %s: %w", p, tenant, store.ErrInvalidArgument)
			}
			return fmt.Errorf("indexing policy principal: %w", err)
		}
	}
	if wildcard {
		if _, err := tx.Exec(ctx, `
			INSERT INTO bucket_policy_principal (bucket_id, tenant_id, principal)
			VALUES ($1, $2, NULL)
		`, bucket.String(), tenant.String()); err != nil {
			return fmt.Errorf("indexing policy wildcard: %w", err)
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
