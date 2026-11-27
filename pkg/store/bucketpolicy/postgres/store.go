// Package postgres provides a PostgreSQL-backed implementation of the bucket
// policy store over the bucket_policy and bucket_policy_principal tables.
package postgres

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	s3bkt "github.com/fil-forge/libforge/commands/s3/bucket"

	"github.com/fil-forge/hilt/pkg/bucketpolicy"
	"github.com/fil-forge/hilt/pkg/store"
	bucketpolicystore "github.com/fil-forge/hilt/pkg/store/bucketpolicy"
	"github.com/fil-forge/hilt/pkg/store/pglock"
	"github.com/fil-forge/ucantone/did"
	"github.com/jackc/pgx/v5"
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

func (s *Store) Get(ctx context.Context, bucket did.DID) (bucketpolicystore.Record, error) {
	rec, err := scanRecord(pglock.Reader(ctx, s.pool).QueryRow(ctx, selectColumns+` WHERE bucket_id = $1`, bucket.String()))
	return pglock.Found(rec, err, "policy")
}

// ListByPrincipal answers from the index: a policy is listed when
// bucket_policy_principal holds a row for the principal or a wildcard row
// (NULL principal) under the tenant.
func (s *Store) ListByPrincipal(ctx context.Context, tenant did.DID, principal string) ([]bucketpolicystore.Record, error) {
	rows, err := pglock.Reader(ctx, s.pool).Query(ctx, selectColumns+` p
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

// PutStatements upserts the document on the condition that the bucket exists
// and is the tenant's.
func (s *Store) PutStatements(tenant, bucket did.DID, doc s3bkt.PolicyDocument) (store.Statement, []store.Statement) {
	put := store.Statement{
		SQL: `
			INSERT INTO bucket_policy (bucket_id, document, etag)
			SELECT $1::text, $2::jsonb, $3::text
			WHERE EXISTS (SELECT 1 FROM bucket b WHERE b.id = $1 AND b.tenant_id = $4)
			ON CONFLICT (bucket_id) DO UPDATE
				SET document = EXCLUDED.document, etag = EXCLUDED.etag, updated_at = NOW()`,
		Args: []any{bucket.String(), bucketpolicy.Canonical(doc), s3bkt.ETag(doc), tenant.String()},
	}
	index := []store.Statement{clearIndexStatement(bucket)}
	if ids := indexed(doc); len(ids) > 0 {
		index = append(index, store.Statement{SQL: insertIndexSQL, Args: []any{bucket.String(), tenant.String(), ids}})
	}
	return put, index
}

// DeleteStatements removes the policy and then its index rows. The index
// rows reference the bucket, not the policy, so they are removed explicitly.
func (s *Store) DeleteStatements(bucket did.DID) (store.Statement, store.Statement) {
	return store.Statement{
		SQL:  `DELETE FROM bucket_policy WHERE bucket_id = $1`,
		Args: []any{bucket.String()},
	}, clearIndexStatement(bucket)
}

// clearIndexStatement removes the bucket's index rows.
func clearIndexStatement(bucket did.DID) store.Statement {
	return store.Statement{
		SQL:  `DELETE FROM bucket_policy_principal WHERE bucket_id = $1`,
		Args: []any{bucket.String()},
	}
}

// insertIndexSQL inserts one index row for the bucket ($1) of the tenant ($2)
// per principal in $3, a NULL standing for the wildcard.
const insertIndexSQL = `
		INSERT INTO bucket_policy_principal (bucket_id, tenant_id, principal_id)
		SELECT $1::text, $2::text, p.principal_id FROM unnest($3::text[]) AS p(principal_id)
	`

// indexed returns the principals the document's index rows carry: one per
// named principal and, when the document names the wildcard, a nil.
func indexed(doc s3bkt.PolicyDocument) []*string {
	named, wildcard := bucketpolicy.Named(doc)
	ids := make([]*string, 0, len(named)+1)
	for i := range named {
		ids = append(ids, &named[i])
	}
	if wildcard {
		ids = append(ids, nil)
	}
	return ids
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
	var doc s3bkt.PolicyDocument
	if err := json.Unmarshal(document, &doc); err != nil {
		return bucketpolicystore.Record{}, fmt.Errorf("decoding policy document: %w", err)
	}
	return bucketpolicystore.Record{Bucket: bucket, Policy: doc, ETag: etag, UpdatedAt: updatedAt}, nil
}
