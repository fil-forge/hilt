// Package postgres provides a PostgreSQL-backed implementation of usage.Store.
package postgres

import (
	"context"
	"fmt"
	"time"

	"github.com/fil-forge/hilt/pkg/store/pglock"
	"github.com/fil-forge/hilt/pkg/store/usage"
	"github.com/fil-forge/ucantone/did"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type Store struct {
	pool *pgxpool.Pool
}

var _ usage.Store = (*Store)(nil)

func New(pool *pgxpool.Pool) *Store {
	return &Store{pool: pool}
}

func (s *Store) SetEgress(ctx context.Context, provider did.DID, counts []usage.EgressCount) error {
	if err := usage.Validate(provider, counts); err != nil {
		return err
	}
	if len(counts) == 0 {
		return nil
	}
	buckets := make([]string, len(counts))
	hours := make([]time.Time, len(counts))
	tenants := make([]string, len(counts))
	sent := make([]int64, len(counts))
	for i, c := range counts {
		buckets[i] = c.Bucket.String()
		hours[i] = c.Hour.UTC()
		tenants[i] = c.Tenant.String()
		sent[i] = int64(c.Bytes)
	}

	tx, err := pglock.Begin(ctx, s.pool)
	if err != nil {
		return fmt.Errorf("beginning transaction: %w", err)
	}
	defer tx.Rollback(ctx) // no-op once committed; rolls back on any early return

	// One statement for the whole report. Validate has refused a bucket and
	// hour named twice, which the upsert could not apply. A row keeps the
	// larger of its total and the reported one.
	if _, err := tx.Exec(ctx, `
		INSERT INTO egress_usage (provider_id, bucket_id, hour, tenant_id, bytes_sent)
		SELECT $1, c.bucket_id, c.hour, c.tenant_id, c.bytes_sent
		FROM unnest($2::text[], $3::timestamptz[], $4::text[], $5::bigint[])
			AS c(bucket_id, hour, tenant_id, bytes_sent)
		ON CONFLICT (provider_id, bucket_id, hour) DO UPDATE
		SET bytes_sent = EXCLUDED.bytes_sent, tenant_id = EXCLUDED.tenant_id, updated_at = NOW()
		WHERE egress_usage.bytes_sent < EXCLUDED.bytes_sent
	`, provider.String(), buckets, hours, tenants, sent); err != nil {
		return fmt.Errorf("storing egress counts: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("committing transaction: %w", err)
	}
	return nil
}

func (s *Store) BucketEgress(ctx context.Context, bucket did.DID, from, to time.Time) ([]usage.HourlyEgress, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT hour, LEAST(SUM(bytes_sent), $4::bigint)::bigint
		FROM egress_usage
		WHERE bucket_id = $1 AND hour >= $2 AND hour < $3
		GROUP BY hour
		ORDER BY hour
	`, bucket.String(), from.UTC(), to.UTC(), int64(usage.MaxBytes))
	if err != nil {
		return nil, fmt.Errorf("reading bucket egress: %w", err)
	}
	return collect(rows)
}

func (s *Store) TenantEgress(ctx context.Context, tenant did.DID, from, to time.Time) ([]usage.HourlyEgress, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT hour, LEAST(SUM(bytes_sent), $4::bigint)::bigint
		FROM egress_usage
		WHERE tenant_id = $1 AND hour >= $2 AND hour < $3
		GROUP BY hour
		ORDER BY hour
	`, tenant.String(), from.UTC(), to.UTC(), int64(usage.MaxBytes))
	if err != nil {
		return nil, fmt.Errorf("reading tenant egress: %w", err)
	}
	return collect(rows)
}

func collect(rows pgx.Rows) ([]usage.HourlyEgress, error) {
	defer rows.Close()
	out := []usage.HourlyEgress{}
	for rows.Next() {
		var (
			hour  time.Time
			bytes int64
		)
		if err := rows.Scan(&hour, &bytes); err != nil {
			return nil, fmt.Errorf("scanning egress: %w", err)
		}
		out = append(out, usage.HourlyEgress{Hour: hour.UTC(), Bytes: uint64(bytes)})
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("reading egress: %w", err)
	}
	return out, nil
}

func (s *Store) SetObjects(ctx context.Context, provider did.DID, counts []usage.ObjectCount) error {
	if err := usage.ValidateObjects(provider, counts); err != nil {
		return err
	}
	if len(counts) == 0 {
		return nil
	}
	buckets := make([]string, len(counts))
	hours := make([]time.Time, len(counts))
	tenants := make([]string, len(counts))
	added := make([]int64, len(counts))
	removed := make([]int64, len(counts))
	for i, c := range counts {
		buckets[i] = c.Bucket.String()
		hours[i] = c.Hour.UTC()
		tenants[i] = c.Tenant.String()
		added[i] = int64(c.Added)
		removed[i] = int64(c.Removed)
	}

	tx, err := pglock.Begin(ctx, s.pool)
	if err != nil {
		return fmt.Errorf("beginning transaction: %w", err)
	}
	defer tx.Rollback(ctx) // no-op once committed; rolls back on any early return

	// One statement for the whole report. ValidateObjects has refused a
	// bucket and hour named twice, which the upsert could not apply. A row
	// keeps the larger of each of its totals and the reported one.
	if _, err := tx.Exec(ctx, `
		INSERT INTO object_usage (bucket_id, hour, provider_id, tenant_id, added, removed)
		SELECT c.bucket_id, c.hour, $1, c.tenant_id, c.added, c.removed
		FROM unnest($2::text[], $3::timestamptz[], $4::text[], $5::bigint[], $6::bigint[])
			AS c(bucket_id, hour, tenant_id, added, removed)
		ON CONFLICT (bucket_id, hour) DO UPDATE
		SET added = GREATEST(object_usage.added, EXCLUDED.added),
			removed = GREATEST(object_usage.removed, EXCLUDED.removed),
			updated_at = NOW()
		WHERE object_usage.added < EXCLUDED.added OR object_usage.removed < EXCLUDED.removed
	`, provider.String(), buckets, hours, tenants, added, removed); err != nil {
		return fmt.Errorf("storing object counts: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("committing transaction: %w", err)
	}
	return nil
}

func (s *Store) BucketObjects(ctx context.Context, bucket did.DID, from, to time.Time) ([]usage.HourlyObjects, error) {
	// The first arm is the latest hour starting before the range, which says
	// what the bucket held as the range opened: one row, read from the end
	// of the index, however long the bucket's history is.
	rows, err := s.pool.Query(ctx, `
		(SELECT hour, added, removed FROM object_usage
			WHERE bucket_id = $1 AND hour < $2
			ORDER BY hour DESC LIMIT 1)
		UNION ALL
		(SELECT hour, added, removed FROM object_usage
			WHERE bucket_id = $1 AND hour >= $2 AND hour < $3)
		ORDER BY hour
	`, bucket.String(), from.UTC(), to.UTC())
	if err != nil {
		return nil, fmt.Errorf("reading bucket objects: %w", err)
	}
	defer rows.Close()
	out := []usage.HourlyObjects{}
	for rows.Next() {
		var (
			hour           time.Time
			added, removed int64
		)
		if err := rows.Scan(&hour, &added, &removed); err != nil {
			return nil, fmt.Errorf("scanning objects: %w", err)
		}
		out = append(out, usage.HourlyObjects{Hour: hour.UTC(), Added: uint64(added), Removed: uint64(removed)})
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("reading objects: %w", err)
	}
	return out, nil
}
