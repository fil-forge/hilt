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
	// hour named twice, which the upsert could not apply.
	if _, err := tx.Exec(ctx, `
		INSERT INTO egress_usage (provider_id, bucket_id, hour, tenant_id, bytes_sent)
		SELECT $1, c.bucket_id, c.hour, c.tenant_id, c.bytes_sent
		FROM unnest($2::text[], $3::timestamptz[], $4::text[], $5::bigint[])
			AS c(bucket_id, hour, tenant_id, bytes_sent)
		ON CONFLICT (provider_id, bucket_id, hour) DO UPDATE
		SET bytes_sent = EXCLUDED.bytes_sent, tenant_id = EXCLUDED.tenant_id, updated_at = NOW()
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
		SELECT hour, SUM(bytes_sent)::bigint
		FROM egress_usage
		WHERE bucket_id = $1 AND hour >= $2 AND hour < $3
		GROUP BY hour
		ORDER BY hour
	`, bucket.String(), from.UTC(), to.UTC())
	if err != nil {
		return nil, fmt.Errorf("reading bucket egress: %w", err)
	}
	return collect(rows)
}

func (s *Store) TenantEgress(ctx context.Context, tenant did.DID, from, to time.Time) ([]usage.HourlyEgress, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT hour, SUM(bytes_sent)::bigint
		FROM egress_usage
		WHERE tenant_id = $1 AND hour >= $2 AND hour < $3
		GROUP BY hour
		ORDER BY hour
	`, tenant.String(), from.UTC(), to.UTC())
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
