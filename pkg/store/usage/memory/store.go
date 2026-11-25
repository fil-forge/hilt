// Package memory provides an in-memory implementation of usage.Store.
package memory

import (
	"context"
	"slices"
	"sync"
	"time"

	"github.com/fil-forge/hilt/pkg/store/usage"
	"github.com/fil-forge/ucantone/did"
)

type key struct {
	provider did.DID
	bucket   did.DID
	hour     int64
}

type row struct {
	tenant did.DID
	bytes  uint64
}

type Store struct {
	mutex  sync.RWMutex
	egress map[key]row
}

var _ usage.Store = (*Store)(nil)

func New() *Store {
	return &Store{egress: map[key]row{}}
}

// ForgetTenant drops the tenant's counts, as deleting the tenant does in the
// Postgres backend. The tenant store calls it when a tenant is deleted.
func (s *Store) ForgetTenant(tenant did.DID) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	for k, r := range s.egress {
		if r.tenant == tenant {
			delete(s.egress, k)
		}
	}
}

func (s *Store) SetEgress(ctx context.Context, provider did.DID, counts []usage.EgressCount) error {
	if err := usage.Validate(provider, counts); err != nil {
		return err
	}
	s.mutex.Lock()
	defer s.mutex.Unlock()

	for _, c := range counts {
		s.egress[key{provider, c.Bucket, c.Hour.Unix()}] = row{tenant: c.Tenant, bytes: c.Bytes}
	}
	return nil
}

func (s *Store) BucketEgress(ctx context.Context, bucket did.DID, from, to time.Time) ([]usage.HourlyEgress, error) {
	return s.sum(from, to, func(k key, _ row) bool { return k.bucket == bucket }), nil
}

func (s *Store) TenantEgress(ctx context.Context, tenant did.DID, from, to time.Time) ([]usage.HourlyEgress, error) {
	return s.sum(from, to, func(_ key, r row) bool { return r.tenant == tenant }), nil
}

// sum totals the rows match selects whose hour starts in [from, to), by hour.
func (s *Store) sum(from, to time.Time, match func(key, row) bool) []usage.HourlyEgress {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	totals := map[int64]uint64{}
	for k, r := range s.egress {
		if k.hour < from.Unix() || k.hour >= to.Unix() || !match(k, r) {
			continue
		}
		totals[k.hour] = usage.AddBytes(totals[k.hour], r.bytes)
	}
	hours := make([]int64, 0, len(totals))
	for h := range totals {
		hours = append(hours, h)
	}
	slices.Sort(hours)
	out := make([]usage.HourlyEgress, 0, len(hours))
	for _, h := range hours {
		out = append(out, usage.HourlyEgress{Hour: time.Unix(h, 0).UTC(), Bytes: totals[h]})
	}
	return out
}
