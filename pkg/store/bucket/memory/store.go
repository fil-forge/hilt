package memory

import (
	"context"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/fil-forge/hilt/pkg/store"
	"github.com/fil-forge/hilt/pkg/store/bucket"
	"github.com/fil-forge/ucantone/did"
)

const defaultListLimit = 1000

type Store struct {
	mutex   sync.RWMutex
	buckets map[did.DID]bucket.Record
}

var _ bucket.Store = (*Store)(nil)

func New() *Store {
	return &Store{buckets: map[did.DID]bucket.Record{}}
}

func (s *Store) Add(ctx context.Context, id did.DID, tenant did.DID, name string) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	for _, b := range s.buckets {
		if b.ID == id || b.Name == name {
			return store.ErrRecordExists
		}
	}
	s.buckets[id] = bucket.Record{
		ID:        id,
		Tenant:    tenant,
		Name:      name,
		CreatedAt: time.Now().UTC(),
	}
	return nil
}

func (s *Store) GetByName(ctx context.Context, name string) (bucket.Record, error) {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	for _, b := range s.buckets {
		if b.Name == name {
			return b, nil
		}
	}
	return bucket.Record{}, store.ErrRecordNotFound
}

func (s *Store) ListByTenant(ctx context.Context, tenant did.DID, opts ...store.PaginationOption) (store.Page[bucket.Record], error) {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	limit := defaultListLimit
	cfg := store.PaginationConfig{Limit: &limit}
	for _, opt := range opts {
		opt(&cfg)
	}

	var recs []bucket.Record
	for _, b := range s.buckets {
		if b.Tenant == tenant {
			recs = append(recs, b)
		}
	}
	slices.SortFunc(recs, func(a, b bucket.Record) int {
		return strings.Compare(a.ID.String(), b.ID.String())
	})

	if cfg.Cursor != nil {
		for i, r := range recs {
			if r.ID.String() == *cfg.Cursor {
				recs = recs[i+1:]
				break
			}
		}
	}

	var cursor *string
	if cfg.Limit != nil && len(recs) > *cfg.Limit {
		recs = recs[:*cfg.Limit]
		last := recs[len(recs)-1].ID.String()
		cursor = &last
	}
	return store.Page[bucket.Record]{Cursor: cursor, Results: recs}, nil
}

func (s *Store) Delete(ctx context.Context, id did.DID) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	delete(s.buckets, id)
	return nil
}
