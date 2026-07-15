package memory

import (
	"context"
	"fmt"
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
	if id == did.Undef {
		return fmt.Errorf("bucket ID is required: %w", store.ErrInvalidArgument)
	}
	if tenant == did.Undef {
		return fmt.Errorf("bucket tenant is required: %w", store.ErrInvalidArgument)
	}
	if err := bucket.ValidateName(name); err != nil {
		return err
	}

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

func (s *Store) ListByTenant(ctx context.Context, tenant did.DID, opts ...bucket.ListOption) (store.Page[bucket.Record], error) {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	limit := defaultListLimit
	cfg := bucket.ListConfig{PaginationConfig: store.PaginationConfig{Limit: &limit}}
	for _, opt := range opts {
		opt(&cfg)
	}
	if len(cfg.IDs) > 0 && len(cfg.Names) > 0 {
		return store.Page[bucket.Record]{}, bucket.ErrConflictingFilters
	}

	var idFilter map[did.DID]bool
	if len(cfg.IDs) > 0 {
		idFilter = make(map[did.DID]bool, len(cfg.IDs))
		for _, id := range cfg.IDs {
			idFilter[id] = true
		}
	}
	var nameFilter map[string]bool
	if len(cfg.Names) > 0 {
		nameFilter = make(map[string]bool, len(cfg.Names))
		for _, name := range cfg.Names {
			nameFilter[name] = true
		}
	}

	var recs []bucket.Record
	for _, b := range s.buckets {
		if b.Tenant != tenant {
			continue
		}
		if idFilter != nil && !idFilter[b.ID] {
			continue
		}
		if nameFilter != nil && !nameFilter[b.Name] {
			continue
		}
		if cfg.Prefix != "" && !strings.HasPrefix(b.Name, cfg.Prefix) {
			continue
		}
		// Resume strictly after the cursor name, whether or not a bucket with
		// that exact name exists.
		if cfg.Cursor != nil && b.Name <= *cfg.Cursor {
			continue
		}
		recs = append(recs, b)
	}
	slices.SortFunc(recs, func(a, b bucket.Record) int {
		return strings.Compare(a.Name, b.Name)
	})

	var cursor *string
	if cfg.Limit != nil && len(recs) > *cfg.Limit {
		recs = recs[:*cfg.Limit]
		last := recs[len(recs)-1].Name
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
