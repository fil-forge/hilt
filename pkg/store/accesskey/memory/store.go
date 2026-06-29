package memory

import (
	"context"
	"slices"
	"sync"
	"time"

	"github.com/fil-forge/hilt/pkg/store"
	"github.com/fil-forge/hilt/pkg/store/accesskey"
	"github.com/fil-forge/ucantone/did"
)

type Store struct {
	mutex sync.RWMutex
	keys  map[did.DID]accesskey.Record
}

var _ accesskey.Store = (*Store)(nil)

func New() *Store {
	return &Store{keys: map[did.DID]accesskey.Record{}}
}

func (s *Store) Add(ctx context.Context, id did.DID, tenant did.DID, name string, buckets []did.DID, permissions []string, expiresAt *time.Time) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	if _, ok := s.keys[id]; ok {
		return store.ErrRecordExists
	}
	var expires *time.Time
	if expiresAt != nil {
		e := expiresAt.UTC()
		expires = &e
	}
	s.keys[id] = accesskey.Record{
		ID:          id,
		Tenant:      tenant,
		Name:        name,
		Buckets:     slices.Clone(buckets),
		Permissions: slices.Clone(permissions),
		ExpiresAt:   expires,
		CreatedAt:   time.Now().UTC(),
	}
	return nil
}

func (s *Store) Get(ctx context.Context, id did.DID) (accesskey.Record, error) {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	rec, ok := s.keys[id]
	if !ok {
		return accesskey.Record{}, store.ErrRecordNotFound
	}
	return rec, nil
}

func (s *Store) ListByTenant(ctx context.Context, tenant did.DID) ([]accesskey.Record, error) {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	var recs []accesskey.Record
	for _, rec := range s.keys {
		if rec.Tenant == tenant {
			recs = append(recs, rec)
		}
	}
	return recs, nil
}

func (s *Store) Delete(ctx context.Context, id did.DID) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	delete(s.keys, id)
	return nil
}
