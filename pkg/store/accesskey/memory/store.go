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

func (s *Store) Add(ctx context.Context, id did.DID, tenant did.DID, name string, buckets []did.DID, permissions []string) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	if _, ok := s.keys[id]; ok {
		return store.ErrRecordExists
	}
	s.keys[id] = accesskey.Record{
		ID:          id,
		Tenant:      tenant,
		Name:        name,
		Buckets:     slices.Clone(buckets),
		Permissions: slices.Clone(permissions),
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
