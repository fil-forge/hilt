package memory

import (
	"context"
	"sync"
	"time"

	"github.com/fil-forge/hilt/pkg/store"
	"github.com/fil-forge/hilt/pkg/store/bucket"
	"github.com/fil-forge/ucantone/did"
)

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
