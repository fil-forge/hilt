package memory

import (
	"context"
	"sync"
	"time"

	"github.com/fil-forge/hilt/pkg/store"
	"github.com/fil-forge/hilt/pkg/store/tenant"
	"github.com/fil-forge/ucantone/did"
)

type Store struct {
	mutex   sync.RWMutex
	tenants map[did.DID]tenant.Record
}

var _ tenant.Store = (*Store)(nil)

func New() *Store {
	return &Store{tenants: map[did.DID]tenant.Record{}}
}

func (s *Store) Add(ctx context.Context, id did.DID, provider did.DID, name string, status tenant.Status) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	if _, ok := s.tenants[id]; ok {
		return store.ErrRecordExists
	}
	s.tenants[id] = tenant.Record{
		ID:        id,
		Provider:  provider,
		Name:      name,
		Status:    status,
		CreatedAt: time.Now().UTC(),
	}
	return nil
}

func (s *Store) Get(ctx context.Context, id did.DID) (tenant.Record, error) {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	rec, ok := s.tenants[id]
	if !ok {
		return tenant.Record{}, store.ErrRecordNotFound
	}
	return rec, nil
}

func (s *Store) SetStatus(ctx context.Context, id did.DID, status tenant.Status) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	rec, ok := s.tenants[id]
	if !ok {
		return store.ErrRecordNotFound
	}
	rec.Status = status
	rec.UpdatedAt = time.Now().UTC()
	s.tenants[id] = rec
	return nil
}
