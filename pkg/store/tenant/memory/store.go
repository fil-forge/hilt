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

func (s *Store) Add(ctx context.Context, id did.DID, externalID string, provider did.DID, name string, status tenant.Status) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	if _, ok := s.tenants[id]; ok {
		return store.ErrRecordExists
	}
	for _, rec := range s.tenants {
		if rec.ExternalID == externalID {
			return store.ErrRecordExists
		}
	}
	s.tenants[id] = tenant.Record{
		ID:         id,
		ExternalID: externalID,
		Provider:   provider,
		Name:       name,
		Status:     status,
		CreatedAt:  time.Now().UTC(),
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

func (s *Store) GetByExternalID(ctx context.Context, externalID string) (tenant.Record, error) {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	for _, rec := range s.tenants {
		if rec.ExternalID == externalID {
			return rec, nil
		}
	}
	return tenant.Record{}, store.ErrRecordNotFound
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

func (s *Store) Delete(ctx context.Context, id did.DID) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	delete(s.tenants, id)
	return nil
}
