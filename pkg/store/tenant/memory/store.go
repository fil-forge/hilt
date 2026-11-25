package memory

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/fil-forge/hilt/pkg/store"
	"github.com/fil-forge/hilt/pkg/store/tenant"
	"github.com/fil-forge/ucantone/did"
)

type Store struct {
	mutex   sync.RWMutex
	tenants map[did.DID]tenant.Record
	// onDelete are called with a tenant's ID as it is deleted.
	onDelete []func(did.DID)
}

var _ tenant.Store = (*Store)(nil)

// Option configures a Store.
type Option func(*Store)

// WithOnDelete has the store call fn with a tenant's ID as the tenant is
// deleted. The stores that keep rows for a tenant drop them here, as the
// Postgres backend's foreign keys do. fn must not call back into the store.
func WithOnDelete(fn func(did.DID)) Option {
	return func(s *Store) { s.onDelete = append(s.onDelete, fn) }
}

func New(opts ...Option) *Store {
	s := &Store{tenants: map[did.DID]tenant.Record{}}
	for _, opt := range opts {
		opt(s)
	}
	return s
}

func (s *Store) Add(ctx context.Context, id did.DID, externalID string, status tenant.Status) error {
	if id == did.Undef {
		return fmt.Errorf("tenant ID is required: %w", store.ErrInvalidArgument)
	}
	if !status.Valid() {
		return fmt.Errorf("invalid tenant status %q: %w", status, store.ErrInvalidArgument)
	}

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
	now := time.Now().UTC()
	s.tenants[id] = tenant.Record{
		ID:         id,
		ExternalID: externalID,
		Status:     status,
		CreatedAt:  now,
		UpdatedAt:  now,
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
	if !status.Valid() {
		return fmt.Errorf("invalid tenant status %q: %w", status, store.ErrInvalidArgument)
	}

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

	if _, ok := s.tenants[id]; !ok {
		return nil
	}
	delete(s.tenants, id)
	for _, fn := range s.onDelete {
		fn(id)
	}
	return nil
}
