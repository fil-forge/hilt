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
	mutex      sync.RWMutex
	tenants    map[did.DID]tenant.Record
	slotsMutex sync.Mutex
	slots      map[did.DID]chan struct{}
}

var _ tenant.Store = (*Store)(nil)

func New() *Store {
	return &Store{tenants: map[did.DID]tenant.Record{}, slots: map[did.DID]chan struct{}{}}
}

// The development backend serializes fence holders per tenant. The map mutex
// is never held across callbacks: other stores may read this tenant inside one.
func (s *Store) hold(ctx context.Context, id did.DID) (func(), error) {
	s.slotsMutex.Lock()
	slot, ok := s.slots[id]
	if !ok {
		slot = make(chan struct{}, 1)
		s.slots[id] = slot
	}
	s.slotsMutex.Unlock()
	timer := time.NewTimer(store.LockTimeout)
	defer timer.Stop()
	select {
	case slot <- struct{}{}:
		return func() { <-slot }, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-timer.C:
		return nil, store.ErrLockTimeout
	}
}

func (s *Store) WithReadLock(ctx context.Context, id did.DID, fn func(context.Context, tenant.Record) error) error {
	release, err := s.hold(ctx, id)
	if err != nil {
		return err
	}
	defer release()
	rec, err := s.Get(ctx, id)
	if err != nil {
		return err
	}
	return fn(ctx, rec)
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
	return s.ChangeStatus(ctx, id, status, nil)
}

func (s *Store) ChangeStatus(ctx context.Context, id did.DID, status tenant.Status, beforeCommit func(context.Context, tenant.Record) error) error {
	if !status.Valid() {
		return fmt.Errorf("invalid tenant status %q: %w", status, store.ErrInvalidArgument)
	}

	release, err := s.hold(ctx, id)
	if err != nil {
		return err
	}
	defer release()
	rec, err := s.Get(ctx, id)
	if err != nil {
		return err
	}
	if beforeCommit != nil {
		if err := beforeCommit(ctx, rec); err != nil {
			return err
		}
	}
	rec.Status = status
	rec.UpdatedAt = time.Now().UTC()
	s.mutex.Lock()
	defer s.mutex.Unlock()
	s.tenants[id] = rec
	return nil
}

func (s *Store) Delete(ctx context.Context, id did.DID) error {
	release, err := s.hold(ctx, id)
	if err != nil {
		return err
	}
	defer release()
	s.mutex.Lock()
	defer s.mutex.Unlock()

	delete(s.tenants, id)
	return nil
}
