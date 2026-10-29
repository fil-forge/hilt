// Package memory provides an in-memory implementation of principal.Store.
// mutex guards the map and is held for one read or one write at a time, never
// across a caller's callback.
package memory

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/fil-forge/hilt/pkg/store"
	"github.com/fil-forge/hilt/pkg/store/principal"
	"github.com/fil-forge/ucantone/did"
)

// entry is a stored principal; deleted marks a tombstone that no read returns
// and that Add revives.
type entry struct {
	rec     principal.Record
	deleted bool
}

type Store struct {
	mutex      sync.RWMutex
	principals map[did.DID]map[string]entry
}

var _ principal.Store = (*Store)(nil)

func New() *Store {
	return &Store{principals: map[did.DID]map[string]entry{}}
}

// WithLive runs fn when the principal is live and refuses with
// [store.ErrInvalidArgument] when it is not, as the Postgres key insert's
// foreign key and liveness check do. The memory access-key store calls it
// through its WithPrincipals option.
func (s *Store) WithLive(ctx context.Context, tenant did.DID, externalID string, fn func() error) error {
	s.mutex.RLock()
	e, ok := s.principals[tenant][externalID]
	s.mutex.RUnlock()
	if !ok || e.deleted {
		return fmt.Errorf("principal %s does not exist: %w", externalID, store.ErrInvalidArgument)
	}
	return fn()
}

func (s *Store) Add(ctx context.Context, tenant did.DID, externalID string) error {
	if tenant == did.Undef {
		return fmt.Errorf("principal tenant is required: %w", store.ErrInvalidArgument)
	}
	if externalID == "" {
		return fmt.Errorf("principal external ID is required: %w", store.ErrInvalidArgument)
	}

	s.mutex.Lock()
	defer s.mutex.Unlock()

	byID, ok := s.principals[tenant]
	if !ok {
		byID = map[string]entry{}
		s.principals[tenant] = byID
	}
	if e, ok := byID[externalID]; ok && !e.deleted {
		return store.ErrRecordExists
	}
	byID[externalID] = entry{rec: principal.Record{
		Tenant:     tenant,
		ExternalID: externalID,
		CreatedAt:  time.Now().UTC(),
	}}
	return nil
}

func (s *Store) Get(ctx context.Context, tenant did.DID, externalID string) (principal.Record, error) {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	e, ok := s.principals[tenant][externalID]
	if !ok || e.deleted {
		return principal.Record{}, store.ErrRecordNotFound
	}
	return e.rec, nil
}

func (s *Store) ListByTenant(ctx context.Context, tenant did.DID) ([]principal.Record, error) {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	var recs []principal.Record
	for _, e := range s.principals[tenant] {
		if !e.deleted {
			recs = append(recs, e.rec)
		}
	}
	slices.SortFunc(recs, func(a, b principal.Record) int {
		return strings.Compare(a.ExternalID, b.ExternalID)
	})
	return recs, nil
}

func (s *Store) ListIDsByTenant(ctx context.Context, tenant did.DID) ([]string, error) {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	var ids []string
	for id, e := range s.principals[tenant] {
		if !e.deleted {
			ids = append(ids, id)
		}
	}
	slices.Sort(ids)
	return ids, nil
}

// Tombstone takes the map mutex only to read the entry and, at the end, to
// write the tombstone. fn runs with the map unlocked, so it may write the
// policy store whose own writes read this one.
func (s *Store) Tombstone(ctx context.Context, tenant did.DID, externalID string, fn func(ctx context.Context) error) error {
	s.mutex.RLock()
	e, ok := s.principals[tenant][externalID]
	s.mutex.RUnlock()
	if !ok || e.deleted {
		return nil // idempotent: nothing to publish and nothing to remove
	}

	if fn != nil {
		if err := fn(ctx); err != nil {
			return fmt.Errorf("before tombstoning principal: %w", err)
		}
	}

	s.mutex.Lock()
	defer s.mutex.Unlock()

	byID, ok := s.principals[tenant]
	if !ok {
		return nil // DeleteByTenant took the whole tenant meanwhile
	}
	e, ok = byID[externalID]
	if !ok || e.deleted {
		return nil
	}
	e.deleted = true
	byID[externalID] = e
	return nil
}

func (s *Store) DeleteByTenant(ctx context.Context, tenant did.DID) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	delete(s.principals, tenant)
	return nil
}
