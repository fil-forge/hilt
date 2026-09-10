// Package memory provides an in-memory implementation of principal.Store.
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

// Get ignores the lock option: reads and writes are serialized by the store
// mutex, so a read already waits for an in-flight Delete.
func (s *Store) Get(ctx context.Context, tenant did.DID, externalID string, opts ...store.ReadOption) (principal.Record, error) {
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

// Delete runs beforeCommit under the store mutex, so a concurrent Get waits
// for the callback to finish and observes either the principal or its
// tombstone, never a state in between.
func (s *Store) Delete(ctx context.Context, tenant did.DID, externalID string, beforeCommit func(ctx context.Context) error) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	byID, ok := s.principals[tenant]
	if !ok {
		return nil
	}
	e, ok := byID[externalID]
	if !ok || e.deleted {
		return nil
	}
	if beforeCommit != nil {
		if err := beforeCommit(ctx); err != nil {
			return fmt.Errorf("before deleting principal: %w", err)
		}
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
