// Package memory provides an in-memory implementation of principal.Store.
//
// The store holds two locks. mutex guards the map and is held for one read or
// one write at a time, never across a caller's callback. removals serializes a
// removal with the writes that must not interleave with it, and is the lock
// Delete holds while beforeCommit runs.
//
// The split mirrors Postgres. A removal there holds the principal row FOR
// UPDATE across its callback while ListByTenant still reads the table without
// waiting; the callback rewrites the policies naming the principal, and a
// policy write of its own lists this store's principals. Holding one lock
// across both would wedge the two writes against each other.
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
	removals   sync.Mutex
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

	// A revive must not interleave with a removal of the same principal: the
	// removal would tombstone the row the revive just wrote.
	s.removals.Lock()
	defer s.removals.Unlock()

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

// Get with [store.WithLock]([store.LockShare]) waits for an in-flight Delete
// of any principal to finish, the way the Postgres read waits on the row held
// FOR UPDATE. An unlocked read takes the map alone and may be answered while a
// removal's callback is still running, as the unlocked Postgres read is
// answered from its snapshot.
func (s *Store) Get(ctx context.Context, tenant did.DID, externalID string, opts ...store.ReadOption) (principal.Record, error) {
	if store.NewReadConfig(opts...).Lock == store.LockShare {
		s.removals.Lock()
		defer s.removals.Unlock()
	}

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

// Delete holds removals for the whole call and takes the map mutex only to
// read the entry and, at the end, to write the tombstone. beforeCommit runs
// with the map unlocked, so it may write the policy store whose own writes
// read this one. A share-locked Get waits on removals and so observes either
// the principal or its tombstone, never a state in between; ListByTenant reads
// the map and never waits, as on Postgres.
func (s *Store) Delete(ctx context.Context, tenant did.DID, externalID string, beforeCommit func(ctx context.Context) error) error {
	s.removals.Lock()
	defer s.removals.Unlock()

	s.mutex.RLock()
	e, ok := s.principals[tenant][externalID]
	s.mutex.RUnlock()
	if !ok || e.deleted {
		return nil // idempotent: nothing to publish and nothing to remove
	}

	if beforeCommit != nil {
		if err := beforeCommit(ctx); err != nil {
			return fmt.Errorf("before deleting principal: %w", err)
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

// Lock runs fn without holding anything: the exclusion it provides on
// Postgres is a row lock a concurrent removal or share-locked read waits on,
// and the memory backend has no waiting reader to serve.
func (s *Store) Lock(ctx context.Context, tenant did.DID, externalIDs []string, fn func(ctx context.Context) error) error {
	return fn(ctx)
}

func (s *Store) DeleteByTenant(ctx context.Context, tenant did.DID) error {
	// A tenant removal waits for an in-flight principal removal, as it would on
	// the row Postgres holds FOR UPDATE.
	s.removals.Lock()
	defer s.removals.Unlock()
	s.mutex.Lock()
	defer s.mutex.Unlock()

	delete(s.principals, tenant)
	return nil
}
