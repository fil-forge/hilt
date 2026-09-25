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
	removals   chan struct{}
	principals map[did.DID]map[string]entry
}

// hold takes the removal lock and release gives it back. removals is a
// one-slot channel rather than a mutex so [Store.Lock] can bound its wait.
func (s *Store) hold()    { s.removals <- struct{}{} }
func (s *Store) release() { <-s.removals }

// LockWait bounds how long [Store.Lock] waits for a removal in flight before
// giving up with [store.ErrLockTimeout], as lock_timeout bounds the wait a
// Postgres row lock gives. It is a variable so a test can shorten it.
var LockWait = store.LockTimeout

var _ principal.Store = (*Store)(nil)

func New() *Store {
	return &Store{removals: make(chan struct{}, 1), principals: map[did.DID]map[string]entry{}}
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
	s.hold()
	defer s.release()

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

// Get with [store.LockShare] waits for an in-flight Delete of any principal
// to finish, the way the Postgres read waits on the row held FOR UPDATE. An
// unlocked read takes the map alone and may be answered while a removal's
// callback is still running, as the unlocked Postgres read is answered from
// its snapshot.
func (s *Store) Get(ctx context.Context, tenant did.DID, externalID string, locks ...store.LockMode) (principal.Record, error) {
	if slices.Contains(locks, store.LockShare) {
		s.hold()
		defer s.release()
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
	s.hold()
	defer s.release()

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

// Lock holds removals while fn runs, so a removal of one of the named
// principals waits for it, as it waits on the rows Postgres holds FOR UPDATE.
// Naming no principal locks nothing, as the Postgres call takes no row lock
// then either.
//
// The wait is bounded at [LockWait]. A policy write calls Lock while holding
// the bucket's policy, and a removal holds removals while its callback
// rewrites that same policy, so each can end up waiting on what the other
// holds. Postgres bounds that cycle with lock_timeout; here the bound is the
// timer below, and the caller gets [store.ErrLockTimeout] to retry.
func (s *Store) Lock(ctx context.Context, tenant did.DID, externalIDs []string, fn func(ctx context.Context) error) error {
	if len(externalIDs) == 0 {
		return fn(ctx)
	}

	timer := time.NewTimer(LockWait)
	defer timer.Stop()
	select {
	case s.removals <- struct{}{}:
		defer s.release()
	case <-timer.C:
		return fmt.Errorf("waited %s for a principal a removal holds: %w", LockWait, store.ErrLockTimeout)
	case <-ctx.Done():
		return ctx.Err()
	}

	return fn(ctx)
}

func (s *Store) DeleteByTenant(ctx context.Context, tenant did.DID) error {
	// A tenant removal waits for an in-flight principal removal, as it would on
	// the row Postgres holds FOR UPDATE.
	s.hold()
	defer s.release()
	s.mutex.Lock()
	defer s.mutex.Unlock()

	delete(s.principals, tenant)
	return nil
}
