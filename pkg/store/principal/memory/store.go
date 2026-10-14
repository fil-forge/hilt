// Package memory provides an in-memory implementation of principal.Store.
//
// The store holds two kinds of lock. mutex guards the map and is held for one
// read or one write at a time, never across a caller's callback. Each row has
// a slot: Add, a share-locked Get, Tombstone and WithLock take the slots of the rows
// they touch, so those calls on one row run one at a time, as the Postgres row
// locks order them. Tombstone holds its slot while fn runs and WithLock
// holds its slots while fn runs; a row none of them holds waits on nothing.
// slotsMutex guards only the slots map.
//
// The split mirrors Postgres. A removal there holds the principal row FOR
// UPDATE across its callback while ListByTenant still reads the table without
// waiting; the callback rewrites the policies naming the principal, and a
// policy write of its own lists this store's principals. Holding one lock
// across both would wedge the two writes against each other.
package memory

import (
	"cmp"
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

// row names a principal's slot.
type row struct {
	tenant did.DID
	id     string
}

type Store struct {
	mutex      sync.RWMutex
	principals map[did.DID]map[string]entry

	slotsMutex sync.Mutex
	// slots holds one single-slot channel per row, a channel rather than a
	// mutex so a wait on it can be bounded. Slots are never freed, so the map
	// grows by one entry per (tenant, id) ever named, rows that never existed
	// included, which is fine for the development backend.
	slots map[row]chan struct{}
}

// LockWait bounds how long a call waits for a row another call holds before
// giving up with [store.ErrLockTimeout], as lock_timeout bounds the wait a
// Postgres row lock gives. It is a variable so a test can shorten it.
var LockWait = store.LockTimeout

var _ principal.Store = (*Store)(nil)

func New() *Store {
	return &Store{principals: map[did.DID]map[string]entry{}, slots: map[row]chan struct{}{}}
}

func (s *Store) slot(r row) chan struct{} {
	s.slotsMutex.Lock()
	defer s.slotsMutex.Unlock()
	c, ok := s.slots[r]
	if !ok {
		c = make(chan struct{}, 1)
		s.slots[r] = c
	}
	return c
}

// hold takes the rows' slots, in one order so two callers over overlapping
// rows cannot deadlock, waiting at most LockWait in all; release gives them
// back. A wait that runs out returns [store.ErrLockTimeout] with nothing held.
func (s *Store) hold(ctx context.Context, rows ...row) (release func(), err error) {
	slices.SortFunc(rows, func(a, b row) int {
		return cmp.Or(strings.Compare(a.tenant.String(), b.tenant.String()), strings.Compare(a.id, b.id))
	})
	rows = slices.Compact(rows)
	timer := time.NewTimer(LockWait)
	defer timer.Stop()
	var held []chan struct{}
	release = func() {
		for _, c := range held {
			<-c
		}
	}
	for _, r := range rows {
		c := s.slot(r)
		select {
		case c <- struct{}{}:
			held = append(held, c)
		case <-timer.C:
			release()
			return nil, fmt.Errorf("waited %s for a principal another call holds: %w", LockWait, store.ErrLockTimeout)
		case <-ctx.Done():
			release()
			return nil, ctx.Err()
		}
	}
	return release, nil
}

// live returns the rows of the tenant's live principals among ids.
func (s *Store) live(tenant did.DID, ids []string) []row {
	s.mutex.RLock()
	defer s.mutex.RUnlock()
	var rows []row
	for _, id := range ids {
		if e, ok := s.principals[tenant][id]; ok && !e.deleted {
			rows = append(rows, row{tenant, id})
		}
	}
	return rows
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
	release, err := s.hold(ctx, row{tenant, externalID})
	if err != nil {
		return err
	}
	defer release()

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

// Get with [store.WithShareLock] waits for a Tombstone or WithLock that holds the same
// principal to finish, the way the Postgres read waits on the row lock. An
// unlocked read takes the map alone and may be answered while a removal's
// callback is still running, as the unlocked Postgres read is answered from
// its snapshot.
func (s *Store) Get(ctx context.Context, tenant did.DID, externalID string, opts ...store.ReadOption) (principal.Record, error) {
	if store.NewReadConfig(opts...).Share {
		release, err := s.hold(ctx, row{tenant, externalID})
		if err != nil {
			return principal.Record{}, err
		}
		defer release()
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

// Tombstone holds the row's slot for the whole call and takes the map mutex only
// to read the entry and, at the end, to write the tombstone. fn runs
// with the map unlocked, so it may write the policy store whose own writes
// read this one. A share-locked Get of the row waits on the slot and so
// observes either the principal or its tombstone, never a state in between;
// ListByTenant reads the map and never waits, as on Postgres.
func (s *Store) Tombstone(ctx context.Context, tenant did.DID, externalID string, fn func(ctx context.Context) error) error {
	release, err := s.hold(ctx, row{tenant, externalID})
	if err != nil {
		return err
	}
	defer release()

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

// WithLock holds the slots of the named live principals while fn runs, so a
// removal of one of them waits for it, as it waits on the rows Postgres holds
// FOR NO KEY UPDATE; ids with no live row, and principals of other tenants, are
// not waited on. Naming no principal locks nothing, as the Postgres call takes
// no row lock then either.
//
// The wait is bounded at [LockWait]. A policy write calls WithLock while holding
// the bucket's policy, and a removal holds its row while its callback rewrites
// that same policy, so each can end up waiting on what the other holds.
// Postgres bounds that cycle with lock_timeout; here the bound is the timer in
// hold, and the caller gets [store.ErrLockTimeout] to retry.
func (s *Store) WithLock(ctx context.Context, tenant did.DID, externalIDs []string, fn func(ctx context.Context) error) error {
	if len(externalIDs) == 0 {
		return fn(ctx)
	}
	release, err := s.hold(ctx, s.live(tenant, externalIDs)...)
	if err != nil {
		return err
	}
	defer release()

	return fn(ctx)
}

func (s *Store) DeleteByTenant(ctx context.Context, tenant did.DID) error {
	// A tenant removal waits for any call that holds one of its principals, as
	// the Postgres DELETE waits on their row locks.
	s.mutex.RLock()
	var rows []row
	for id := range s.principals[tenant] {
		rows = append(rows, row{tenant, id})
	}
	s.mutex.RUnlock()
	release, err := s.hold(ctx, rows...)
	if err != nil {
		return err
	}
	defer release()
	s.mutex.Lock()
	defer s.mutex.Unlock()

	delete(s.principals, tenant)
	return nil
}
