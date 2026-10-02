package memory

import (
	"context"
	"fmt"
	"iter"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/fil-forge/hilt/pkg/store"
	dlgstore "github.com/fil-forge/hilt/pkg/store/delegation"
	ucanlib "github.com/fil-forge/libforge/ucan"
	"github.com/fil-forge/ucantone/did"
	"github.com/fil-forge/ucantone/ucan"
	"github.com/ipfs/go-cid"
)

const defaultListLimit = 1000

// Store holds two locks. mutex guards the map and is held for one read or one
// write at a time, never across Replace's callback. writes serializes the
// writers, as the per-audience advisory locks do on Postgres, and is the lock
// Replace holds while next runs; it is a one-slot channel rather than a mutex
// so [Store.hold] can bound its wait.
type Store struct {
	mutex  sync.RWMutex
	writes chan struct{}
	// audience DID -> delegations (sorted by link string)
	byAudience map[did.DID][]ucan.Delegation
}

// LockWait bounds how long a writer waits for a write in flight before giving
// up with [store.ErrLockTimeout], as lock_timeout bounds the wait a Postgres
// advisory lock gives. It is a variable so a test can shorten it.
var LockWait = store.LockTimeout

var _ dlgstore.Store = (*Store)(nil)

func New() *Store {
	return &Store{writes: make(chan struct{}, 1), byAudience: map[did.DID][]ucan.Delegation{}}
}

// hold takes the write lock, waiting at most [LockWait] or until ctx is done,
// and release gives it back.
func (s *Store) hold(ctx context.Context) error {
	timer := time.NewTimer(LockWait)
	defer timer.Stop()
	select {
	case s.writes <- struct{}{}:
		return nil
	case <-timer.C:
		return fmt.Errorf("waited %s for an audience a write holds: %w", LockWait, store.ErrLockTimeout)
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (s *Store) release() { <-s.writes }

func (s *Store) PutBatch(ctx context.Context, delegations []ucan.Delegation) error {
	// Validate the whole batch before storing anything.
	if slices.Contains(delegations, nil) {
		return fmt.Errorf("delegations must not be nil: %w", store.ErrInvalidArgument)
	}

	if err := s.hold(ctx); err != nil {
		return err
	}
	defer s.release()
	s.mutex.Lock()
	defer s.mutex.Unlock()

	s.put(delegations)
	return nil
}

// Replace swaps the audiences' delegations holding the write lock for the
// whole call, which serializes it against every other write: next sees the
// settled current sets and its result is in place before the lock is
// released. Another writer waits at most [LockWait] for it. Reads take the
// map alone and are answered while next runs, as on Postgres.
func (s *Store) Replace(ctx context.Context, audiences []did.DID, next func(ctx context.Context, current map[did.DID][]ucan.Delegation) (map[did.DID][]ucan.Delegation, error)) error {
	if err := s.hold(ctx); err != nil {
		return err
	}
	defer s.release()

	s.mutex.RLock()
	current := make(map[did.DID][]ucan.Delegation, len(audiences))
	for _, aud := range audiences {
		current[aud] = slices.Clone(s.byAudience[aud])
	}
	s.mutex.RUnlock()

	replacement, err := next(ctx, current)
	if err != nil {
		return err
	}
	if err := dlgstore.CheckReplacement(audiences, replacement); err != nil {
		return err
	}

	s.mutex.Lock()
	defer s.mutex.Unlock()
	for _, aud := range audiences {
		delete(s.byAudience, aud)
		s.put(replacement[aud])
	}
	return nil
}

// put stores the delegations, skipping any already held. The caller holds
// both locks.
func (s *Store) put(delegations []ucan.Delegation) {
	for _, d := range delegations {
		aud := d.Audience()
		existing := s.byAudience[aud]
		if slices.ContainsFunc(existing, func(e ucan.Delegation) bool {
			return e.Link() == d.Link()
		}) {
			continue
		}
		existing = append(existing, d)
		slices.SortFunc(existing, func(a, b ucan.Delegation) int {
			return strings.Compare(a.Link().String(), b.Link().String())
		})
		s.byAudience[aud] = existing
	}
}

func (s *Store) ListByAudience(ctx context.Context, audience did.DID, opts ...store.PaginationOption) (store.Page[ucan.Delegation], error) {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	return page(slices.Clone(s.byAudience[audience]), opts), nil
}

func (s *Store) ListBySubject(ctx context.Context, subject did.DID, opts ...store.PaginationOption) (store.Page[ucan.Delegation], error) {
	if !subject.Defined() {
		return store.Page[ucan.Delegation]{}, fmt.Errorf("cannot list powerline delegations: %w", store.ErrInvalidArgument)
	}

	s.mutex.RLock()
	defer s.mutex.RUnlock()

	// The store indexes only by audience, so scan each audience's delegations and
	// collect those whose subject matches. The result is sorted by link because map
	// iteration order is not stable, and pagination needs a stable order.
	var dlgs []ucan.Delegation
	for _, existing := range s.byAudience {
		for _, d := range existing {
			if d.Subject() == subject {
				dlgs = append(dlgs, d)
			}
		}
	}
	slices.SortFunc(dlgs, func(a, b ucan.Delegation) int {
		return strings.Compare(a.Link().String(), b.Link().String())
	})
	return page(dlgs, opts), nil
}

// page applies the pagination options to a link-sorted list of delegations. The
// cursor is the link string of the last item of the previous page.
func page(dlgs []ucan.Delegation, opts []store.PaginationOption) store.Page[ucan.Delegation] {
	limit := defaultListLimit
	cfg := store.PaginationConfig{Limit: &limit}
	for _, opt := range opts {
		opt(&cfg)
	}

	if cfg.Cursor != nil {
		for i, d := range dlgs {
			if d.Link().String() == *cfg.Cursor {
				if i+1 < len(dlgs) {
					dlgs = dlgs[i+1:]
				} else {
					dlgs = nil
				}
				break
			}
		}
	}

	// A non-positive limit falls back to the default, matching the postgres
	// backend; without the guard, truncating to zero would panic below.
	if cfg.Limit == nil || *cfg.Limit <= 0 {
		cfg.Limit = &limit
	}

	var cursor *string
	if len(dlgs) > *cfg.Limit {
		dlgs = dlgs[:*cfg.Limit]
		last := dlgs[len(dlgs)-1].Link().String()
		cursor = &last
	}
	return store.Page[ucan.Delegation]{Cursor: cursor, Results: dlgs}
}

func (s *Store) DeleteByAudience(ctx context.Context, audience did.DID) error {
	if err := s.hold(ctx); err != nil {
		return err
	}
	defer s.release()
	s.mutex.Lock()
	defer s.mutex.Unlock()

	delete(s.byAudience, audience)
	return nil
}

func (s *Store) DeleteBySubject(ctx context.Context, subject did.DID) error {
	if !subject.Defined() {
		return fmt.Errorf("cannot delete powerline delegations: %w", store.ErrInvalidArgument)
	}

	if err := s.hold(ctx); err != nil {
		return err
	}
	defer s.release()
	s.mutex.Lock()
	defer s.mutex.Unlock()

	// The store indexes only by audience, so scan each audience's delegations and
	// drop those whose subject matches, removing now-empty audience entries.
	for aud, dlgs := range s.byAudience {
		kept := slices.DeleteFunc(dlgs, func(d ucan.Delegation) bool {
			return d.Subject() == subject
		})
		if len(kept) == 0 {
			delete(s.byAudience, aud)
		} else {
			s.byAudience[aud] = kept
		}
	}
	return nil
}

func (s *Store) ProofChain(ctx context.Context, aud did.DID, cmd ucan.Command, sub did.DID) ([]ucan.Delegation, []cid.Cid, error) {
	if !sub.Defined() {
		return nil, nil, fmt.Errorf("missing proof chain subject: %w", store.ErrInvalidArgument)
	}
	matcher := ucanlib.NewDelegationMatcher(s.listExact)
	return ucanlib.ProofChain(ctx, matcher, aud, cmd, sub)
}

// listExact lists delegations for the EXACT audience, command and subject. The
// subject MAY be [did.Undef] to indicate a powerline delegation.
func (s *Store) listExact(ctx context.Context, aud did.DID, cmd ucan.Command, sub did.DID) iter.Seq2[ucan.Delegation, error] {
	return func(yield func(ucan.Delegation, error) bool) {
		s.mutex.RLock()
		dlgs := slices.Clone(s.byAudience[aud])
		s.mutex.RUnlock()

		for _, d := range dlgs {
			if d.Command() == cmd && d.Subject() == sub {
				if !yield(d, nil) {
					return
				}
			}
		}
	}
}
