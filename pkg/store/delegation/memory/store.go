package memory

import (
	"context"
	"fmt"
	"iter"
	"slices"
	"strings"
	"sync"

	"github.com/fil-forge/hilt/pkg/store"
	dlgstore "github.com/fil-forge/hilt/pkg/store/delegation"
	ucanlib "github.com/fil-forge/libforge/ucan"
	"github.com/fil-forge/ucantone/did"
	"github.com/fil-forge/ucantone/ucan"
	"github.com/ipfs/go-cid"
)

const defaultListLimit = 1000

// Store guards its map with mutex, held for one read or one write at a time
// and never across Replace's callback, so writes run side by side as they do
// on Postgres.
type Store struct {
	mutex sync.RWMutex
	// audience DID -> delegations (sorted by link string)
	byAudience map[did.DID][]ucan.Delegation
}

var _ dlgstore.Store = (*Store)(nil)

func New() *Store {
	return &Store{byAudience: map[did.DID][]ucan.Delegation{}}
}

func (s *Store) PutBatch(ctx context.Context, delegations []ucan.Delegation) error {
	// Validate the whole batch before storing anything.
	if slices.Contains(delegations, nil) {
		return fmt.Errorf("delegations must not be nil: %w", store.ErrInvalidArgument)
	}

	s.mutex.Lock()
	defer s.mutex.Unlock()

	s.put(delegations)
	return nil
}

// Replace reads the audiences' sets, runs next without holding the map, and
// swaps the sets for next's result.
func (s *Store) Replace(ctx context.Context, audiences []did.DID, next func(ctx context.Context, current map[did.DID][]ucan.Delegation) (map[did.DID][]ucan.Delegation, error)) error {
	return s.replace(ctx, audiences, func(ucan.Delegation) bool { return true }, next)
}

// ReplaceBySubject runs as Replace does over the audiences' delegations over
// subject.
func (s *Store) ReplaceBySubject(ctx context.Context, subject did.DID, audiences []did.DID, next func(ctx context.Context, current map[did.DID][]ucan.Delegation) (map[did.DID][]ucan.Delegation, error)) error {
	if !subject.Defined() {
		return fmt.Errorf("cannot replace powerline delegations by subject: %w", store.ErrInvalidArgument)
	}
	return s.replace(ctx, audiences, func(d ucan.Delegation) bool { return d.Subject() == subject }, func(ctx context.Context, current map[did.DID][]ucan.Delegation) (map[did.DID][]ucan.Delegation, error) {
		replacement, err := next(ctx, current)
		if err != nil {
			return nil, err
		}
		if err := dlgstore.CheckReplacement(audiences, replacement); err != nil {
			return nil, err
		}
		return replacement, dlgstore.CheckSubject(audiences, subject.String(), replacement)
	})
}

// replace swaps the audiences' delegations that inScope selects for next's
// result and keeps the rest.
func (s *Store) replace(ctx context.Context, audiences []did.DID, inScope func(ucan.Delegation) bool, next func(ctx context.Context, current map[did.DID][]ucan.Delegation) (map[did.DID][]ucan.Delegation, error)) error {
	s.mutex.RLock()
	current := make(map[did.DID][]ucan.Delegation, len(audiences))
	for _, aud := range audiences {
		for _, d := range s.byAudience[aud] {
			if inScope(d) {
				current[aud] = append(current[aud], d)
			}
		}
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
		kept := slices.DeleteFunc(slices.Clone(s.byAudience[aud]), inScope)
		if len(kept) == 0 {
			delete(s.byAudience, aud)
		} else {
			s.byAudience[aud] = kept
		}
		s.put(replacement[aud])
	}
	return nil
}

// put stores the delegations, skipping any already held. The caller holds
// the mutex.
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
	s.mutex.Lock()
	defer s.mutex.Unlock()

	delete(s.byAudience, audience)
	return nil
}

func (s *Store) DeleteBySubject(ctx context.Context, subject did.DID) error {
	if !subject.Defined() {
		return fmt.Errorf("cannot delete powerline delegations: %w", store.ErrInvalidArgument)
	}
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
