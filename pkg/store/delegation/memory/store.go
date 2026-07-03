package memory

import (
	"context"
	"errors"
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
	s.mutex.Lock()
	defer s.mutex.Unlock()

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
	return nil
}

func (s *Store) ListByAudience(ctx context.Context, audience did.DID, opts ...store.PaginationOption) (store.Page[ucan.Delegation], error) {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	limit := defaultListLimit
	cfg := store.PaginationConfig{Limit: &limit}
	for _, opt := range opts {
		opt(&cfg)
	}

	dlgs := slices.Clone(s.byAudience[audience])
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

	var cursor *string
	if cfg.Limit != nil && len(dlgs) > *cfg.Limit {
		dlgs = dlgs[:*cfg.Limit]
		last := dlgs[len(dlgs)-1].Link().String()
		cursor = &last
	}
	return store.Page[ucan.Delegation]{Cursor: cursor, Results: dlgs}, nil
}

func (s *Store) DeleteByAudience(ctx context.Context, audience did.DID) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	delete(s.byAudience, audience)
	return nil
}

func (s *Store) DeleteBySubject(ctx context.Context, subject did.DID) error {
	if !subject.Defined() {
		return errors.New("cannot delete powerline delegations")
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
