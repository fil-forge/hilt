package memory

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/fil-forge/hilt/pkg/store"
	"github.com/fil-forge/hilt/pkg/store/provider"
	"github.com/fil-forge/ucantone/did"
)

type Store struct {
	mutex     sync.RWMutex
	providers []provider.Record
}

var _ provider.Store = (*Store)(nil)

func New() *Store {
	return &Store{}
}

func (s *Store) Add(ctx context.Context, id did.DID, region string, policy *did.DID) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	if id == did.Undef {
		return fmt.Errorf("provider ID is required: %w", store.ErrInvalidArgument)
	}
	if region == "" {
		return fmt.Errorf("provider region is required: %w", store.ErrInvalidArgument)
	}

	for _, p := range s.providers {
		if p.ID == id || p.Region == region {
			return store.ErrRecordExists
		}
	}
	now := time.Now().UTC()
	rec := provider.Record{
		ID:        id,
		Region:    region,
		CreatedAt: now,
		UpdatedAt: now,
	}
	if policy != nil {
		if *policy == did.Undef {
			return fmt.Errorf("provider policy must be defined when set: %w", store.ErrInvalidArgument)
		}
		p := *policy
		rec.Policy = &p
	}
	s.providers = append(s.providers, rec)
	return nil
}

func (s *Store) Get(ctx context.Context, id did.DID) (provider.Record, error) {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	for _, p := range s.providers {
		if p.ID == id {
			return p, nil
		}
	}
	return provider.Record{}, store.ErrRecordNotFound
}

func (s *Store) SetPolicy(ctx context.Context, id did.DID, policy did.DID) error {
	if policy == did.Undef {
		return fmt.Errorf("provider policy is required: %w", store.ErrInvalidArgument)
	}
	s.mutex.Lock()
	defer s.mutex.Unlock()

	for i := range s.providers {
		if s.providers[i].ID == id {
			p := policy
			s.providers[i].Policy = &p
			s.providers[i].UpdatedAt = time.Now().UTC()
			return nil
		}
	}
	return store.ErrRecordNotFound
}

func (s *Store) List(ctx context.Context) ([]provider.Record, error) {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	recs := slices.Clone(s.providers)
	if recs == nil {
		recs = []provider.Record{}
	}
	slices.SortFunc(recs, func(a, b provider.Record) int {
		return strings.Compare(a.ID.String(), b.ID.String())
	})
	return recs, nil
}

func (s *Store) GetByRegion(ctx context.Context, region string) (provider.Record, error) {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	for _, p := range s.providers {
		if p.Region == region {
			return p, nil
		}
	}
	return provider.Record{}, store.ErrRecordNotFound
}
