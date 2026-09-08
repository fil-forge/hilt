package memory

import (
	"context"
	"fmt"
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

func (s *Store) Add(ctx context.Context, id did.DID, region string, policy did.DID) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	if id == did.Undef {
		return fmt.Errorf("provider ID is required: %w", store.ErrInvalidArgument)
	}
	if region == "" {
		return fmt.Errorf("provider region is required: %w", store.ErrInvalidArgument)
	}
	if policy == did.Undef {
		return fmt.Errorf("provider policy is required: %w", store.ErrInvalidArgument)
	}

	for _, p := range s.providers {
		if p.ID == id || p.Region == region {
			return store.ErrRecordExists
		}
	}
	s.providers = append(s.providers, provider.Record{
		ID:        id,
		Region:    region,
		Policy:    policy,
		CreatedAt: time.Now().UTC(),
	})
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
