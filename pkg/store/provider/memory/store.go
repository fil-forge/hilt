package memory

import (
	"context"
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

func (s *Store) Add(ctx context.Context, id did.DID, region string) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	for _, p := range s.providers {
		if p.ID == id || p.Region == region {
			return store.ErrRecordExists
		}
	}
	s.providers = append(s.providers, provider.Record{
		ID:        id,
		Region:    region,
		CreatedAt: time.Now().UTC(),
	})
	return nil
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
