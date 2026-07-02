// Package memory provides an in-memory implementation of vault.Vault.
package memory

import (
	"context"
	"slices"
	"sync"

	"github.com/fil-forge/hilt/pkg/vault"
)

type Store struct {
	mutex  sync.RWMutex
	values map[string][]byte
}

var _ vault.Vault = (*Store)(nil)

func New() *Store {
	return &Store{values: map[string][]byte{}}
}

func (s *Store) Read(ctx context.Context, key string) ([]byte, error) {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	v, ok := s.values[key]
	if !ok {
		return nil, vault.ErrNotFound
	}
	// Return a copy so callers cannot mutate the stored secret.
	return slices.Clone(v), nil
}

func (s *Store) Write(ctx context.Context, key string, value []byte) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	// Store a copy so later mutation of the caller's slice cannot alter the
	// stored secret.
	s.values[key] = slices.Clone(value)
	return nil
}

func (s *Store) Delete(ctx context.Context, key string) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	delete(s.values, key)
	return nil
}
