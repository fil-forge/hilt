// Package memory provides an in-memory implementation of wrapkey.Store.
package memory

import (
	"context"
	"sort"
	"sync"
	"time"

	"github.com/fil-forge/hilt/pkg/store"
	"github.com/fil-forge/hilt/pkg/store/wrapkey"
	"github.com/fil-forge/ucantone/did"
)

type key struct {
	tenant  string
	version int
}

type Store struct {
	mutex sync.RWMutex
	keys  map[key]wrapkey.Record
}

var _ wrapkey.Store = (*Store)(nil)

func New() *Store {
	return &Store{keys: map[key]wrapkey.Record{}}
}

func (s *Store) Add(ctx context.Context, rec wrapkey.Record) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	k := key{tenant: rec.Tenant.String(), version: rec.Version}
	if _, ok := s.keys[k]; ok {
		return store.ErrRecordExists
	}
	// Enforce at most one active key per tenant.
	if rec.Status == wrapkey.Active {
		for _, existing := range s.keys {
			if existing.Tenant == rec.Tenant && existing.Status == wrapkey.Active {
				return store.ErrRecordExists
			}
		}
	}
	if rec.CreatedAt.IsZero() {
		rec.CreatedAt = time.Now().UTC()
	}
	s.keys[k] = rec
	return nil
}

func (s *Store) GetActive(ctx context.Context, tenant did.DID) (wrapkey.Record, error) {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	for _, rec := range s.keys {
		if rec.Tenant == tenant && rec.Status == wrapkey.Active {
			return rec, nil
		}
	}
	return wrapkey.Record{}, store.ErrRecordNotFound
}

func (s *Store) Get(ctx context.Context, tenant did.DID, version int) (wrapkey.Record, error) {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	rec, ok := s.keys[key{tenant: tenant.String(), version: version}]
	if !ok {
		return wrapkey.Record{}, store.ErrRecordNotFound
	}
	return rec, nil
}

func (s *Store) List(ctx context.Context, tenant did.DID) ([]wrapkey.Record, error) {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	var recs []wrapkey.Record
	for _, rec := range s.keys {
		if rec.Tenant == tenant {
			recs = append(recs, rec)
		}
	}
	// Newest version first.
	sort.Slice(recs, func(i, j int) bool { return recs[i].Version > recs[j].Version })
	return recs, nil
}

func (s *Store) Archive(ctx context.Context, tenant did.DID, version int) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	k := key{tenant: tenant.String(), version: version}
	rec, ok := s.keys[k]
	if !ok {
		return store.ErrRecordNotFound
	}
	rec.Status = wrapkey.Archived
	rec.ArchivedAt = time.Now().UTC()
	s.keys[k] = rec
	return nil
}
