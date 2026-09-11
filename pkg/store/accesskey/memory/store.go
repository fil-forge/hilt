// Package memory provides an in-memory implementation of accesskey.Store.
package memory

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/fil-forge/hilt/pkg/store"
	"github.com/fil-forge/hilt/pkg/store/accesskey"
	"github.com/fil-forge/ucantone/did"
)

type Store struct {
	mutex sync.RWMutex
	keys  map[did.DID]accesskey.Record
}

var _ accesskey.Store = (*Store)(nil)

func New() *Store {
	return &Store{keys: map[did.DID]accesskey.Record{}}
}

// Add stores the record. Like the other memory stores it enforces no
// referential integrity: a principal-bound key is accepted whether or not the
// principal exists.
func (s *Store) Add(ctx context.Context, in accesskey.Input) error {
	if err := in.Validate(); err != nil {
		return err
	}

	s.mutex.Lock()
	defer s.mutex.Unlock()

	if _, ok := s.keys[in.ID]; ok {
		return store.ErrRecordExists
	}
	// A service key's name is unique within the tenant; a principal-bound key's
	// name is unique within its principal. This mirrors the two partial unique
	// indexes of the Postgres schema.
	for _, rec := range s.keys {
		if rec.Tenant != in.Tenant || rec.Name != in.Name {
			continue
		}
		switch {
		case rec.Principal == nil && in.Principal == nil:
			return store.ErrRecordExists
		case rec.Principal != nil && in.Principal != nil && *rec.Principal == *in.Principal:
			return store.ErrRecordExists
		}
	}
	var expires *time.Time
	if in.ExpiresAt != nil {
		e := in.ExpiresAt.UTC()
		expires = &e
	}
	var principal *string
	if in.Principal != nil {
		p := *in.Principal
		principal = &p
	}
	s.keys[in.ID] = accesskey.Record{
		ID:          in.ID,
		Tenant:      in.Tenant,
		Name:        in.Name,
		Buckets:     slices.Clone(in.Buckets),
		Permissions: slices.Clone(in.Permissions),
		Principal:   principal,
		ExpiresAt:   expires,
		CreatedAt:   time.Now().UTC(),
	}
	return nil
}

// Get ignores the lock option: reads and writes are serialized by the store
// mutex, so a read already waits for an in-flight Delete.
func (s *Store) Get(ctx context.Context, id did.DID, opts ...store.ReadOption) (accesskey.Record, error) {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	rec, ok := s.keys[id]
	if !ok {
		return accesskey.Record{}, store.ErrRecordNotFound
	}
	return rec, nil
}

func (s *Store) ListByTenant(ctx context.Context, tenant did.DID, opts ...accesskey.ListOption) ([]accesskey.Record, error) {
	cfg := accesskey.NewListConfig(opts...)

	s.mutex.RLock()
	defer s.mutex.RUnlock()

	var recs []accesskey.Record
	for _, rec := range s.keys {
		if rec.Tenant != tenant {
			continue
		}
		if cfg.Principal != nil && (rec.Principal == nil || *rec.Principal != *cfg.Principal) {
			continue
		}
		recs = append(recs, rec)
	}
	slices.SortFunc(recs, func(a, b accesskey.Record) int {
		return strings.Compare(a.ID.String(), b.ID.String())
	})
	return recs, nil
}

// Delete runs beforeCommit under the store mutex, so a concurrent Get waits
// for the callback to finish and observes either the row or its absence, never
// a state in between.
func (s *Store) Delete(ctx context.Context, id did.DID, beforeCommit func(ctx context.Context) error) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	if _, ok := s.keys[id]; !ok {
		return nil
	}
	if beforeCommit != nil {
		if err := beforeCommit(ctx); err != nil {
			return fmt.Errorf("before deleting access key: %w", err)
		}
	}
	delete(s.keys, id)
	return nil
}
