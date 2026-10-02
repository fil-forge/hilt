// Package memory provides an in-memory implementation of accesskey.Store.
package memory

import (
	"context"
	"slices"
	"sync"
	"time"

	"github.com/fil-forge/hilt/pkg/store"
	"github.com/fil-forge/hilt/pkg/store/accesskey"
	"github.com/fil-forge/ucantone/did"
)

type Store struct {
	mutex      sync.RWMutex
	keys       map[did.DID]accesskey.Record
	principals func(ctx context.Context, tenant did.DID, principal string, fn func() error) error
}

var _ accesskey.Store = (*Store)(nil)

// Option configures a Store.
type Option func(*Store)

// WithPrincipals makes Add run a principal-bound key's insert inside guard,
// which holds the principal against a removal and refuses one that is not
// live with [store.ErrInvalidArgument], as the Postgres insert's FOR SHARE on
// the principal row does. The memory principal store's WithLive is the guard.
// Without it any principal may be named.
func WithPrincipals(guard func(ctx context.Context, tenant did.DID, principal string, fn func() error) error) Option {
	return func(s *Store) { s.principals = guard }
}

func New(opts ...Option) *Store {
	s := &Store{keys: map[did.DID]accesskey.Record{}}
	for _, opt := range opts {
		opt(s)
	}
	return s
}

// Add stores the record. It enforces no referential integrity of its own: a
// principal-bound key's principal is checked only when the store is built with
// [WithPrincipals], and then the insert runs while the principal is held.
func (s *Store) Add(ctx context.Context, in accesskey.Input) error {
	if err := in.Validate(); err != nil {
		return err
	}
	if in.Principal != nil && s.principals != nil {
		return s.principals(ctx, in.Tenant, *in.Principal, func() error { return s.add(in) })
	}
	return s.add(in)
}

func (s *Store) add(in accesskey.Input) error {
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

// Get ignores the lock mode: reads and writes are serialized by the store
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
	return recs, nil
}

func (s *Store) Delete(ctx context.Context, id did.DID) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	delete(s.keys, id)
	return nil
}
