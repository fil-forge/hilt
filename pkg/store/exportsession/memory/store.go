// Package memory provides an in-memory implementation of exportsession.Store.
package memory

import (
	"bytes"
	"context"
	"encoding/json"
	"sync"
	"time"

	"github.com/fil-forge/hilt/pkg/store"
	"github.com/fil-forge/hilt/pkg/store/exportsession"
	"github.com/fil-forge/ucantone/did"
	"github.com/ipfs/go-cid"
)

// session keeps the audit log decoded so AppendAudit is a slice append.
type session struct {
	rec   exportsession.Record
	audit []json.RawMessage
}

type Store struct {
	mutex    sync.RWMutex
	sessions map[string]session
}

var _ exportsession.Store = (*Store)(nil)

func New() *Store {
	return &Store{sessions: map[string]session{}}
}

func (s *Store) Add(ctx context.Context, input exportsession.Input) error {
	// Mirrors the table's NOT NULL / CHECK constraints.
	if input.ID == "" || input.CustomerKey == "" {
		return store.ErrInvalidArgument
	}

	s.mutex.Lock()
	defer s.mutex.Unlock()

	if _, ok := s.sessions[input.ID]; ok {
		return store.ErrRecordExists
	}
	now := time.Now().UTC()
	s.sessions[input.ID] = session{rec: exportsession.Record{
		ID:          input.ID,
		Tenant:      input.Tenant,
		Bucket:      input.Bucket,
		CustomerKey: input.CustomerKey,
		State:       exportsession.Opened,
		CreatedAt:   now,
		UpdatedAt:   now,
		ExpiresAt:   input.ExpiresAt.UTC(),
	}}
	return nil
}

func (s *Store) Get(ctx context.Context, id string) (exportsession.Record, error) {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	sess, ok := s.sessions[id]
	if !ok {
		return exportsession.Record{}, store.ErrRecordNotFound
	}
	return sess.record(), nil
}

func (s *Store) Transition(ctx context.Context, id string, from, to exportsession.State) error {
	if !exportsession.ValidTransition(from, to) || to == exportsession.Pinned {
		return store.ErrInvalidArgument
	}

	s.mutex.Lock()
	defer s.mutex.Unlock()

	sess, ok := s.sessions[id]
	if !ok || sess.rec.State != from {
		return store.ErrRecordNotFound
	}
	sess.rec.State = to
	sess.rec.UpdatedAt = time.Now().UTC()
	s.sessions[id] = sess
	return nil
}

func (s *Store) Pin(ctx context.Context, id string, root cid.Cid) error {
	if !root.Defined() {
		return store.ErrInvalidArgument
	}

	s.mutex.Lock()
	defer s.mutex.Unlock()

	sess, ok := s.sessions[id]
	if !ok || sess.rec.State != exportsession.PoPVerified {
		return store.ErrRecordNotFound
	}
	now := time.Now().UTC()
	sess.rec.State = exportsession.Pinned
	sess.rec.Root = root
	sess.rec.PinnedAt = now
	sess.rec.UpdatedAt = now
	s.sessions[id] = sess
	return nil
}

func (s *Store) AppendAudit(ctx context.Context, id string, entry []byte) error {
	// Postgres rejects a non-JSON entry at the jsonb cast.
	if !json.Valid(entry) {
		return store.ErrInvalidArgument
	}

	s.mutex.Lock()
	defer s.mutex.Unlock()

	sess, ok := s.sessions[id]
	if !ok {
		return store.ErrRecordNotFound
	}
	sess.audit = append(sess.audit, json.RawMessage(bytes.Clone(entry)))
	sess.rec.UpdatedAt = time.Now().UTC()
	s.sessions[id] = sess
	return nil
}

func (s *Store) HasOpen(ctx context.Context, tenant did.DID) (bool, error) {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	for _, sess := range s.sessions {
		if sess.rec.Tenant == tenant && sess.rec.State.Open() {
			return true, nil
		}
	}
	return false, nil
}

func (s *Store) HasOpenForBucket(ctx context.Context, bucket did.DID) (bool, error) {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	for _, sess := range s.sessions {
		if sess.rec.Bucket == bucket && sess.rec.State.Open() {
			return true, nil
		}
	}
	return false, nil
}

func (s *Store) DeleteByTenant(ctx context.Context, tenant did.DID) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	for id, sess := range s.sessions {
		if sess.rec.Tenant == tenant {
			delete(s.sessions, id)
		}
	}
	return nil
}

// record returns a copy of the session with the audit log encoded.
func (sess session) record() exportsession.Record {
	rec := sess.rec
	audit := sess.audit
	if audit == nil {
		audit = []json.RawMessage{}
	}
	b, err := json.Marshal(audit)
	if err != nil {
		panic(err) // every entry was json.Valid when appended
	}
	rec.Audit = b
	return rec
}
