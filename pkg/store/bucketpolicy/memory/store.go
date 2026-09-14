// Package memory provides an in-memory implementation of the bucket policy
// store. It does not enforce referential integrity: any bucket, tenant or
// principal may be named.
package memory

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/fil-forge/hilt/pkg/bucketpolicy"
	"github.com/fil-forge/hilt/pkg/store"
	bucketpolicystore "github.com/fil-forge/hilt/pkg/store/bucketpolicy"
	"github.com/fil-forge/ucantone/did"
)

// entry is a stored policy with the index the Postgres backend keeps in
// bucket_policy_principal: the principals it names and whether it names the
// wildcard.
type entry struct {
	tenant   did.DID
	rec      bucketpolicystore.Record
	named    map[string]bool
	wildcard bool
}

type Store struct {
	mutex    sync.RWMutex
	policies map[did.DID]entry
}

var _ bucketpolicystore.Store = (*Store)(nil)

func New() *Store {
	return &Store{policies: map[did.DID]entry{}}
}

// Get ignores the lock option: reads and writes are serialized by the store
// mutex, so a read already waits for an in-flight write.
func (s *Store) Get(ctx context.Context, bucket did.DID, opts ...store.ReadOption) (bucketpolicystore.Record, error) {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	e, ok := s.policies[bucket]
	if !ok {
		return bucketpolicystore.Record{}, store.ErrRecordNotFound
	}
	return cloneRecord(e.rec), nil
}

// Put runs beforeCommit under the store mutex, so a concurrent Get waits for
// the callback to finish and observes either the old policy or the new one.
func (s *Store) Put(ctx context.Context, in bucketpolicystore.Input, beforeCommit func(ctx context.Context, old *bucketpolicystore.Record) error) (string, error) {
	if in.Bucket == did.Undef {
		return "", fmt.Errorf("policy bucket is required: %w", store.ErrInvalidArgument)
	}
	if in.Tenant == did.Undef {
		return "", fmt.Errorf("policy tenant is required: %w", store.ErrInvalidArgument)
	}

	s.mutex.Lock()
	defer s.mutex.Unlock()

	var old *bucketpolicystore.Record
	if e, ok := s.policies[in.Bucket]; ok {
		rec := cloneRecord(e.rec)
		old = &rec
	}
	if err := checkPrecondition(old, in.IfMatch); err != nil {
		return "", err
	}
	if beforeCommit != nil {
		if err := beforeCommit(ctx, old); err != nil {
			return "", fmt.Errorf("before writing policy: %w", err)
		}
	}

	doc := clonePolicy(in.Policy)
	named, wildcard := bucketpolicy.Named(doc)
	namedSet := make(map[string]bool, len(named))
	for _, p := range named {
		namedSet[p] = true
	}
	etag := bucketpolicy.ETag(doc)
	s.policies[in.Bucket] = entry{
		tenant: in.Tenant,
		rec: bucketpolicystore.Record{
			Bucket:    in.Bucket,
			Policy:    doc,
			ETag:      etag,
			UpdatedAt: time.Now().UTC(),
		},
		named:    namedSet,
		wildcard: wildcard,
	}
	return etag, nil
}

func (s *Store) Delete(ctx context.Context, bucket did.DID, ifMatch string, beforeCommit func(ctx context.Context, old bucketpolicystore.Record) error) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	e, ok := s.policies[bucket]
	if !ok {
		return store.ErrRecordNotFound
	}
	if e.rec.ETag != ifMatch {
		return fmt.Errorf("policy ETag is %s: %w", e.rec.ETag, store.ErrPreconditionFailed)
	}
	if beforeCommit != nil {
		if err := beforeCommit(ctx, cloneRecord(e.rec)); err != nil {
			return fmt.Errorf("before deleting policy: %w", err)
		}
	}
	delete(s.policies, bucket)
	return nil
}

func (s *Store) DeleteByBucket(ctx context.Context, bucket did.DID) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	delete(s.policies, bucket)
	return nil
}

func (s *Store) ListByPrincipal(ctx context.Context, tenant did.DID, principal string, opts ...store.ReadOption) ([]bucketpolicystore.Record, error) {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	var recs []bucketpolicystore.Record
	for _, e := range s.policies {
		if e.tenant != tenant {
			continue
		}
		if e.wildcard || e.named[principal] {
			recs = append(recs, cloneRecord(e.rec))
		}
	}
	slices.SortFunc(recs, func(a, b bucketpolicystore.Record) int {
		return strings.Compare(a.Bucket.String(), b.Bucket.String())
	})
	return recs, nil
}

// checkPrecondition applies the If-Match / If-None-Match rule: a nil ifMatch
// requires no current policy; a non-nil one must equal the current ETag.
func checkPrecondition(old *bucketpolicystore.Record, ifMatch *string) error {
	switch {
	case ifMatch == nil && old != nil:
		return fmt.Errorf("policy already exists with ETag %s: %w", old.ETag, store.ErrPreconditionFailed)
	case ifMatch != nil && old == nil:
		return fmt.Errorf("bucket has no policy: %w", store.ErrPreconditionFailed)
	case ifMatch != nil && old.ETag != *ifMatch:
		return fmt.Errorf("policy ETag is %s: %w", old.ETag, store.ErrPreconditionFailed)
	}
	return nil
}

func cloneRecord(r bucketpolicystore.Record) bucketpolicystore.Record {
	r.Policy = clonePolicy(r.Policy)
	return r
}

func clonePolicy(d bucketpolicy.Policy) bucketpolicy.Policy {
	if d.Statements == nil {
		return bucketpolicy.Policy{}
	}
	statements := make([]bucketpolicy.Statement, len(d.Statements))
	for i, st := range d.Statements {
		statements[i] = bucketpolicy.Statement{
			Effect:     st.Effect,
			Principals: slices.Clone(st.Principals),
			Actions:    slices.Clone(st.Actions),
		}
	}
	return bucketpolicy.Policy{Statements: statements}
}
