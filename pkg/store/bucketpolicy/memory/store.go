// Package memory provides an in-memory implementation of the bucket policy
// store. It enforces no referential integrity of its own: any tenant or
// principal may be named, and a bucket is checked only when the store is
// built with [WithBuckets].
package memory

import (
	"context"
	"encoding/json"
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
	mutex     sync.RWMutex
	policies  map[did.DID]entry
	hasBucket func(did.DID) bool
}

var _ bucketpolicystore.Store = (*Store)(nil)

// Option configures a Store.
type Option func(*Store)

// WithBuckets makes Put refuse a bucket for which has reports false, with
// [store.ErrRecordNotFound] and before fn runs, as the Postgres
// backend does. Without it any bucket may be named.
func WithBuckets(has func(did.DID) bool) Option {
	return func(s *Store) { s.hasBucket = has }
}

func New(opts ...Option) *Store {
	s := &Store{policies: map[did.DID]entry{}}
	for _, opt := range opts {
		opt(s)
	}
	return s
}

// Get ignores the lock mode: reads and writes are serialized by the store
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

// Put runs fn under the store mutex, so a concurrent Get waits for
// the callback to finish and observes either the old policy or the new one.
func (s *Store) Put(ctx context.Context, in bucketpolicystore.Input, fn func(ctx context.Context, old *bucketpolicystore.Record) error) (string, error) {
	if in.Bucket == did.Undef {
		return "", fmt.Errorf("policy bucket is required: %w", store.ErrInvalidArgument)
	}
	if in.Tenant == did.Undef {
		return "", fmt.Errorf("policy tenant is required: %w", store.ErrInvalidArgument)
	}

	s.mutex.Lock()
	defer s.mutex.Unlock()

	if s.hasBucket != nil && !s.hasBucket(in.Bucket) {
		return "", fmt.Errorf("bucket %s does not exist: %w", in.Bucket, store.ErrRecordNotFound)
	}
	var old *bucketpolicystore.Record
	if e, ok := s.policies[in.Bucket]; ok {
		rec := cloneRecord(e.rec)
		old = &rec
	}
	if err := bucketpolicystore.CheckInputPrecondition(in, old); err != nil {
		return "", err
	}
	if fn != nil {
		if err := fn(ctx, old); err != nil {
			return "", fmt.Errorf("before writing policy: %w", err)
		}
	}

	// Store the normalized document, as the Postgres backend does.
	var doc bucketpolicy.Policy
	if err := json.Unmarshal(bucketpolicy.Canonical(in.Policy), &doc); err != nil {
		return "", fmt.Errorf("normalizing policy: %w", err)
	}
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

func (s *Store) Delete(ctx context.Context, bucket did.DID, ifMatch string, fn func(ctx context.Context, old bucketpolicystore.Record) error) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	e, ok := s.policies[bucket]
	if !ok {
		return store.ErrRecordNotFound
	}
	if ifMatch != "" && e.rec.ETag != ifMatch {
		return fmt.Errorf("policy ETag is %s: %w", e.rec.ETag, store.ErrPreconditionFailed)
	}
	if fn != nil {
		if err := fn(ctx, cloneRecord(e.rec)); err != nil {
			return fmt.Errorf("before deleting policy: %w", err)
		}
	}
	delete(s.policies, bucket)
	return nil
}

// DeleteByBucket runs fn under the store mutex, as Put does, so a
// policy write waits for it.
func (s *Store) DeleteByBucket(ctx context.Context, bucket did.DID, fn func(ctx context.Context) error) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	if fn != nil {
		if err := fn(ctx); err != nil {
			return err
		}
	}
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

func cloneRecord(r bucketpolicystore.Record) bucketpolicystore.Record {
	r.Policy = clonePolicy(r.Policy)
	return r
}

func clonePolicy(d bucketpolicy.Policy) bucketpolicy.Policy {
	if d.Statements == nil {
		return bucketpolicy.Policy{}
	}
	statements := make([]bucketpolicy.Statement, len(d.Statements))
	copy(statements, d.Statements)
	for i := range statements {
		statements[i].Principal.IDs = slices.Clone(statements[i].Principal.IDs)
		statements[i].Actions = slices.Clone(statements[i].Actions)
	}
	return bucketpolicy.Policy{Statements: statements}
}
