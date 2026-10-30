// Package memory provides an in-memory implementation of the bucket policy
// store. It enforces no referential integrity of its own: any tenant or
// principal may be named, and a bucket is checked only when the store is
// built with [WithBuckets].
package memory

import (
	"context"
	"encoding/json"
	"fmt"
	"maps"
	"slices"
	"strings"
	"sync"
	"time"

	s3bkt "github.com/fil-forge/libforge/commands/s3/bucket"

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

func (s *Store) Get(ctx context.Context, bucket did.DID) (bucketpolicystore.Record, error) {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	e, ok := s.policies[bucket]
	if !ok {
		return bucketpolicystore.Record{}, store.ErrRecordNotFound
	}
	return cloneRecord(e.rec), nil
}

// Put reads the current policy, runs fn without holding the store mutex, and
// stores the new policy, so a concurrent write is never held up by fn and the
// last write to store wins.
func (s *Store) Put(ctx context.Context, in bucketpolicystore.Input, fn func(ctx context.Context, old *bucketpolicystore.Record) error) error {
	if in.Bucket == did.Undef {
		return fmt.Errorf("policy bucket is required: %w", store.ErrInvalidArgument)
	}
	if in.Tenant == did.Undef {
		return fmt.Errorf("policy tenant is required: %w", store.ErrInvalidArgument)
	}
	if s.hasBucket != nil && !s.hasBucket(in.Bucket) {
		return fmt.Errorf("bucket %s does not exist: %w", in.Bucket, store.ErrRecordNotFound)
	}
	var old *bucketpolicystore.Record
	if rec, err := s.Get(ctx, in.Bucket); err == nil {
		old = &rec
	}
	if fn != nil {
		if err := fn(ctx, old); err != nil {
			return fmt.Errorf("before writing policy: %w", err)
		}
	}

	// Store the normalized document, as the Postgres backend does.
	var doc s3bkt.PolicyDocument
	if err := json.Unmarshal(bucketpolicy.Canonical(in.Policy), &doc); err != nil {
		return fmt.Errorf("normalizing policy: %w", err)
	}
	named, wildcard := bucketpolicy.Named(doc)
	namedSet := make(map[string]bool, len(named))
	for _, p := range named {
		namedSet[p] = true
	}
	s.mutex.Lock()
	defer s.mutex.Unlock()
	s.policies[in.Bucket] = entry{
		tenant: in.Tenant,
		rec: bucketpolicystore.Record{
			Bucket:    in.Bucket,
			Policy:    doc,
			UpdatedAt: time.Now().UTC(),
		},
		named:    namedSet,
		wildcard: wildcard,
	}
	return nil
}

// Delete runs fn without holding the store mutex, as Put does.
func (s *Store) Delete(ctx context.Context, bucket did.DID, fn func(ctx context.Context, old bucketpolicystore.Record) error) error {
	old, err := s.Get(ctx, bucket)
	if err != nil {
		return err
	}
	if fn != nil {
		if err := fn(ctx, old); err != nil {
			return fmt.Errorf("before deleting policy: %w", err)
		}
	}
	s.mutex.Lock()
	defer s.mutex.Unlock()
	delete(s.policies, bucket)
	return nil
}

// DeleteByBucket runs fn without holding the store mutex, as Put does.
func (s *Store) DeleteByBucket(ctx context.Context, bucket did.DID, fn func(ctx context.Context) error) error {
	if fn != nil {
		if err := fn(ctx); err != nil {
			return err
		}
	}
	s.mutex.Lock()
	defer s.mutex.Unlock()
	delete(s.policies, bucket)
	return nil
}

func (s *Store) ListByPrincipal(ctx context.Context, tenant did.DID, principal string) ([]bucketpolicystore.Record, error) {
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

func clonePolicy(d s3bkt.PolicyDocument) s3bkt.PolicyDocument {
	if d.Statements == nil {
		return s3bkt.PolicyDocument{Version: d.Version}
	}
	statements := make([]s3bkt.Statement, len(d.Statements))
	copy(statements, d.Statements)
	for i := range statements {
		statements[i].Principal = maps.Clone(statements[i].Principal)
		statements[i].Actions = maps.Clone(statements[i].Actions)
		statements[i].Resources = maps.Clone(statements[i].Resources)
	}
	return s3bkt.PolicyDocument{Version: d.Version, Statements: statements}
}
