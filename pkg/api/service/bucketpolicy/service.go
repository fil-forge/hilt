// Package policy provides the business logic for bucket policies: the
// compare-and-set reads and writes of a bucket's policy document, and the two
// principal reads computed from it, the policies naming a principal and its
// effective actions per bucket.
//
// Every write publishes one principal invalidation per principal whose
// effective set the write changes, inside the store transaction that commits
// the document and under one deadline for the whole batch. The store commits
// only when every publish succeeded, so a principal never keeps access the
// gateway has not been told to re-read.
//
// Known errors are in errors.go so handlers can map them to HTTP responses;
// unexpected failures are returned wrapped for the handler to log.
package bucketpolicy

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/fil-forge/hilt/pkg/bucketpolicy"
	"github.com/fil-forge/hilt/pkg/invalidation"
	"github.com/fil-forge/hilt/pkg/store"
	bucketstore "github.com/fil-forge/hilt/pkg/store/bucket"
	bucketpolicystore "github.com/fil-forge/hilt/pkg/store/bucketpolicy"
	principalstore "github.com/fil-forge/hilt/pkg/store/principal"
	tenantstore "github.com/fil-forge/hilt/pkg/store/tenant"
	"github.com/fil-forge/ucantone/did"
	"go.uber.org/zap"
	"golang.org/x/sync/errgroup"
)

// Record is a bucket's policy as the API reports it: the policy, its strong
// ETag, and the name the bucket is addressed by.
type Record struct {
	BucketName string
	Policy     bucketpolicy.Policy
	ETag       string
}

// Access is a principal's effective actions on one bucket.
type Access struct {
	BucketName string
	Actions    []string
}

// Service implements the bucket policy operations shared by the REST handlers.
type Service struct {
	logger        *zap.Logger
	tenants       tenantstore.Store
	buckets       bucketstore.Store
	principals    principalstore.Store
	policies      bucketpolicystore.Store
	invalidations invalidation.Publisher
}

// New constructs the policy service.
func New(
	logger *zap.Logger,
	tenants tenantstore.Store,
	buckets bucketstore.Store,
	principals principalstore.Store,
	policies bucketpolicystore.Store,
	invalidations invalidation.Publisher,
) *Service {
	return &Service{
		logger:        logger,
		tenants:       tenants,
		buckets:       buckets,
		principals:    principals,
		policies:      policies,
		invalidations: invalidations,
	}
}

// Get returns the bucket's policy with the ETag its next write conditions on.
func (s *Service) Get(ctx context.Context, externalID, bucketName string) (Record, error) {
	tenantID, err := s.tenant(ctx, externalID)
	if err != nil {
		return Record{}, err
	}
	b, err := s.bucket(ctx, tenantID, bucketName)
	if err != nil {
		return Record{}, err
	}
	rec, err := s.policies.Get(ctx, b.ID)
	if errors.Is(err, store.ErrRecordNotFound) {
		return Record{}, ErrPolicyNotFound
	} else if err != nil {
		return Record{}, fmt.Errorf("reading the policy of bucket %q: %w", bucketName, err)
	}
	return Record{BucketName: bucketName, Policy: rec.Policy, ETag: rec.ETag}, nil
}

// Put creates or replaces the bucket's policy. A nil ifMatch is the create
// (If-None-Match: *) and requires the bucket to have no policy; a non-nil one
// must equal the current ETag. It returns the new ETag and whether the call
// created the first policy for the bucket.
//
// The invalidations for the principals the change affects are published inside
// the store's transaction, so a publish failure leaves the old document in
// place.
func (s *Service) Put(ctx context.Context, externalID, bucketName string, doc bucketpolicy.Policy, ifMatch *string) (string, bool, error) {
	tenantID, err := s.tenant(ctx, externalID)
	if err != nil {
		return "", false, err
	}
	b, err := s.bucket(ctx, tenantID, bucketName)
	if err != nil {
		return "", false, err
	}
	tenantPrincipals, err := s.tenantPrincipals(ctx, tenantID)
	if err != nil {
		return "", false, err
	}
	if err := bucketpolicy.Validate(doc, func(p string) bool { return slices.Contains(tenantPrincipals, p) }); err != nil {
		return "", false, err
	}

	created := ifMatch == nil
	etag, err := s.policies.Put(ctx, bucketpolicystore.Input{
		Bucket:  b.ID,
		Tenant:  tenantID,
		Policy:  doc,
		IfMatch: ifMatch,
	}, func(ctx context.Context, old *bucketpolicystore.Record) error {
		var oldDoc *bucketpolicy.Policy
		if old != nil {
			oldDoc = &old.Policy
		}
		// Re-list under the bucket lock: a principal created since the list above
		// is one the wildcard now reaches, and its first authorize waits on this
		// same lock, so invalidating it here reaches it in time.
		principals, err := s.tenantPrincipals(ctx, tenantID)
		if err != nil {
			return err
		}
		return s.invalidate(ctx, tenantID, bucketpolicy.Changed(oldDoc, &doc, principals))
	})
	if err != nil {
		return "", false, s.writeError(bucketName, err)
	}
	s.logger.Info("wrote bucket policy",
		zap.Stringer("tenant", tenantID), zap.String("bucket", bucketName), zap.Bool("created", created))
	return etag, created, nil
}

// Delete removes the bucket's policy. ifMatch must equal the current ETag.
// Every principal the policy reached loses its access, so each is invalidated
// inside the store's transaction.
func (s *Service) Delete(ctx context.Context, externalID, bucketName, ifMatch string) error {
	tenantID, err := s.tenant(ctx, externalID)
	if err != nil {
		return err
	}
	b, err := s.bucket(ctx, tenantID, bucketName)
	if err != nil {
		return err
	}
	err = s.policies.Delete(ctx, b.ID, ifMatch, func(ctx context.Context, old bucketpolicystore.Record) error {
		// Re-list under the bucket lock, as Put does.
		principals, err := s.tenantPrincipals(ctx, tenantID)
		if err != nil {
			return err
		}
		return s.invalidate(ctx, tenantID, bucketpolicy.Changed(&old.Policy, nil, principals))
	})
	if errors.Is(err, store.ErrRecordNotFound) {
		return ErrPolicyNotFound
	} else if err != nil {
		return s.writeError(bucketName, err)
	}
	s.logger.Info("deleted bucket policy", zap.Stringer("tenant", tenantID), zap.String("bucket", bucketName))
	return nil
}

// ListByPrincipal returns every policy of the tenant with a statement naming
// the principal or the wildcard, in bucket name order.
func (s *Service) ListByPrincipal(ctx context.Context, externalID, userID string) ([]Record, error) {
	tenantID, recs, err := s.principalPolicies(ctx, externalID, userID)
	if err != nil {
		return nil, err
	}
	names, err := s.bucketNames(ctx, tenantID, recs)
	if err != nil {
		return nil, err
	}
	out := make([]Record, 0, len(recs))
	for _, rec := range recs {
		name, ok := names[rec.Bucket]
		if !ok {
			continue // the bucket went away between the two reads
		}
		out = append(out, Record{BucketName: name, Policy: rec.Policy, ETag: rec.ETag})
	}
	slices.SortFunc(out, func(a, b Record) int { return strings.Compare(a.BucketName, b.BucketName) })
	return out, nil
}

// Access returns the principal's effective actions per bucket, computed from
// the tenant's stored policies. Buckets whose effective set is empty are
// omitted. It reads the store and makes no network call.
func (s *Service) Access(ctx context.Context, externalID, userID string) ([]Access, error) {
	tenantID, recs, err := s.principalPolicies(ctx, externalID, userID)
	if err != nil {
		return nil, err
	}
	names, err := s.bucketNames(ctx, tenantID, recs)
	if err != nil {
		return nil, err
	}
	out := make([]Access, 0, len(recs))
	for _, rec := range recs {
		actions := bucketpolicy.Effective(&rec.Policy, userID)
		if len(actions) == 0 {
			continue
		}
		name, ok := names[rec.Bucket]
		if !ok {
			continue // the bucket went away between the two reads
		}
		out = append(out, Access{BucketName: name, Actions: actions})
	}
	slices.SortFunc(out, func(a, b Access) int { return strings.Compare(a.BucketName, b.BucketName) })
	return out, nil
}

// principalPolicies resolves the tenant and the principal and returns the
// policies naming it.
func (s *Service) principalPolicies(ctx context.Context, externalID, userID string) (did.DID, []bucketpolicystore.Record, error) {
	tenantID, err := s.tenant(ctx, externalID)
	if err != nil {
		return did.Undef, nil, err
	}
	if _, err := s.principals.Get(ctx, tenantID, userID); errors.Is(err, store.ErrRecordNotFound) {
		return did.Undef, nil, ErrPrincipalNotFound
	} else if err != nil {
		return did.Undef, nil, fmt.Errorf("looking up principal: %w", err)
	}
	recs, err := s.policies.ListByPrincipal(ctx, tenantID, userID)
	if err != nil {
		return did.Undef, nil, fmt.Errorf("listing the principal's policies: %w", err)
	}
	return tenantID, recs, nil
}

// publishConcurrency is how many invalidations of one write are in flight at
// once. The revocation service takes them in any order.
const publishConcurrency = 4

// invalidate publishes one invalidation per principal, a few at a time, under
// one deadline for the whole batch: it runs inside the store's write
// transaction while the bucket is locked, so the batch is bounded at
// [invalidation.BatchTimeout] rather than each publish in turn (see there).
// Any failure, the deadline included, fails the write and rolls it back.
func (s *Service) invalidate(ctx context.Context, tenantID did.DID, principals []string) error {
	ctx, cancel := context.WithTimeout(ctx, invalidation.BatchTimeout)
	defer cancel()
	g, ctx := errgroup.WithContext(ctx)
	g.SetLimit(publishConcurrency)
	for _, p := range principals {
		g.Go(func() error {
			if err := s.invalidations.Invalidate(ctx, tenantID, p); err != nil {
				return fmt.Errorf("invalidating principal %q: %w", p, err)
			}
			return nil
		})
	}
	return g.Wait()
}

// writeError maps the store's compare-and-set and locking failures to the
// service's own; anything else is wrapped for the handler to log.
func (s *Service) writeError(bucketName string, err error) error {
	switch {
	case errors.Is(err, store.ErrPreconditionFailed):
		return ErrPreconditionFailed
	case errors.Is(err, store.ErrLockTimeout):
		return ErrConcurrentChange
	}
	return fmt.Errorf("writing the policy of bucket %q: %w", bucketName, err)
}

// tenant resolves the caller's external id to the tenant DID.
func (s *Service) tenant(ctx context.Context, externalID string) (did.DID, error) {
	rec, err := s.tenants.GetByExternalID(ctx, externalID)
	if errors.Is(err, store.ErrRecordNotFound) {
		return did.Undef, ErrTenantNotFound
	} else if err != nil {
		return did.Undef, fmt.Errorf("looking up tenant: %w", err)
	}
	return rec.ID, nil
}

// bucket resolves a bucket name within the tenant. A bucket another tenant
// owns is reported as missing, so a policy read tells a caller nothing about
// another tenant's names.
func (s *Service) bucket(ctx context.Context, tenantID did.DID, name string) (bucketstore.Record, error) {
	rec, err := s.buckets.GetByName(ctx, name)
	if errors.Is(err, store.ErrRecordNotFound) || (err == nil && rec.Tenant != tenantID) {
		return bucketstore.Record{}, ErrBucketNotFound
	} else if err != nil {
		return bucketstore.Record{}, fmt.Errorf("looking up bucket %q: %w", name, err)
	}
	return rec, nil
}

// tenantPrincipals returns the tenant's principal userIds, which validation
// checks names against and the wildcard expands to.
func (s *Service) tenantPrincipals(ctx context.Context, tenantID did.DID) ([]string, error) {
	recs, err := s.principals.ListByTenant(ctx, tenantID)
	if err != nil {
		return nil, fmt.Errorf("listing the tenant's principals: %w", err)
	}
	ids := make([]string, 0, len(recs))
	for _, rec := range recs {
		ids = append(ids, rec.ExternalID)
	}
	return ids, nil
}

// bucketNames resolves the bucket DIDs the records carry to the names the API
// addresses them by, in one listing.
func (s *Service) bucketNames(ctx context.Context, tenantID did.DID, recs []bucketpolicystore.Record) (map[did.DID]string, error) {
	if len(recs) == 0 {
		return nil, nil
	}
	ids := make([]did.DID, 0, len(recs))
	for _, rec := range recs {
		ids = append(ids, rec.Bucket)
	}
	page, err := store.Collect(ctx, func(ctx context.Context, opts store.PaginationConfig) (store.Page[bucketstore.Record], error) {
		o := []bucketstore.ListOption{bucketstore.WithIDs(ids...)}
		if opts.Cursor != nil {
			o = append(o, bucketstore.WithCursor(*opts.Cursor))
		}
		return s.buckets.ListByTenant(ctx, tenantID, o...)
	})
	if err != nil {
		return nil, fmt.Errorf("resolving bucket names: %w", err)
	}
	names := make(map[did.DID]string, len(page))
	for _, b := range page {
		names[b.ID] = b.Name
	}
	return names, nil
}
