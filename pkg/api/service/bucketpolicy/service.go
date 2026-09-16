// Package policy provides the business logic for bucket policies: the
// compare-and-set reads and writes of a bucket's policy document, and the two
// principal reads computed from it, the policies naming a principal and its
// effective actions per bucket.
//
// Every write rewrites the delegations over the bucket of every key of each
// principal whose effective set the write changes, inside the store
// transaction that commits the document, while the affected principal rows
// are locked, and under one deadline for the whole batch. The store commits
// only when the rotation succeeded, so a principal never keeps access the
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
	"github.com/fil-forge/hilt/pkg/grant"
	"github.com/fil-forge/hilt/pkg/store"
	bucketstore "github.com/fil-forge/hilt/pkg/store/bucket"
	bucketpolicystore "github.com/fil-forge/hilt/pkg/store/bucketpolicy"
	principalstore "github.com/fil-forge/hilt/pkg/store/principal"
	tenantstore "github.com/fil-forge/hilt/pkg/store/tenant"
	"github.com/fil-forge/ucantone/did"
	"go.uber.org/zap"
)

// Record is a bucket's policy as the API reports it: the policy, its strong
// ETag, and the name the bucket is addressed by.
type Record struct {
	BucketName string              `json:"bucketName"`
	ETag       string              `json:"etag"`
	Policy     bucketpolicy.Policy `json:"policy"`
}

// Access is a principal's effective actions on one bucket.
type Access struct {
	Name    string   `json:"name"`
	Actions []string `json:"actions"`
}

// Service implements the bucket policy operations shared by the REST handlers.
type Service struct {
	logger     *zap.Logger
	tenants    tenantstore.Store
	buckets    bucketstore.Store
	principals principalstore.Store
	policies   bucketpolicystore.Store
	grants     *grant.Rotator
}

// New constructs the policy service.
func New(
	logger *zap.Logger,
	tenants tenantstore.Store,
	buckets bucketstore.Store,
	principals principalstore.Store,
	policies bucketpolicystore.Store,
	grants *grant.Rotator,
) *Service {
	return &Service{
		logger:     logger,
		tenants:    tenants,
		buckets:    buckets,
		principals: principals,
		policies:   policies,
		grants:     grants,
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
// The delegations of the principals the change affects are rotated inside the
// store's transaction, so a publish failure leaves the old document in place.
func (s *Service) Put(ctx context.Context, externalID, bucketName string, doc bucketpolicy.Policy, ifMatch *string) (string, bool, error) {
	tenantID, err := s.tenant(ctx, externalID)
	if err != nil {
		return "", false, err
	}
	b, err := s.bucket(ctx, tenantID, bucketName)
	if err != nil {
		return "", false, err
	}
	etag, err := s.Write(ctx, tenantID, b.ID, bucketName, doc, ifMatch)
	if err != nil {
		return "", false, err
	}
	created := ifMatch == nil
	s.logger.Info("wrote bucket policy",
		zap.Stringer("tenant", tenantID), zap.String("bucket", bucketName), zap.Bool("created", created))
	return etag, created, nil
}

// Write is the write [Service.Put] makes once it has resolved the tenant and
// the bucket, for a caller that already holds both: it validates doc against
// the tenant's principals, creates or replaces the bucket's policy under the
// same compare-and-set rule, and rotates the affected principals' keys inside
// the store's transaction. Bucket creation stores the policy a CreateBucket
// request carries this way. bucketName names the bucket in errors.
func (s *Service) Write(ctx context.Context, tenantID, bucketID did.DID, bucketName string, doc bucketpolicy.Policy, ifMatch *string) (string, error) {
	tenantPrincipals, err := principalstore.ExternalIDs(ctx, s.principals, tenantID)
	if err != nil {
		return "", err
	}
	if err := bucketpolicy.Validate(doc, func(p string) bool { return slices.Contains(tenantPrincipals, p) }); err != nil {
		return "", err
	}
	etag, err := s.policies.Put(ctx, bucketpolicystore.Input{
		Bucket:  bucketID,
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
		// same lock, so rotating its keys here reaches it in time.
		principals, err := principalstore.ExternalIDs(ctx, s.principals, tenantID)
		if err != nil {
			return err
		}
		return s.rotate(ctx, tenantID, bucketID, oldDoc, &doc, principals)
	})
	if err != nil {
		return "", s.writeError(ctx, bucketName, err)
	}
	return etag, nil
}

// Delete removes the bucket's policy. ifMatch must equal the current ETag.
// Every principal the policy reached loses its access, so each one's keys lose
// their delegations over the bucket inside the store's transaction.
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
		principals, err := principalstore.ExternalIDs(ctx, s.principals, tenantID)
		if err != nil {
			return err
		}
		return s.rotate(ctx, tenantID, b.ID, &old.Policy, nil, principals)
	})
	if errors.Is(err, store.ErrRecordNotFound) {
		return ErrPolicyNotFound
	} else if err != nil {
		return s.writeError(ctx, bucketName, err)
	}
	s.logger.Info("deleted bucket policy", zap.Stringer("tenant", tenantID), zap.String("bucket", bucketName))
	return nil
}

// ListByPrincipal returns every policy of the tenant with a statement naming
// the principal or the wildcard, in bucket name order.
func (s *Service) ListByPrincipal(ctx context.Context, externalID, principalID string) ([]Record, error) {
	tenantID, recs, err := s.principalPolicies(ctx, externalID, principalID)
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
func (s *Service) Access(ctx context.Context, externalID, principalID string) ([]Access, error) {
	recs, err := s.ListByPrincipal(ctx, externalID, principalID)
	if err != nil {
		return nil, err
	}
	out := make([]Access, 0, len(recs))
	for _, rec := range recs {
		if actions := bucketpolicy.Effective(&rec.Policy, principalID); len(actions) > 0 {
			out = append(out, Access{Name: rec.BucketName, Actions: actions})
		}
	}
	return out, nil
}

// principalPolicies resolves the tenant and the principal and returns the
// policies naming it.
func (s *Service) principalPolicies(ctx context.Context, externalID, principalID string) (did.DID, []bucketpolicystore.Record, error) {
	tenantID, err := s.tenant(ctx, externalID)
	if err != nil {
		return did.Undef, nil, err
	}
	if _, err := s.principals.Get(ctx, tenantID, principalID); errors.Is(err, store.ErrRecordNotFound) {
		return did.Undef, nil, ErrPrincipalNotFound
	} else if err != nil {
		return did.Undef, nil, fmt.Errorf("looking up principal: %w", err)
	}
	recs, err := s.policies.ListByPrincipal(ctx, tenantID, principalID)
	if err != nil {
		return did.Undef, nil, fmt.Errorf("listing the principal's policies: %w", err)
	}
	return tenantID, recs, nil
}

// rotate rewrites the delegations over the bucket of every key of each
// principal whose effective actions the change from oldDoc to newDoc alters,
// holding those principals' rows so a key created for one of them meanwhile
// is either included or created from the committed policy. It runs inside the
// store's write transaction while the bucket is locked, so the whole of it is
// bounded at [grant.BatchTimeout] (see there). Any failure, the deadline
// included, fails the write and rolls it back.
func (s *Service) rotate(ctx context.Context, tenantID, bucketID did.DID, oldDoc, newDoc *bucketpolicy.Policy, principals []string) error {
	affected := bucketpolicy.Changed(oldDoc, newDoc, principals)
	if len(affected) == 0 {
		return nil
	}
	ctx, cancel := context.WithTimeout(ctx, grant.BatchTimeout)
	defer cancel()
	return s.principals.Lock(ctx, tenantID, affected, func(ctx context.Context) error {
		actions := make(map[string][]string, len(affected))
		for _, p := range affected {
			actions[p] = bucketpolicy.Effective(newDoc, p)
		}
		if err := s.grants.Rotate(ctx, tenantID, bucketID, actions); err != nil {
			return fmt.Errorf("rotating the delegations of the affected principals: %w", err)
		}
		return nil
	})
}

// writeError maps the store's compare-and-set and locking failures to the
// service's own; anything else is wrapped for the handler to log. The batch
// deadline of the rotation is a locking failure too: it fires before the lock
// timeout it runs under, and the write is retried the same way; the caller's
// own deadline running out is not, so the context error counts only while the
// caller's ctx lives. A document the store refuses for naming a principal the
// tenant no longer has (removed between the validation above and the write)
// is an invalid policy.
func (s *Service) writeError(ctx context.Context, bucketName string, err error) error {
	switch {
	case errors.Is(err, store.ErrPreconditionFailed):
		return ErrPreconditionFailed
	case store.Contended(ctx, err):
		return ErrConcurrentChange
	case errors.Is(err, store.ErrInvalidArgument):
		return fmt.Errorf("%w: a principal the policy names no longer exists", bucketpolicy.ErrInvalidPolicy)
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
