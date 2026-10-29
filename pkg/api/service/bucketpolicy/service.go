// Package bucketpolicy provides the business logic for bucket policies: the
// writes of a bucket's policy document, and the two principal reads computed
// from it, the policies naming a principal and its effective actions per
// bucket.
//
// Every write rewrites the delegations over the bucket of every key of each
// principal whose effective set the write changes, inside the store
// transaction that commits the document, revoking the replaced delegations
// before that transaction writes anything. Writes are unconditional and take no
// lock: of two concurrent writes to one bucket, the one that commits last is
// the stored policy.
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

	s3bkt "github.com/fil-forge/libforge/commands/s3/bucket"

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

// Record is a bucket's policy as the service reports it: the policy and the
// name the bucket is addressed by.
type Record struct {
	BucketName string
	Policy     s3bkt.PolicyDocument
}

// Access is a principal's effective actions on one bucket.
type Access struct {
	Name    string
	Actions []string
}

// Service implements the bucket policy writes the /s3/bucket/policy handler
// makes and the principal reads the REST handlers serve.
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

// Write creates or replaces the bucket's policy, for a caller that has
// resolved the tenant and the bucket. It validates doc against the bucket
// (every resource must name bucketName) and the tenant's principals.
// bucketName also names the bucket in errors.
//
// The delegations of the principals the change affects are rotated inside the
// store's transaction, so a publish failure leaves the old document in place.
func (s *Service) Write(ctx context.Context, tenantID, bucketID did.DID, bucketName string, doc s3bkt.PolicyDocument) error {
	tenantPrincipals, err := s.principals.ListIDsByTenant(ctx, tenantID)
	if err != nil {
		return err
	}
	if err := bucketpolicy.Validate(doc, bucketName, func(p string) bool { return slices.Contains(tenantPrincipals, p) }); err != nil {
		return err
	}
	in := bucketpolicystore.Input{
		Bucket: bucketID,
		Tenant: tenantID,
		Policy: doc,
	}
	err = s.policies.Put(ctx, in, func(ctx context.Context, old *bucketpolicystore.Record) error {
		var oldDoc *s3bkt.PolicyDocument
		if old != nil {
			oldDoc = &old.Policy
		}
		// Re-list inside the write: a principal created since the list above is
		// one the wildcard now reaches, so its keys are rotated here.
		principals, err := s.principals.ListIDsByTenant(ctx, tenantID)
		if err != nil {
			return err
		}
		// A principal removed since the validation above must not be named in
		// the committed document. The memory store checks no principals itself.
		named, _ := bucketpolicy.Named(doc)
		for _, p := range named {
			if !slices.Contains(principals, p) {
				return fmt.Errorf("principal %q was removed: %w", p, store.ErrInvalidArgument)
			}
		}
		return s.rotate(ctx, tenantID, bucketID, oldDoc, &doc, principals)
	})
	if err != nil {
		return s.writeError(bucketName, err)
	}
	return nil
}

// Remove removes the bucket's policy, for a caller that has resolved the
// tenant and the bucket. Every principal the policy reached loses its access,
// so each one's keys lose their delegations over the bucket inside the
// store's transaction. bucketName names the bucket in errors and logs.
func (s *Service) Remove(ctx context.Context, tenantID, bucketID did.DID, bucketName string) error {
	err := s.policies.Delete(ctx, bucketID, func(ctx context.Context, old bucketpolicystore.Record) error {
		principals, err := s.principals.ListIDsByTenant(ctx, tenantID)
		if err != nil {
			return err
		}
		return s.rotate(ctx, tenantID, bucketID, &old.Policy, nil, principals)
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
		out = append(out, Record{BucketName: name, Policy: rec.Policy})
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
// revoking the ones it replaces first. It runs inside the store's write
// transaction, bounded at [grant.BatchTimeout]. Any failure, the deadline and
// a failed publish included, fails the write and rolls it back.
func (s *Service) rotate(ctx context.Context, tenantID, bucketID did.DID, oldDoc, newDoc *s3bkt.PolicyDocument, principals []string) error {
	affected := bucketpolicy.Changed(oldDoc, newDoc, principals)
	if len(affected) == 0 {
		return nil
	}
	actions := make(map[string][]string, len(affected))
	for _, p := range affected {
		actions[p] = bucketpolicy.Effective(newDoc, p)
	}
	if err := s.grants.Rotate(ctx, tenantID, bucketID, actions); err != nil {
		return fmt.Errorf("rotating the delegations of the affected principals: %w", err)
	}
	return nil
}

// writeError maps the store's failures to the service's own; anything else is
// wrapped for the handler to log. A bucket the store no longer has (deleted
// since the lookup) is a missing bucket. A document the store refuses for
// naming a principal the tenant no longer has (removed between the validation
// and the write) is an invalid policy.
func (s *Service) writeError(bucketName string, err error) error {
	switch {
	case errors.Is(err, store.ErrRecordNotFound):
		return ErrBucketNotFound
	case errors.Is(err, store.ErrInvalidArgument):
		return fmt.Errorf("%w: a principal the policy names no longer exists", s3bkt.ErrInvalidPolicy)
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
