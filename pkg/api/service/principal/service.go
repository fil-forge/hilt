// Package principal provides the business logic for a tenant's principals: the
// console users whose access to the tenant's buckets is computed from bucket
// policies at request time. A principal holds no DID, no vault entry and no
// delegation, and appears in no UCAN; the keys bound to it hold no delegation
// either.
//
// Removal is the one operation that spans three tables. It runs under the
// principal store's row lock: the callback publishes the invalidation, strips
// the principal from every policy naming it, and deletes its keys, and only
// then does the store delete the row and commit. A failure part way leaves the
// principal with narrower access and a retryable delete.
//
// Known errors are in errors.go so handlers can map them to HTTP responses;
// unexpected failures are returned wrapped for the handler to log.
package principal

import (
	"context"
	"errors"
	"fmt"
	"slices"

	"github.com/fil-forge/hilt/pkg/bucketpolicy"
	"github.com/fil-forge/hilt/pkg/invalidation"
	"github.com/fil-forge/hilt/pkg/store"
	accesskeystore "github.com/fil-forge/hilt/pkg/store/accesskey"
	bucketpolicystore "github.com/fil-forge/hilt/pkg/store/bucketpolicy"
	principalstore "github.com/fil-forge/hilt/pkg/store/principal"
	tenantstore "github.com/fil-forge/hilt/pkg/store/tenant"
	"github.com/fil-forge/hilt/pkg/vault"
	"github.com/fil-forge/ucantone/did"
	"go.uber.org/zap"
)

const (
	// maxUserIDLength bounds the opaque userId the caller supplies.
	maxUserIDLength = 255
)

// Service implements the principal operations shared by the REST handlers.
type Service struct {
	logger        *zap.Logger
	tenants       tenantstore.Store
	principals    principalstore.Store
	policies      bucketpolicystore.Store
	accessKeys    accesskeystore.Store
	secrets       vault.Vault
	invalidations invalidation.Publisher
}

// New constructs the principal service.
func New(
	logger *zap.Logger,
	tenants tenantstore.Store,
	principals principalstore.Store,
	policies bucketpolicystore.Store,
	accessKeys accesskeystore.Store,
	secrets vault.Vault,
	invalidations invalidation.Publisher,
) *Service {
	return &Service{
		logger:        logger,
		tenants:       tenants,
		principals:    principals,
		policies:      policies,
		accessKeys:    accessKeys,
		secrets:       secrets,
		invalidations: invalidations,
	}
}

// Create records the principal and nothing else. It is idempotent: the second
// report is false when the principal already existed.
func (s *Service) Create(ctx context.Context, externalID, userID string) (principalstore.Record, bool, error) {
	// bucketpolicy.Wildcard is the policy language's "every principal", so a
	// principal of that name would collide with it: deleting the principal would
	// strip the wildcard from every policy the tenant has.
	if userID == "" || len(userID) > maxUserIDLength || userID == bucketpolicy.Wildcard {
		return principalstore.Record{}, false, ErrInvalidUserID
	}
	tenantID, err := s.tenant(ctx, externalID)
	if err != nil {
		return principalstore.Record{}, false, err
	}

	created := true
	if err := s.principals.Add(ctx, tenantID, userID); errors.Is(err, store.ErrRecordExists) {
		created = false
	} else if err != nil {
		return principalstore.Record{}, false, fmt.Errorf("recording principal: %w", err)
	}

	rec, err := s.principals.Get(ctx, tenantID, userID)
	if err != nil {
		return principalstore.Record{}, false, fmt.Errorf("loading principal: %w", err)
	}
	if created {
		s.logger.Info("created principal", zap.Stringer("tenant", tenantID), zap.String("principal", userID))
	}
	return rec, created, nil
}

// List returns every principal of the tenant, ordered by userId.
func (s *Service) List(ctx context.Context, externalID string) ([]principalstore.Record, error) {
	tenantID, err := s.tenant(ctx, externalID)
	if err != nil {
		return nil, err
	}
	recs, err := s.principals.ListByTenant(ctx, tenantID)
	if err != nil {
		return nil, fmt.Errorf("listing principals: %w", err)
	}
	return recs, nil
}

// Get returns one principal of the tenant.
func (s *Service) Get(ctx context.Context, externalID, userID string) (principalstore.Record, error) {
	tenantID, err := s.tenant(ctx, externalID)
	if err != nil {
		return principalstore.Record{}, err
	}
	return s.principal(ctx, tenantID, userID)
}

// Delete removes the principal, its access to every bucket, and its keys. The
// store holds the principal row locked while [Service.remove] runs, so an
// authorize request for the principal waits for the outcome. It is idempotent:
// a principal that is already gone is a no-op.
func (s *Service) Delete(ctx context.Context, externalID, userID string) error {
	tenantID, err := s.tenant(ctx, externalID)
	if err != nil {
		return err
	}
	if err := s.principals.Delete(ctx, tenantID, userID, func(ctx context.Context) error {
		return s.remove(ctx, tenantID, userID)
	}); err != nil {
		// A lock the removal waited on, or a policy edited between the listing
		// and the rewrite, means another writer got there first. Nothing was
		// committed, so the caller repeats the call.
		if errors.Is(err, store.ErrLockTimeout) || errors.Is(err, store.ErrPreconditionFailed) {
			s.logger.Info("principal removal lost a race with a concurrent write",
				zap.Stringer("tenant", tenantID), zap.String("principal", userID), zap.Error(err))
			return ErrConcurrentChange
		}
		return fmt.Errorf("deleting principal %q: %w", userID, err)
	}
	s.logger.Info("deleted principal", zap.Stringer("tenant", tenantID), zap.String("principal", userID))
	return nil
}

// remove runs while the principal row is locked, in the RFC's order: publish
// the invalidation, strip the principal from every policy naming it, delete
// its keys. Each step is idempotent, so a failure is retried by repeating the
// call. The one invalidation covers everything the removal changes, so the
// policy and key writes it makes publish none of their own.
func (s *Service) remove(ctx context.Context, tenantID did.DID, userID string) error {
	if err := s.invalidations.Invalidate(ctx, tenantID, userID); err != nil {
		return err
	}
	if err := s.stripFromPolicies(ctx, tenantID, userID); err != nil {
		return err
	}
	return s.deleteKeys(ctx, tenantID, userID)
}

// stripFromPolicies removes the principal from every statement naming it,
// deleting statements left with no principal and policies left with no
// statement. Each write carries the ETag the listing read, so a policy edited
// concurrently fails the removal rather than reverting it. Policies that
// reach the principal only through the wildcard are left alone: the wildcard
// names the tenant's principals, and this one is about to stop being one.
func (s *Service) stripFromPolicies(ctx context.Context, tenantID did.DID, userID string) error {
	recs, err := s.policies.ListByPrincipal(ctx, tenantID, userID)
	if err != nil {
		return fmt.Errorf("listing the principal's policies: %w", err)
	}
	for _, rec := range recs {
		doc, changed := withoutPrincipal(rec.Policy, userID)
		if !changed {
			continue
		}
		etag := rec.ETag
		if len(doc.Statements) == 0 {
			if err := s.policies.Delete(ctx, rec.Bucket, etag, nil); err != nil && !errors.Is(err, store.ErrRecordNotFound) {
				return fmt.Errorf("deleting the policy of bucket %s: %w", rec.Bucket, err)
			}
			continue
		}
		if _, err := s.policies.Put(ctx, bucketpolicystore.Input{
			Bucket:  rec.Bucket,
			Tenant:  tenantID,
			Policy:  doc,
			IfMatch: &etag,
		}, nil); err != nil {
			return fmt.Errorf("rewriting the policy of bucket %s: %w", rec.Bucket, err)
		}
	}
	return nil
}

// deleteKeys removes the principal's access keys: the row first, so a key
// whose vault entry outlives it is unreachable rather than unusable-but-present.
func (s *Service) deleteKeys(ctx context.Context, tenantID did.DID, userID string) error {
	recs, err := s.accessKeys.ListByTenant(ctx, tenantID, accesskeystore.WithPrincipal(userID))
	if err != nil {
		return fmt.Errorf("listing the principal's access keys: %w", err)
	}
	for _, rec := range recs {
		// The invalidation for this principal is already published, so the key
		// deletions publish nothing of their own.
		if err := s.accessKeys.Delete(ctx, rec.ID, nil); err != nil {
			return fmt.Errorf("deleting access key %s: %w", rec.ID, err)
		}
		if err := s.secrets.Delete(ctx, vault.AccessKeyPath(tenantID, rec.ID)); err != nil {
			s.logger.Warn("removing access key from vault",
				zap.Stringer("access_key", rec.ID),
				zap.Error(err),
			)
		}
	}
	return nil
}

// ListAccessKeys returns the keys bound to the principal.
func (s *Service) ListAccessKeys(ctx context.Context, externalID, userID string) ([]accesskeystore.Record, error) {
	tenantID, err := s.tenant(ctx, externalID)
	if err != nil {
		return nil, err
	}
	if _, err := s.principal(ctx, tenantID, userID); err != nil {
		return nil, err
	}
	recs, err := s.accessKeys.ListByTenant(ctx, tenantID, accesskeystore.WithPrincipal(userID))
	if err != nil {
		return nil, fmt.Errorf("listing the principal's access keys: %w", err)
	}
	return recs, nil
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

// principal resolves userID to a principal of the tenant, or
// [ErrPrincipalNotFound].
func (s *Service) principal(ctx context.Context, tenantID did.DID, userID string) (principalstore.Record, error) {
	rec, err := s.principals.Get(ctx, tenantID, userID)
	if errors.Is(err, store.ErrRecordNotFound) {
		return principalstore.Record{}, ErrPrincipalNotFound
	} else if err != nil {
		return principalstore.Record{}, fmt.Errorf("looking up principal: %w", err)
	}
	return rec, nil
}

// withoutPrincipal returns doc with userID removed from every statement naming
// it, dropping statements left with no principal, and reports whether anything
// changed.
func withoutPrincipal(doc bucketpolicy.Policy, userID string) (bucketpolicy.Policy, bool) {
	var statements []bucketpolicy.Statement
	changed := false
	for _, st := range doc.Statements {
		principals := slices.DeleteFunc(slices.Clone(st.Principals), func(p string) bool { return p == userID })
		if len(principals) != len(st.Principals) {
			changed = true
		}
		if len(principals) == 0 {
			continue
		}
		statements = append(statements, bucketpolicy.Statement{
			Effect:     st.Effect,
			Principals: principals,
			Actions:    st.Actions,
		})
	}
	return bucketpolicy.Policy{Statements: statements}, changed
}
