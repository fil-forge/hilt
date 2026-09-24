// Package principal provides the business logic for a tenant's principals: the
// console users whose access to the tenant's buckets is computed from bucket
// policies. A principal holds no DID, no vault entry and no delegation, and
// appears in no UCAN; each key bound to it holds the delegations the policies
// grant the principal.
//
// Removal is the one operation that spans three tables. It runs under the
// principal store's row lock: the callback revokes the delegations of the
// principal's keys, strips the principal from every policy naming it, and
// deletes its keys, and only then does the store mark the row removed and commit. A
// failure part way leaves the principal with narrower access and a retryable
// delete.
//
// Known errors are in errors.go so handlers can map them to HTTP responses;
// unexpected failures are returned wrapped for the handler to log.
package principal

import (
	"context"
	"errors"
	"fmt"

	"github.com/fil-forge/hilt/pkg/bucketpolicy"
	"github.com/fil-forge/hilt/pkg/grant"
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
	// maxPrincipalIDLength bounds the opaque principalId the caller supplies.
	maxPrincipalIDLength = 255
)

// Service implements the principal operations shared by the REST handlers.
type Service struct {
	logger     *zap.Logger
	tenants    tenantstore.Store
	principals principalstore.Store
	policies   bucketpolicystore.Store
	accessKeys accesskeystore.Store
	secrets    vault.Vault
	grants     *grant.Rotator
}

// New constructs the principal service.
func New(
	logger *zap.Logger,
	tenants tenantstore.Store,
	principals principalstore.Store,
	policies bucketpolicystore.Store,
	accessKeys accesskeystore.Store,
	secrets vault.Vault,
	grants *grant.Rotator,
) *Service {
	return &Service{
		logger:     logger,
		tenants:    tenants,
		principals: principals,
		policies:   policies,
		accessKeys: accessKeys,
		secrets:    secrets,
		grants:     grants,
	}
}

// Create records the principal and nothing else. It is idempotent: the second
// report is false when the principal already existed. A removed principal
// under the same id is revived and reported as created; it starts with no keys
// and named in no statement.
func (s *Service) Create(ctx context.Context, externalID, principalID string) (principalstore.Record, bool, error) {
	// bucketpolicy.Wildcard is the policy language's "every principal", so a
	// principal of that name would collide with it: deleting the principal would
	// strip the wildcard from every policy the tenant has.
	if principalID == "" || len(principalID) > maxPrincipalIDLength || principalID == bucketpolicy.Wildcard {
		return principalstore.Record{}, false, ErrInvalidPrincipalID
	}
	tenantID, err := s.tenant(ctx, externalID)
	if err != nil {
		return principalstore.Record{}, false, err
	}

	created := true
	if err := s.principals.Add(ctx, tenantID, principalID); errors.Is(err, store.ErrRecordExists) {
		created = false
	} else if err != nil {
		return principalstore.Record{}, false, fmt.Errorf("recording principal: %w", err)
	}

	rec, err := s.principals.Get(ctx, tenantID, principalID)
	if err != nil {
		return principalstore.Record{}, false, fmt.Errorf("loading principal: %w", err)
	}
	if created {
		s.logger.Info("created principal", zap.Stringer("tenant", tenantID), zap.String("principal", principalID))
	}
	return rec, created, nil
}

// List returns every principal of the tenant, ordered by principalId.
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
func (s *Service) Get(ctx context.Context, externalID, principalID string) (principalstore.Record, error) {
	tenantID, err := s.tenant(ctx, externalID)
	if err != nil {
		return principalstore.Record{}, err
	}
	return s.principal(ctx, tenantID, principalID)
}

// Delete removes the principal, its access to every bucket, and its keys. The
// store holds the principal row locked while [Service.remove] runs, so an
// authorize request for the principal waits for the outcome. It is idempotent:
// a principal that is already gone is a no-op.
func (s *Service) Delete(ctx context.Context, externalID, principalID string) error {
	tenantID, err := s.tenant(ctx, externalID)
	if err != nil {
		return err
	}
	if err := s.principals.Delete(ctx, tenantID, principalID, func(ctx context.Context) error {
		return s.remove(ctx, tenantID, principalID)
	}); err != nil {
		// A lock the removal waited on, or a policy edited between the listing
		// and the rewrite, means another writer got there first. Nothing was
		// committed, so the caller repeats the call. The removal's batch
		// deadline ([grant.BatchTimeout]) is below the stores' lock timeout,
		// so a wait that hits it surfaces as the context error rather than
		// [store.ErrLockTimeout]; the caller's own deadline running out is
		// not that case, so it is mapped only while the caller's context lives.
		if store.Contended(ctx, err) || errors.Is(err, store.ErrPreconditionFailed) {
			s.logger.Info("principal removal lost a race with a concurrent write",
				zap.Stringer("tenant", tenantID), zap.String("principal", principalID), zap.Error(err))
			return ErrConcurrentChange
		}
		return fmt.Errorf("deleting principal %q: %w", principalID, err)
	}
	s.logger.Info("deleted principal", zap.Stringer("tenant", tenantID), zap.String("principal", principalID))
	return nil
}

// remove runs while the principal row is locked, in the RFC's order: revoke
// the delegations of the principal's keys, strip the principal from every policy
// naming it, delete its keys. Each step is idempotent, so a failure is retried
// by repeating the call. The revocations cover everything the removal changes,
// so the policy and key writes it makes publish none of their own. It runs
// under the principal row's lock, so the whole of it is bounded at
// [grant.BatchTimeout], below the wait a share-locked reader gives the row.
func (s *Service) remove(ctx context.Context, tenantID did.DID, principalID string) error {
	ctx, cancel := context.WithTimeout(ctx, grant.BatchTimeout)
	defer cancel()
	if err := s.grants.Revoke(ctx, tenantID, principalID); err != nil {
		return err
	}
	if err := s.stripFromPolicies(ctx, tenantID, principalID); err != nil {
		return err
	}
	return s.deleteKeys(ctx, tenantID, principalID)
}

// stripFromPolicies removes the principal from every statement naming it,
// deleting statements left with no principal and policies left with no
// statement. Each write carries the ETag the listing read, so a policy edited
// concurrently fails the removal rather than reverting it. Policies that
// reach the principal only through the wildcard are left alone: the wildcard
// names the tenant's principals, and this one is about to stop being one.
func (s *Service) stripFromPolicies(ctx context.Context, tenantID did.DID, principalID string) error {
	recs, err := s.policies.ListByPrincipal(ctx, tenantID, principalID)
	if err != nil {
		return fmt.Errorf("listing the principal's policies: %w", err)
	}
	for _, rec := range recs {
		doc, changed := bucketpolicy.WithoutPrincipal(rec.Policy, principalID)
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
func (s *Service) deleteKeys(ctx context.Context, tenantID did.DID, principalID string) error {
	recs, err := s.accessKeys.ListByTenant(ctx, tenantID, accesskeystore.WithPrincipal(principalID))
	if err != nil {
		return fmt.Errorf("listing the principal's access keys: %w", err)
	}
	for _, rec := range recs {
		// The key's delegations are already revoked and gone, so the deletion
		// publishes nothing of its own.
		if err := s.accessKeys.Delete(ctx, rec.ID); err != nil {
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
func (s *Service) ListAccessKeys(ctx context.Context, externalID, principalID string) ([]accesskeystore.Record, error) {
	tenantID, err := s.tenant(ctx, externalID)
	if err != nil {
		return nil, err
	}
	if _, err := s.principal(ctx, tenantID, principalID); err != nil {
		return nil, err
	}
	recs, err := s.accessKeys.ListByTenant(ctx, tenantID, accesskeystore.WithPrincipal(principalID))
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

// principal resolves principalID to a principal of the tenant, or
// [ErrPrincipalNotFound].
func (s *Service) principal(ctx context.Context, tenantID did.DID, principalID string) (principalstore.Record, error) {
	rec, err := s.principals.Get(ctx, tenantID, principalID)
	if errors.Is(err, store.ErrRecordNotFound) {
		return principalstore.Record{}, ErrPrincipalNotFound
	} else if err != nil {
		return principalstore.Record{}, fmt.Errorf("looking up principal: %w", err)
	}
	return rec, nil
}
