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
	delegationstore "github.com/fil-forge/hilt/pkg/store/delegation"
	principalstore "github.com/fil-forge/hilt/pkg/store/principal"
	tenantstore "github.com/fil-forge/hilt/pkg/store/tenant"
	"github.com/fil-forge/hilt/pkg/vault"
	"github.com/fil-forge/ucantone/did"
	"github.com/fil-forge/ucantone/ucan"
	"go.uber.org/zap"
)

const (
	// maxPrincipalIDLength bounds the opaque principalId the caller supplies.
	maxPrincipalIDLength = 255
)

// Service implements the principal operations shared by the REST handlers.
type Service struct {
	logger      *zap.Logger
	tenants     tenantstore.Store
	principals  principalstore.Store
	policies    bucketpolicystore.Store
	accessKeys  accesskeystore.Store
	delegations delegationstore.Store
	secrets     vault.Vault
	revocations grant.RevocationPublisher
	grants      *grant.Rotator
}

// New constructs the principal service.
func New(
	logger *zap.Logger,
	tenants tenantstore.Store,
	principals principalstore.Store,
	policies bucketpolicystore.Store,
	accessKeys accesskeystore.Store,
	delegations delegationstore.Store,
	secrets vault.Vault,
	revocations grant.RevocationPublisher,
	grants *grant.Rotator,
) *Service {
	return &Service{
		logger:      logger,
		tenants:     tenants,
		principals:  principals,
		policies:    policies,
		accessKeys:  accessKeys,
		delegations: delegations,
		secrets:     secrets,
		revocations: revocations,
		grants:      grants,
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

// Delete removes the principal, its access to every bucket, and its keys, in
// two steps. It first revokes the delegations of the principal's keys and
// strips the principal from every policy naming it, without locking the
// principal row: a policy write holds its bucket while its rotation locks the
// principals it changes, so a removal that held the row while it waited for a
// bucket would wait on that write as it waited on the removal. The store then
// holds the row locked while [Service.remove] finishes, so an authorize request
// for the principal waits for the outcome. It is idempotent: a principal that
// is already gone is a no-op.
func (s *Service) Delete(ctx context.Context, externalID, principalID string) error {
	tenantID, err := s.tenant(ctx, externalID)
	if err != nil {
		return err
	}
	err = s.grants.Revoke(ctx, tenantID, principalID)
	if err == nil {
		err = s.stripFromPolicies(ctx, tenantID, principalID)
	}
	if err == nil {
		err = s.principals.Delete(ctx, tenantID, principalID, func(ctx context.Context) error {
			return s.remove(ctx, tenantID, principalID)
		})
	}
	if err != nil {
		// A lock the removal waited on, a policy edited between the listing
		// and the rewrite, or a policy naming the principal again by the time
		// its row is locked, means another writer got there first. Each step is
		// idempotent, so the caller repeats the call. The removal's batch
		// deadline ([grant.BatchTimeout]) is below the stores' lock timeout,
		// so a wait that hits it surfaces as the context error rather than
		// [store.ErrLockTimeout]; the caller's own deadline running out is
		// not that case, so it is mapped only while the caller's context lives.
		if errors.Is(err, store.ErrLockTimeout) || errors.Is(err, store.ErrPreconditionFailed) || errors.Is(err, errNamedAgain) ||
			(errors.Is(err, context.DeadlineExceeded) && ctx.Err() == nil) {
			s.logger.Info("principal removal lost a race with a concurrent write",
				zap.Stringer("tenant", tenantID), zap.String("principal", principalID), zap.Error(err))
			return ErrConcurrentChange
		}
		return fmt.Errorf("deleting principal %q: %w", principalID, err)
	}
	s.logger.Info("deleted principal", zap.Stringer("tenant", tenantID), zap.String("principal", principalID))
	return nil
}

// errNamedAgain is a policy naming the principal once its row is locked: a
// write named it after [Service.stripFromPolicies] ran.
var errNamedAgain = errors.New("a policy names the principal again")

// remove runs while the principal row is locked. A write naming the principal
// now waits for the outcome, so it checks that no policy names the principal,
// then revokes what the principal's keys hold and deletes their rows under the
// keys' delegation locks, in one write: a creation storing a key's grants
// meanwhile either lands first and is revoked here, or waits and finds the row
// gone. Nothing here waits on a bucket. The revocations cover everything the
// removal changes, so the policy and key writes it makes publish none of their
// own. It runs under the principal row's lock, so the whole of it is bounded at
// [grant.BatchTimeout], below the wait a share-locked reader gives the row.
func (s *Service) remove(ctx context.Context, tenantID did.DID, principalID string) error {
	ctx, cancel := context.WithTimeout(ctx, grant.BatchTimeout)
	defer cancel()
	recs, err := s.policies.ListByPrincipal(ctx, tenantID, principalID)
	if err != nil {
		return fmt.Errorf("listing the principal's policies: %w", err)
	}
	for _, rec := range recs {
		if _, named := bucketpolicy.WithoutPrincipal(rec.Policy, principalID); named {
			return fmt.Errorf("bucket %s: %w", rec.Bucket, errNamedAgain)
		}
	}
	keys, err := s.accessKeys.ListByTenant(ctx, tenantID, accesskeystore.WithPrincipal(principalID))
	if err != nil {
		return fmt.Errorf("listing the principal's access keys: %w", err)
	}
	if len(keys) == 0 {
		return nil
	}
	issuer, err := vault.TenantIssuer(ctx, s.secrets, tenantID)
	if err != nil {
		return err
	}
	audiences := make([]did.DID, len(keys))
	for i, key := range keys {
		audiences[i] = key.ID
	}
	log := s.logger.With(zap.Stringer("tenant", tenantID), zap.String("principal", principalID))
	err = s.delegations.Replace(ctx, audiences, func(ctx context.Context, current map[did.DID][]ucan.Delegation) (map[did.DID][]ucan.Delegation, error) {
		var all []ucan.Delegation
		for _, key := range keys {
			all = append(all, current[key.ID]...)
		}
		if err := grant.PublishRevocations(ctx, log, s.revocations, issuer, all); err != nil {
			return nil, err
		}
		for _, key := range keys {
			if err := s.accessKeys.Delete(ctx, key.ID); err != nil {
				return nil, fmt.Errorf("deleting access key %s: %w", key.ID, err)
			}
		}
		return nil, nil
	})
	if err != nil {
		return err
	}
	// The rows went first, so a key whose vault entry outlives it is
	// unreachable rather than unusable-but-present.
	for _, key := range keys {
		if err := s.secrets.Delete(ctx, vault.AccessKeyPath(tenantID, key.ID)); err != nil {
			s.logger.Warn("removing access key from vault",
				zap.Stringer("access_key", key.ID),
				zap.Error(err),
			)
		}
	}
	return nil
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
