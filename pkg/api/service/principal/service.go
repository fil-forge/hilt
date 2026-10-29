// Package principal provides the business logic for a tenant's principals: the
// console users whose access to the tenant's buckets is computed from bucket
// policies. A principal holds no DID, no vault entry and no delegation, and
// appears in no UCAN; each key bound to it holds the delegations the policies
// grant the principal.
//
// Removal is the one operation that spans three tables. It first revokes and
// removes the delegations of the principal's keys, strips the principal from
// every policy naming it, then tombstones the principal: the tombstone write's
// callback revokes anything the keys gained meanwhile and deletes the keys.
// Each write publishes its revocations before it writes anything, so a failure
// part way leaves the principal with narrower access and a retryable delete.
//
// Known errors are in errors.go so handlers can map them to HTTP responses;
// unexpected failures are returned wrapped for the handler to log.
package principal

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"unicode/utf8"

	s3bkt "github.com/fil-forge/libforge/commands/s3/bucket"

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
	// maxPrincipalIDLength bounds the opaque principalId the caller supplies,
	// in bytes.
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
		grants:      grants,
	}
}

// ValidID reports whether id can be a principalId. s3bkt.Wildcard is the
// policy language's "every principal", so a principal of that name would
// collide with it: deleting the principal would strip the wildcard from every
// policy the tenant has. Postgres refuses invalid UTF-8 and NUL in text. The id
// travels as one path segment of the Tenant API, so it must not hold a
// character that delimits or escapes a segment, nor be a dot segment a client
// could resolve away.
func ValidID(id string) bool {
	return id != "" && len(id) <= maxPrincipalIDLength && id != s3bkt.Wildcard &&
		utf8.ValidString(id) && !strings.ContainsRune(id, 0) &&
		!strings.ContainsAny(id, "/;,?%") && id != "." && id != ".."
}

// Create records the principal and nothing else. It is idempotent: the second
// report is false when the principal already existed. A removed principal
// under the same id is revived and reported as created; it starts with no keys
// and named in no statement.
func (s *Service) Create(ctx context.Context, externalID, principalID string) (principalstore.Record, bool, error) {
	if !ValidID(principalID) {
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

	// A removal committing between the record and the read leaves nothing to
	// read, which is reported as the failure it is.
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

// Delete removes the principal, its access to every bucket, and its keys. It
// revokes and removes the delegations of the principal's keys, strips the
// principal from every policy naming it, then tombstones the principal while
// [Service.remove] revokes anything its keys gained meanwhile and deletes
// them. It takes no lock: a policy write
// naming the principal while this runs can leave a policy naming a removed
// principal, which evaluation skips. It is idempotent: a principal that is
// already gone is a no-op.
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
		err = s.principals.Tombstone(ctx, tenantID, principalID, func(ctx context.Context) error {
			return s.remove(ctx, tenantID, principalID)
		})
	}
	if err != nil {
		return fmt.Errorf("deleting principal %q: %w", principalID, err)
	}
	s.logger.Info("deleted principal", zap.Stringer("tenant", tenantID), zap.String("principal", principalID))
	return nil
}

// remove runs inside the principal's tombstone write. It revokes what the
// principal's keys hold, then deletes those delegations and the keys' rows in
// one write. The revocations cover everything the removal changes, so the
// policy and key writes it makes publish none of their own. It is bounded at
// [grant.BatchTimeout].
func (s *Service) remove(ctx context.Context, tenantID did.DID, principalID string) error {
	ctx, cancel := context.WithTimeout(ctx, grant.BatchTimeout)
	defer cancel()
	keys, err := s.accessKeys.ListByTenant(ctx, tenantID, accesskeystore.WithPrincipal(principalID))
	if err != nil {
		return fmt.Errorf("listing the principal's access keys: %w", err)
	}
	if len(keys) == 0 {
		return nil
	}
	audiences := make([]did.DID, len(keys))
	for i, key := range keys {
		audiences[i] = key.ID
	}
	err = s.delegations.Replace(ctx, audiences, func(ctx context.Context, current map[did.DID][]ucan.Delegation) (map[did.DID][]ucan.Delegation, error) {
		var held []ucan.Delegation
		for _, key := range keys {
			held = append(held, current[key.ID]...)
		}
		if err := s.grants.Publish(ctx, tenantID, held); err != nil {
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
// statement. Each rewrite is unconditional, so a policy edited between the
// listing and the rewrite loses that edit. Policies that reach the principal
// only through the wildcard are left alone: the wildcard names the tenant's
// principals, and this one is about to stop being one.
func (s *Service) stripFromPolicies(ctx context.Context, tenantID did.DID, principalID string) error {
	recs, err := s.policies.ListByPrincipal(ctx, tenantID, principalID)
	if err != nil {
		return fmt.Errorf("listing the principal's policies: %w", err)
	}
	for _, rec := range recs {
		doc, changed := bucketpolicy.RemovePrincipal(rec.Policy, principalID)
		if !changed {
			continue
		}
		if len(doc.Statements) == 0 {
			if err := s.policies.Delete(ctx, rec.Bucket, nil); err != nil && !errors.Is(err, store.ErrRecordNotFound) {
				return fmt.Errorf("deleting the policy of bucket %s: %w", rec.Bucket, err)
			}
			continue
		}
		if err := s.policies.Put(ctx, bucketpolicystore.Input{
			Bucket: rec.Bucket,
			Tenant: tenantID,
			Policy: doc,
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
