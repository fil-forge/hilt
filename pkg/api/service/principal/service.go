// Package principal provides the business logic for a tenant's principals: the
// console users whose access to the tenant's buckets is computed from bucket
// policies. A principal holds no DID, no vault entry and no delegation, and
// appears in no UCAN; each key bound to it holds the delegations the policies
// grant the principal.
//
// Removal changes what the tenant's keys may do, so it runs as a task on the
// tenant's queue ([tenantqueue]), behind any other change to the tenant, and
// the service waits for it.
//
// Known errors are in errors.go so handlers can map them to HTTP responses;
// unexpected failures are returned wrapped for the handler to log.
package principal

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"

	s3bkt "github.com/fil-forge/libforge/commands/s3/bucket"

	"github.com/fil-forge/hilt/pkg/store"
	principalstore "github.com/fil-forge/hilt/pkg/store/principal"
	tenantstore "github.com/fil-forge/hilt/pkg/store/tenant"
	"github.com/fil-forge/hilt/pkg/tasks/tenantqueue"
	"github.com/fil-forge/hilt/pkg/vault"
	"github.com/fil-forge/libforge/taskrunner"
	"github.com/fil-forge/ucantone/did"
	"go.uber.org/zap"
)

const (
	// maxPrincipalIDLength bounds the opaque principalId the caller supplies,
	// in bytes.
	maxPrincipalIDLength = 255
)

// Service implements the principal operations shared by the REST handlers.
type Service struct {
	logger     *zap.Logger
	tenants    tenantstore.Store
	principals principalstore.Store
	secrets    vault.Vault
	runner     *taskrunner.Runner
}

// New constructs the principal service. runner runs the removals, and must
// have queue-tenant's handlers registered ([tenantqueue.New]) and be started
// before Delete is called.
func New(
	logger *zap.Logger,
	tenants tenantstore.Store,
	principals principalstore.Store,
	secrets vault.Vault,
	runner *taskrunner.Runner,
) *Service {
	return &Service{
		logger:     logger,
		tenants:    tenants,
		principals: principals,
		secrets:    secrets,
		runner:     runner,
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

	rec, err := s.principals.Get(ctx, tenantID, principalID)
	if errors.Is(err, store.ErrRecordNotFound) {
		// A removal committing between the record and the read is what
		// removed it; the caller repeats the call.
		s.logger.Info("principal creation lost a race with a removal",
			zap.Stringer("tenant", tenantID), zap.String("principal", principalID))
		return principalstore.Record{}, false, ErrConcurrentChange
	} else if err != nil {
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

// DeleteTimeout is the longest a principal removal waits for its turn on the
// tenant's queue. A removal that has not started by then is abandoned with
// nothing written, and the caller repeats the call.
const DeleteTimeout = 30 * time.Second

// Delete removes the principal, its keys, and its place in every bucket
// policy naming it. The change is a queue-tenant.remove-principal task
// ([tenantqueue]), which Delete waits for: in one commit the principal leaves
// every statement naming it, the other principals' grants over each
// rewritten policy's bucket change as a policy write changes them, every
// grant of the principal's keys leaves the delegation store and is recorded
// as a revocation owed, the keys are deleted and the principal is
// tombstoned. From that commit no request is authorized with the keys. The
// revocations are published after it, by the task the commit queues, and
// retried until the revocation service takes them, so Delete returns before
// the gateway has been told to drop what it cached for the keys, and
// succeeds while the revocation service is down. The keys' secrets are then
// removed from the vault, best effort. It is idempotent: a principal that is
// already gone is a no-op.
//
// The task and the vault cleanup run on a context detached from the request,
// so a client disconnect cannot leave the keys deleted with their secrets
// behind. A removal still waiting for its turn after [DeleteTimeout], or at
// ctx's deadline if that is sooner, is abandoned with nothing written and
// reported as [ErrConcurrentChange].
func (s *Service) Delete(ctx context.Context, externalID, principalID string) error {
	tenantID, err := s.tenant(ctx, externalID)
	if err != nil {
		return err
	}
	spec := tenantqueue.RemovePrincipalSpec(tenantID, principalID)
	expires := time.Now().Add(DeleteTimeout)
	if deadline, ok := ctx.Deadline(); ok && deadline.Before(expires) {
		expires = deadline
	}
	spec.Expires = &expires
	ctx = context.WithoutCancel(ctx)
	res, err := s.runner.Run(ctx, spec)
	if err != nil {
		if errors.Is(err, taskrunner.ErrExpired) {
			return ErrConcurrentChange
		}
		return fmt.Errorf("deleting principal %q: %w", principalID, err)
	}
	keys, err := tenantqueue.DecodeRemovePrincipalResult(res)
	if err != nil {
		return fmt.Errorf("deleting principal %q: %w", principalID, err)
	}
	// The rows went first, so a key whose vault entry outlives it is
	// unreachable rather than present but unusable.
	for _, key := range keys {
		if err := s.secrets.Delete(ctx, vault.AccessKeyPath(tenantID, key)); err != nil {
			s.logger.Warn("removing access key from vault", zap.Stringer("access_key", key), zap.Error(err))
		}
	}
	s.logger.Info("deleted principal", zap.Stringer("tenant", tenantID), zap.String("principal", principalID), zap.Int("access_keys", len(keys)))
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
