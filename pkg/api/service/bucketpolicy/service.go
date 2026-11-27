// Package bucketpolicy provides the business logic for bucket policies: the
// compare-and-set writes of a bucket's policy document, and the two
// principal reads computed from it, the policies naming a principal and its
// effective actions per bucket.
//
// A write or a removal is a task on the tenant's queue ([tenantqueue]), which
// the service submits and waits for. In one commit the task writes the
// document and gives every key of each principal whose effective set the
// change alters the grants it now holds over the bucket; the grants it takes
// away are recorded as revocations owed and published after the commit.
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
	"github.com/fil-forge/hilt/pkg/store"
	bucketstore "github.com/fil-forge/hilt/pkg/store/bucket"
	bucketpolicystore "github.com/fil-forge/hilt/pkg/store/bucketpolicy"
	principalstore "github.com/fil-forge/hilt/pkg/store/principal"
	tenantstore "github.com/fil-forge/hilt/pkg/store/tenant"
	"github.com/fil-forge/hilt/pkg/tasks/tenantqueue"
	"github.com/fil-forge/libforge/taskrunner"
	"github.com/fil-forge/ucantone/did"
	"go.uber.org/zap"
)

// Record is a bucket's policy as the service reports it: the policy, its strong
// ETag, and the name the bucket is addressed by.
type Record struct {
	BucketName string
	ETag       string
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
	runner     *taskrunner.Runner
}

// New constructs the policy service. runner runs the policy writes and
// removals, and must have queue-tenant's handlers registered
// ([tenantqueue.New]) and be started before Write or Remove is called.
func New(
	logger *zap.Logger,
	tenants tenantstore.Store,
	buckets bucketstore.Store,
	principals principalstore.Store,
	policies bucketpolicystore.Store,
	runner *taskrunner.Runner,
) *Service {
	return &Service{
		logger:     logger,
		tenants:    tenants,
		buckets:    buckets,
		principals: principals,
		policies:   policies,
		runner:     runner,
	}
}

// Condition is a write's precondition on the bucket's current policy, as
// If-Match and If-None-Match state it.
type Condition struct {
	// Negate requires that no current policy matches Match (If-None-Match).
	// Only "*" is accepted with it: the bucket must have no policy.
	Negate bool
	// Match is the ETag the current policy must carry, or "*".
	Match string
}

// IfMatch is the condition that the bucket's current policy carries etag.
func IfMatch(etag string) Condition { return Condition{Match: etag} }

// IfNoneMatch is the condition that no current policy matches v; with "*",
// that the bucket has no policy.
func IfNoneMatch(v string) Condition { return Condition{Negate: true, Match: v} }

// WriteOption configures a [Service.Write]. Without one the write is
// unconditional, as a PutBucketPolicy without If-Match or If-None-Match is.
type WriteOption func(*tenantqueue.PolicyCondition) error

// WithCondition makes the write check c. A second condition on the same
// write, or a negated one other than "*", is [ErrInvalidPrecondition].
func WithCondition(c Condition) WriteOption {
	return func(in *tenantqueue.PolicyCondition) error {
		if in.Conditional {
			return fmt.Errorf("a write takes one condition: %w", ErrInvalidPrecondition)
		}
		if c.Negate && c.Match != "*" {
			return fmt.Errorf("If-None-Match must be *: %w", ErrInvalidPrecondition)
		}
		in.Conditional = true
		if !c.Negate {
			in.IfMatch = &c.Match
		}
		return nil
	}
}

// Write creates or replaces the bucket's policy, for a caller that has
// resolved the tenant and the bucket. The document must be valid for the
// bucket (every resource must name bucketName) and name only principals the
// tenant has, and the condition [WithCondition] sets must hold. bucketName
// also names the bucket in errors. It returns the new ETag and whether the
// bucket had no policy before.
//
// The write is a queue-tenant.put-policy task ([tenantqueue]), which Write
// waits for, behind any other change to the tenant queued before it. The
// task is what decides: the validation made here before it only spares the
// work of a request that cannot succeed. From the task's commit every
// affected key holds the grants of the new document over the bucket. The
// grants it lost are revoked after the commit, by the task the commit
// queues, and retried until the revocation service takes them, so Write
// returns before the gateway has been told to drop what it cached, and
// succeeds while the revocation service is down.
//
// If ctx ends first the task stays queued and a worker finishes it. A task
// still waiting for its turn at ctx's deadline is abandoned with nothing
// written and reported as [ErrConcurrentChange].
func (s *Service) Write(ctx context.Context, tenantID, bucketID did.DID, bucketName string, doc s3bkt.PolicyDocument, opts ...WriteOption) (string, bool, error) {
	tenantPrincipals, err := s.principals.ListIDsByTenant(ctx, tenantID)
	if err != nil {
		return "", false, err
	}
	if err := bucketpolicy.Validate(doc, bucketName, func(p string) bool { return slices.Contains(tenantPrincipals, p) }); err != nil {
		return "", false, err
	}
	var cond tenantqueue.PolicyCondition
	for _, opt := range opts {
		if err := opt(&cond); err != nil {
			return "", false, err
		}
	}
	spec, err := tenantqueue.PutPolicySpec(tenantID, bucketID, bucketName, doc, cond)
	if err != nil {
		return "", false, fmt.Errorf("building the task of the policy of bucket %q: %w", bucketName, err)
	}
	res, err := s.runner.Run(ctx, spec)
	if err != nil {
		return "", false, s.taskError(bucketName, err)
	}
	etag, created, err := tenantqueue.DecodePutPolicyResult(res)
	if err != nil {
		return "", false, fmt.Errorf("writing the policy of bucket %q: %w", bucketName, err)
	}
	return etag, created, nil
}

// Remove removes the bucket's policy, for a caller that has resolved the
// tenant and the bucket. A non-nil ifMatch must equal the current ETag; nil
// removes whatever is stored (a DeleteBucketPolicy without If-Match). Every
// principal the policy reached loses its access, so each one's keys lose
// their grants over the bucket. bucketName names the bucket in errors and
// logs.
//
// The removal is a queue-tenant.delete-policy task, which Remove waits for
// as [Service.Write] waits for its own. A bucket the tenant no longer has
// (deleted since the lookup) has no policy to remove, and is reported as
// [ErrPolicyNotFound].
func (s *Service) Remove(ctx context.Context, tenantID, bucketID did.DID, bucketName string, ifMatch *string) error {
	spec, err := tenantqueue.DeletePolicySpec(tenantID, bucketID, bucketName, ifMatch)
	if err != nil {
		return fmt.Errorf("building the task removing the policy of bucket %q: %w", bucketName, err)
	}
	if _, err := s.runner.Run(ctx, spec); err != nil {
		if errors.Is(err, tenantqueue.ErrUnknownBucket) {
			return ErrPolicyNotFound
		}
		return s.taskError(bucketName, err)
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

// taskError maps the outcome of a failed policy task to the service's known
// errors; anything else is wrapped for the handler to log. A bucket the
// tenant no longer has (deleted since the lookup) is a missing bucket. A
// document the task refuses, one naming a principal removed since the
// validation included, is returned as the task reported it, an error
// wrapping [s3bkt.ErrInvalidPolicy]. A failed precondition is logged with the
// task's error, which names the stored ETag and the one sent, since the
// mapped error the caller sees carries neither. A task that expired waited
// behind the tenant's other changes for as long as its caller allowed.
func (s *Service) taskError(bucketName string, err error) error {
	switch {
	case errors.Is(err, store.ErrPreconditionFailed):
		s.logger.Warn("bucket policy precondition failed", zap.String("bucket", bucketName), zap.Error(err))
		return ErrPreconditionFailed
	case errors.Is(err, tenantqueue.ErrPolicyNotFound):
		return ErrPolicyNotFound
	case errors.Is(err, tenantqueue.ErrUnknownBucket):
		return ErrBucketNotFound
	case errors.Is(err, s3bkt.ErrInvalidPolicy):
		// The task marked the error final; the caller gets the error it
		// marked.
		if inner := errors.Unwrap(err); inner != nil && taskrunner.IsPermanent(err) {
			return inner
		}
		return err
	case errors.Is(err, taskrunner.ErrExpired):
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
