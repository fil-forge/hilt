// Package accesskey provides the S3 access-key business logic for the REST API:
// creation, listing, retrieval and deletion. A key created with a principal is
// bound to it: it holds no permissions or buckets of its own, and its
// delegations are derived from the tenant's bucket policies for that
// principal.
//
// Creation and deletion change what the tenant's keys may do, so each runs as
// a task on the tenant's queue ([tenantqueue]), behind any other change to
// the tenant, and the service waits for it. The service keeps what a task
// cannot hold: it generates the key pair, writes the secret to the vault and
// hands the secret to the caller, and none of it enters the task.
//
// It returns the known errors in errors.go so handlers can map them to HTTP
// responses; unexpected failures are returned wrapped for the handler to log.
package accesskey

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"slices"
	"time"

	principalsvc "github.com/fil-forge/hilt/pkg/api/service/principal"
	"github.com/fil-forge/hilt/pkg/s3perm"
	"github.com/fil-forge/hilt/pkg/store"
	accesskeystore "github.com/fil-forge/hilt/pkg/store/accesskey"
	"github.com/fil-forge/hilt/pkg/store/bucket"
	"github.com/fil-forge/hilt/pkg/store/principal"
	"github.com/fil-forge/hilt/pkg/store/tenant"
	"github.com/fil-forge/hilt/pkg/tasks/tenantqueue"
	"github.com/fil-forge/hilt/pkg/vault"
	"github.com/fil-forge/libforge/taskrunner"
	"github.com/fil-forge/ucantone/did"
	"github.com/fil-forge/ucantone/multikey/ed25519"
	"github.com/multiformats/go-multibase"
	"go.uber.org/zap"
)

// CreateTimeout is the longest a key creation waits for its turn on the
// tenant's queue. A creation that has not started by then is abandoned with
// nothing written, and the caller repeats the call.
const CreateTimeout = 30 * time.Second

// Service implements S3 access-key operations shared by the REST handlers.
type Service struct {
	logger     *zap.Logger
	tenants    tenant.Store
	accessKeys accesskeystore.Store
	principals principal.Store
	buckets    bucket.Store
	secrets    vault.Vault
	runner     *taskrunner.Runner
}

// New constructs the access-key service. runner runs the key creations and
// deletions, and must have queue-tenant's handlers registered
// ([tenantqueue.New]) and be started before Create or Delete is called.
func New(
	logger *zap.Logger,
	tenants tenant.Store,
	accessKeys accesskeystore.Store,
	principals principal.Store,
	buckets bucket.Store,
	secrets vault.Vault,
	runner *taskrunner.Runner,
) *Service {
	return &Service{
		logger:     logger,
		tenants:    tenants,
		accessKeys: accessKeys,
		principals: principals,
		buckets:    buckets,
		secrets:    secrets,
		runner:     runner,
	}
}

// Create creates an S3 access key for the tenant. With no principal it is a
// service key: the tenant→access-key delegations for the requested permissions
// are issued (scoped to the named buckets, or tenant-wide when none are given)
// and the name must be unique within the tenant. With a principal the key is
// bound to it: permissions and buckets must be empty, its delegations are those
// the tenant's bucket policies grant the principal, and the name must be unique
// within the principal.
// It returns the stored record and the secret access key (the one time it is
// exposed).
//
// The key's row and delegations are written by a queue-tenant.create-key
// task, in one commit ([tenantqueue]), which Create waits for. The task is
// what decides: it refuses a disabled tenant, a name already taken, an
// unknown principal and an unknown bucket, and the checks made here before it
// only spare the work of a request that cannot succeed. Create writes the
// secret to the vault before it submits the task, since the task's arguments
// are stored and must not hold it, and removes it again when the task fails.
//
// The task runs even if ctx ends while Create waits, so a caller that goes
// away never leaves a key created without its secret or a secret without its
// key. A creation still waiting for its turn after [CreateTimeout], or at
// ctx's deadline when that is sooner, is abandoned with nothing written and
// reported as [ErrConcurrentChange].
func (s *Service) Create(ctx context.Context, externalID, name string, permissions, bucketNames []string, principalID *string, expiresAt *time.Time) (accesskeystore.Record, string, error) {
	if name == "" || len(name) > tenantqueue.MaxKeyNameLength {
		return accesskeystore.Record{}, "", ErrInvalidName
	}
	if principalID != nil {
		if !principalsvc.ValidID(*principalID) {
			return accesskeystore.Record{}, "", principalsvc.ErrInvalidPrincipalID
		}
		if len(permissions) > 0 || len(bucketNames) > 0 {
			return accesskeystore.Record{}, "", ErrPrincipalScoped
		}
	} else {
		if len(permissions) == 0 {
			return accesskeystore.Record{}, "", ErrNoPermissions
		}
		for _, p := range permissions {
			if !s3perm.Valid(p) {
				return accesskeystore.Record{}, "", fmt.Errorf("%w: %s", ErrInvalidPermission, p)
			}
		}
	}

	tenantRec, err := s.tenants.GetByExternalID(ctx, externalID)
	if errors.Is(err, store.ErrRecordNotFound) {
		return accesskeystore.Record{}, "", ErrTenantNotFound
	} else if err != nil {
		return accesskeystore.Record{}, "", fmt.Errorf("looking up tenant: %w", err)
	}
	log := s.logger.With(zap.Stringer("tenant", tenantRec.ID))
	if tenantRec.Status == tenant.Disabled {
		return accesskeystore.Record{}, "", ErrTenantDisabled
	}

	if principalID != nil {
		_, err := s.principals.Get(ctx, tenantRec.ID, *principalID)
		if errors.Is(err, store.ErrRecordNotFound) {
			return accesskeystore.Record{}, "", ErrUnknownPrincipal
		} else if err != nil {
			return accesskeystore.Record{}, "", fmt.Errorf("looking up principal: %w", err)
		}
		log = log.With(zap.String("principal", *principalID))
	}

	// Resolve the named buckets to DIDs in a single tenant-scoped list query. The
	// query is scoped to the tenant, so a name owned by another tenant (or one that
	// doesn't exist) simply won't come back. An empty list means tenant-wide
	// (powerline) access.
	var bucketIDs []did.DID
	bucketNameOf := map[did.DID]string{}
	if len(bucketNames) > 0 {
		bucketIDs = make([]did.DID, 0, len(bucketNames))
		recs, err := store.Collect(ctx, func(ctx context.Context, opts store.PaginationConfig) (store.Page[bucket.Record], error) {
			listOpts := []bucket.ListOption{bucket.WithNames(bucketNames...)}
			if opts.Cursor != nil {
				listOpts = append(listOpts, bucket.WithCursor(*opts.Cursor))
			}
			return s.buckets.ListByTenant(ctx, tenantRec.ID, listOpts...)
		})
		if err != nil {
			return accesskeystore.Record{}, "", fmt.Errorf("resolving buckets: %w", err)
		}
		byName := make(map[string]did.DID, len(recs))
		for _, b := range recs {
			byName[b.Name] = b.ID
			bucketNameOf[b.ID] = b.Name
		}
		for _, n := range bucketNames {
			id, ok := byName[n]
			if !ok {
				return accesskeystore.Record{}, "", fmt.Errorf("%w: %s", ErrUnknownBucket, n)
			}
			bucketIDs = append(bucketIDs, id)
		}
	}

	// Generate the ed25519 access key. accessKeyId is the bare did:key identifier;
	// secretAccessKey is the multibase base64url private key.
	signer, err := ed25519.Generate()
	if err != nil {
		return accesskeystore.Record{}, "", fmt.Errorf("generating access key: %w", err)
	}
	accessKeyID := signer.KeyDID()
	secretAccessKey, err := multibase.Encode(multibase.Base64url, signer.Bytes())
	if err != nil {
		return accesskeystore.Record{}, "", fmt.Errorf("encoding secret access key: %w", err)
	}
	log = log.With(zap.Stringer("access_key", accessKeyID))

	// The times are the ones the key's row will hold, to the microsecond, so
	// the record returned here is the one a later read returns.
	createdAt := toMicros(time.Now())
	if expiresAt != nil {
		e := toMicros(*expiresAt)
		expiresAt = &e
	}
	var in accesskeystore.Input
	if principalID != nil {
		in, err = accesskeystore.NewPrincipalKey(accessKeyID, tenantRec.ID, name, *principalID, expiresAt)
	} else {
		in, err = accesskeystore.NewServiceKey(accessKeyID, tenantRec.ID, name, bucketIDs, permissions, expiresAt)
	}
	if err != nil {
		return accesskeystore.Record{}, "", fmt.Errorf("building access key record: %w", err)
	}
	in.CreatedAt = createdAt
	spec, err := tenantqueue.CreateKeySpec(in)
	if err != nil {
		return accesskeystore.Record{}, "", fmt.Errorf("building the access key's task: %w", err)
	}
	expires := time.Now().Add(CreateTimeout)
	if deadline, ok := ctx.Deadline(); ok && deadline.Before(expires) {
		expires = deadline
	}
	spec.Expires = &expires

	vaultPath := vault.AccessKeyPath(tenantRec.ID, accessKeyID)
	if err := s.secrets.Write(ctx, vaultPath, signer.Bytes()); err != nil {
		return accesskeystore.Record{}, "", fmt.Errorf("storing access key: %w", err)
	}

	// The task and the vault cleanup run on a context detached from the
	// request (values retained, cancellation and deadline dropped), so a
	// client disconnect, which cancels ctx, cannot return before the task has
	// an outcome. The task's expiry bounds the wait instead.
	detached := context.WithoutCancel(ctx)
	if _, err := s.runner.Run(detached, spec); err != nil {
		if outcomeUnknown(err) {
			// The runner failed without reporting what became of the task,
			// which may still run before it expires. The secret stays, so a
			// key that does get created is usable and can be deleted.
			log.Warn("access key creation ended without an outcome; its vault entry is kept", zap.Error(err))
		} else if err := s.secrets.Delete(detached, vaultPath); err != nil {
			log.Warn("removing the vault entry of an access key that was not created", zap.Error(err))
		}
		return accesskeystore.Record{}, "", createError(err, bucketNameOf)
	}

	rec := accesskeystore.Record{
		ID:          in.ID,
		Tenant:      in.Tenant,
		Name:        in.Name,
		Permissions: in.Permissions,
		Principal:   in.Principal,
		CreatedAt:   createdAt,
		ExpiresAt:   in.ExpiresAt,
	}
	if len(in.Buckets) > 0 {
		rec.Buckets = in.Buckets
	}
	log.Info("created access key")
	return rec, secretAccessKey, nil
}

// toMicros returns t to the microsecond, the precision a key's row keeps.
func toMicros(t time.Time) time.Time { return time.UnixMicro(t.UnixMicro()) }

// outcomeUnknown reports whether a key creation that returned err may still
// create the key. It cannot when the task itself failed, which its handler
// marks as final, when it expired before it ran, and when the runner refused
// it for not running. Any other error is the runner's own, from which the
// task may be left queued until it expires.
func outcomeUnknown(err error) bool {
	return !taskrunner.IsPermanent(err) && !errors.Is(err, taskrunner.ErrExpired) && !errors.Is(err, taskrunner.ErrNotStarted)
}

// createError maps the outcome of a failed queue-tenant.create-key task to
// the service's known errors. bucketNameOf names the buckets the request
// resolved, for a bucket deleted since.
func createError(err error, bucketNameOf map[did.DID]string) error {
	var unknownBucket *tenantqueue.UnknownBucketError
	switch {
	case errors.Is(err, tenantqueue.ErrTenantNotFound):
		return ErrTenantNotFound
	case errors.Is(err, tenantqueue.ErrTenantDisabled):
		return ErrTenantDisabled
	case errors.Is(err, tenantqueue.ErrKeyNameTaken):
		return ErrNameConflict
	case errors.Is(err, tenantqueue.ErrUnknownPrincipal):
		return ErrUnknownPrincipal
	case errors.As(err, &unknownBucket):
		if name, ok := bucketNameOf[unknownBucket.Bucket]; ok {
			return fmt.Errorf("%w: %s", ErrUnknownBucket, name)
		}
		return fmt.Errorf("%w: %s", ErrUnknownBucket, unknownBucket.Bucket)
	case errors.Is(err, tenantqueue.ErrInvalidKeyName):
		return ErrInvalidName
	case errors.Is(err, tenantqueue.ErrNoPermissions):
		return ErrNoPermissions
	case errors.Is(err, tenantqueue.ErrInvalidPermission):
		return ErrInvalidPermission
	case errors.Is(err, tenantqueue.ErrPrincipalScoped):
		return ErrPrincipalScoped
	case errors.Is(err, taskrunner.ErrExpired):
		// Other changes to the tenant held its queue for the whole wait.
		return ErrConcurrentChange
	}
	return fmt.Errorf("creating access key: %w", err)
}

// List returns the tenant's access keys and a DID→name map for the buckets they
// reference (for rendering).
func (s *Service) List(ctx context.Context, externalID string, opts ...accesskeystore.ListOption) ([]accesskeystore.Record, map[did.DID]string, error) {
	tenantRec, err := s.tenants.GetByExternalID(ctx, externalID)
	if errors.Is(err, store.ErrRecordNotFound) {
		return nil, nil, ErrTenantNotFound
	} else if err != nil {
		return nil, nil, fmt.Errorf("looking up tenant: %w", err)
	}

	recs, err := s.accessKeys.ListByTenant(ctx, tenantRec.ID, opts...)
	if err != nil {
		return nil, nil, fmt.Errorf("listing access keys: %w", err)
	}

	// Resolve names only for the buckets actually referenced across all keys.
	ids := map[did.DID]struct{}{}
	for _, rec := range recs {
		for _, b := range rec.Buckets {
			ids[b] = struct{}{}
		}
	}
	names, err := s.bucketNamesByID(ctx, tenantRec.ID, slices.Collect(maps.Keys(ids)))
	if err != nil {
		return nil, nil, fmt.Errorf("resolving bucket names: %w", err)
	}
	return recs, names, nil
}

// Get returns a single access key belonging to the tenant, and a DID→name map for
// its buckets.
func (s *Service) Get(ctx context.Context, externalID, accessKeyID string) (accesskeystore.Record, map[did.DID]string, error) {
	tenantRec, err := s.tenants.GetByExternalID(ctx, externalID)
	if errors.Is(err, store.ErrRecordNotFound) {
		return accesskeystore.Record{}, nil, ErrTenantNotFound
	} else if err != nil {
		return accesskeystore.Record{}, nil, fmt.Errorf("looking up tenant: %w", err)
	}

	id, err := did.Parse(did.KeyPrefix + accessKeyID)
	if err != nil {
		return accesskeystore.Record{}, nil, ErrAccessKeyNotFound
	}
	rec, err := s.accessKeys.Get(ctx, id)
	if errors.Is(err, store.ErrRecordNotFound) || (err == nil && rec.Tenant != tenantRec.ID) {
		return accesskeystore.Record{}, nil, ErrAccessKeyNotFound
	} else if err != nil {
		return accesskeystore.Record{}, nil, fmt.Errorf("looking up access key: %w", err)
	}

	names, err := s.bucketNamesByID(ctx, tenantRec.ID, rec.Buckets)
	if err != nil {
		return accesskeystore.Record{}, nil, fmt.Errorf("resolving bucket names: %w", err)
	}
	return rec, names, nil
}

// Delete removes an access key belonging to the tenant, of either kind. The
// change is a queue-tenant.delete-key task ([tenantqueue]), which Delete
// waits for: in one commit the delegations the tenant issued to the key
// leave the delegation store and are recorded as revocations owed, and the
// key's record is deleted. From that commit no request is authorized with
// the key. The revocations are published after it, by the task the commit
// queues, and retried until the revocation service takes them, so Delete
// returns before the gateway has been told to drop what it cached for the
// key, and succeeds while the revocation service is down.
//
// If ctx ends first the task stays queued and a worker finishes it; the
// key's vault entry is then left behind, unreachable without the record. A
// task still waiting for its turn at ctx's deadline is abandoned with
// nothing written and reported as [ErrConcurrentChange].
func (s *Service) Delete(ctx context.Context, externalID, accessKeyID string) error {
	tenantRec, err := s.tenants.GetByExternalID(ctx, externalID)
	if errors.Is(err, store.ErrRecordNotFound) {
		return ErrTenantNotFound
	} else if err != nil {
		return fmt.Errorf("looking up tenant: %w", err)
	}

	id, err := did.Parse(did.KeyPrefix + accessKeyID)
	if err != nil {
		return ErrAccessKeyNotFound
	}
	rec, err := s.accessKeys.Get(ctx, id)
	if errors.Is(err, store.ErrRecordNotFound) || (err == nil && rec.Tenant != tenantRec.ID) {
		return ErrAccessKeyNotFound
	} else if err != nil {
		return fmt.Errorf("looking up access key: %w", err)
	}

	if _, err := s.runner.Run(ctx, tenantqueue.DeleteKeySpec(tenantRec.ID, id)); err != nil {
		if errors.Is(err, taskrunner.ErrExpired) {
			return ErrConcurrentChange
		}
		return fmt.Errorf("deleting access key: %w", err)
	}
	// The row went first, so a key whose vault entry outlives it is unreachable
	// rather than present but unusable.
	if err := s.secrets.Delete(ctx, vault.AccessKeyPath(tenantRec.ID, id)); err != nil {
		s.logger.Warn("removing access key from vault", zap.Error(err))
	}
	s.logger.Info("deleted access key",
		zap.Stringer("tenant", tenantRec.ID),
		zap.Stringer("access_key", id),
	)
	return nil
}

// bucketNamesByID returns a DID→name map for the given bucket IDs owned by the
// tenant. IDs that don't resolve (e.g. a deleted bucket) are simply absent.
func (s *Service) bucketNamesByID(ctx context.Context, tenantID did.DID, ids []did.DID) (map[did.DID]string, error) {
	if len(ids) == 0 {
		return map[did.DID]string{}, nil
	}
	recs, err := store.Collect(ctx, func(ctx context.Context, opts store.PaginationConfig) (store.Page[bucket.Record], error) {
		listOpts := []bucket.ListOption{bucket.WithIDs(ids...)}
		if opts.Cursor != nil {
			listOpts = append(listOpts, bucket.WithCursor(*opts.Cursor))
		}
		return s.buckets.ListByTenant(ctx, tenantID, listOpts...)
	})
	if err != nil {
		return nil, err
	}
	names := make(map[did.DID]string, len(recs))
	for _, b := range recs {
		names[b.ID] = b.Name
	}
	return names, nil
}
