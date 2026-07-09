// Package accesskey provides the S3 access-key business logic for the REST API:
// creation (key-pair generation + tenant→access-key delegation issuance), listing,
// retrieval, and revocation. It returns the known errors in errors.go so handlers
// can map them to HTTP responses; unexpected failures are returned wrapped for the
// handler to log.
package accesskey

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"slices"
	"time"

	"github.com/fil-forge/hilt/pkg/s3perm"
	"github.com/fil-forge/hilt/pkg/store"
	accesskeystore "github.com/fil-forge/hilt/pkg/store/accesskey"
	"github.com/fil-forge/hilt/pkg/store/bucket"
	delegationstore "github.com/fil-forge/hilt/pkg/store/delegation"
	"github.com/fil-forge/hilt/pkg/store/tenant"
	"github.com/fil-forge/hilt/pkg/vault"
	"github.com/fil-forge/ucantone/did"
	"github.com/fil-forge/ucantone/multikey"
	"github.com/fil-forge/ucantone/multikey/ed25519"
	"github.com/fil-forge/ucantone/multikey/secp256k1"
	"github.com/fil-forge/ucantone/ucan"
	"github.com/fil-forge/ucantone/ucan/delegation"
	"github.com/multiformats/go-multibase"
	"go.uber.org/zap"
)

const maxNameLength = 64

// Service implements S3 access-key operations shared by the REST handlers.
type Service struct {
	logger      *zap.Logger
	tenants     tenant.Store
	accessKeys  accesskeystore.Store
	buckets     bucket.Store
	delegations delegationstore.Store
	secrets     vault.Vault
}

// New constructs the access-key service.
func New(
	logger *zap.Logger,
	tenants tenant.Store,
	accessKeys accesskeystore.Store,
	buckets bucket.Store,
	delegations delegationstore.Store,
	secrets vault.Vault,
) *Service {
	return &Service{
		logger:      logger,
		tenants:     tenants,
		accessKeys:  accessKeys,
		buckets:     buckets,
		delegations: delegations,
		secrets:     secrets,
	}
}

// Create creates an S3 access key for the tenant and issues the tenant→access-key
// delegations for the requested permissions (scoped to the named buckets, or
// tenant-wide when none are given). It returns the stored record and the secret
// access key (the one time it is exposed).
func (s *Service) Create(ctx context.Context, externalID, name string, permissions, bucketNames []string, expiresAt *time.Time) (accesskeystore.Record, string, error) {
	if name == "" || len(name) > maxNameLength {
		return accesskeystore.Record{}, "", ErrInvalidName
	}
	if len(permissions) == 0 {
		return accesskeystore.Record{}, "", ErrNoPermissions
	}
	for _, p := range permissions {
		if !s3perm.Valid(p) {
			return accesskeystore.Record{}, "", fmt.Errorf("%w: %s", ErrInvalidPermission, p)
		}
	}

	tenantRec, err := s.tenants.GetByExternalID(ctx, externalID)
	if errors.Is(err, store.ErrRecordNotFound) {
		return accesskeystore.Record{}, "", ErrTenantNotFound
	} else if err != nil {
		return accesskeystore.Record{}, "", fmt.Errorf("looking up tenant: %w", err)
	}
	log := s.logger.With(zap.Stringer("tenant", tenantRec.ID))

	// Load the tenant signer up front: it is required to issue delegations and its
	// absence is unrecoverable, so fail before creating any state.
	tenantKeyBytes, err := s.secrets.Read(ctx, vault.TenantKeyPath(tenantRec.ID))
	if err != nil {
		return accesskeystore.Record{}, "", fmt.Errorf("reading tenant key: %w", err)
	}
	tenantSigner, err := secp256k1.Decode(tenantKeyBytes)
	if err != nil {
		return accesskeystore.Record{}, "", fmt.Errorf("decoding tenant key: %w", err)
	}
	issuer := multikey.NewIssuer(tenantRec.ID, tenantSigner)

	// Resolve the named buckets to DIDs in a single tenant-scoped list query. The
	// query is scoped to the tenant, so a name owned by another tenant (or one that
	// doesn't exist) simply won't come back. An empty list means tenant-wide
	// (powerline) access.
	bucketIDs := make([]did.DID, 0, len(bucketNames))
	if len(bucketNames) > 0 {
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

	vaultPath := vault.AccessKeyPath(tenantRec.ID, accessKeyID)
	if err := s.secrets.Write(ctx, vaultPath, signer.Bytes()); err != nil {
		return accesskeystore.Record{}, "", fmt.Errorf("storing access key: %w", err)
	}

	// Best-effort rollback of the (idempotent) state created below, so a partial
	// failure leaves nothing behind and is retryable. Cleanup runs on a context
	// detached from the request (values retained, cancellation/deadline dropped) so
	// a client disconnect — which cancels ctx — cannot abort the rollback partway
	// and leave orphaned state.
	rollback := func() {
		cleanupCtx := context.WithoutCancel(ctx)
		if err := s.delegations.DeleteByAudience(cleanupCtx, accessKeyID); err != nil {
			log.Warn("rollback: deleting delegations", zap.Error(err))
		}
		if err := s.accessKeys.Delete(cleanupCtx, accessKeyID); err != nil {
			log.Warn("rollback: deleting access key", zap.Error(err))
		}
		if err := s.secrets.Delete(cleanupCtx, vaultPath); err != nil {
			log.Warn("rollback: deleting access key from vault", zap.Error(err))
		}
	}

	if err := s.accessKeys.Add(ctx, accessKeyID, tenantRec.ID, name, bucketIDs, permissions, expiresAt); err != nil {
		rollback()
		// Name uniqueness is enforced by the store's (tenant, name) constraint; a
		// fresh random access-key DID colliding is not a realistic case.
		if errors.Is(err, store.ErrRecordExists) {
			return accesskeystore.Record{}, "", ErrNameConflict
		}
		return accesskeystore.Record{}, "", fmt.Errorf("storing access key record: %w", err)
	}

	// Issue tenant→access-key delegations: one per (command × subject), where
	// subject is each bucket DID or a single powerline (undefined subject).
	var opts []delegation.Option
	if expiresAt != nil {
		opts = append(opts, delegation.WithExpiration(ucan.UnixTimestamp(expiresAt.Unix())))
	}
	subjects := bucketIDs
	if len(subjects) == 0 {
		subjects = []did.DID{did.Undef} // powerline: undefined subject
	}
	var dels []ucan.Delegation
	for _, sub := range subjects {
		for _, cmd := range s3perm.CommandsFor(permissions...) {
			d, err := delegation.Delegate(issuer, accessKeyID, sub, cmd, opts...)
			if err != nil {
				rollback()
				return accesskeystore.Record{}, "", fmt.Errorf("issuing delegation: %w", err)
			}
			dels = append(dels, d)
		}
	}
	if len(dels) > 0 {
		if err := s.delegations.PutBatch(ctx, dels); err != nil {
			rollback()
			return accesskeystore.Record{}, "", fmt.Errorf("storing delegations: %w", err)
		}
	}

	rec, err := s.accessKeys.Get(ctx, accessKeyID)
	if err != nil {
		return accesskeystore.Record{}, "", fmt.Errorf("loading created access key: %w", err)
	}
	log.Info("created access key")
	return rec, secretAccessKey, nil
}

// List returns the tenant's access keys and a DID→name map for the buckets they
// reference (for rendering).
func (s *Service) List(ctx context.Context, externalID string) ([]accesskeystore.Record, map[did.DID]string, error) {
	tenantRec, err := s.tenants.GetByExternalID(ctx, externalID)
	if errors.Is(err, store.ErrRecordNotFound) {
		return nil, nil, ErrTenantNotFound
	} else if err != nil {
		return nil, nil, fmt.Errorf("looking up tenant: %w", err)
	}

	recs, err := s.accessKeys.ListByTenant(ctx, tenantRec.ID)
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

// Delete revokes an access key belonging to the tenant: removing its delegations,
// vault key, and record. Sending UCAN revocations to a revocation service is out
// of scope (no such service exists yet, as with Sprue deprovisioning).
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

	if err := s.delegations.DeleteByAudience(ctx, id); err != nil {
		return fmt.Errorf("deleting access key delegations: %w", err)
	}
	if err := s.secrets.Delete(ctx, vault.AccessKeyPath(tenantRec.ID, id)); err != nil {
		s.logger.Warn("removing access key from vault", zap.Error(err))
	}
	if err := s.accessKeys.Delete(ctx, id); err != nil {
		return fmt.Errorf("deleting access key: %w", err)
	}
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
