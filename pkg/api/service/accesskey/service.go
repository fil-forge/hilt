// Package accesskey provides the S3 access-key business logic for the REST API:
// creation (key-pair generation and, for a service key, tenant→access-key
// delegation issuance), listing, retrieval, and revocation. A key created with
// a principal is bound to it: it holds no permissions, buckets or delegations
// of its own and is authorized from the tenant's bucket policies; deleting one
// publishes an invalidation for its principal, since there is no delegation a
// revocation could name. It returns the known errors in errors.go so handlers
// can map them to HTTP responses;
// unexpected failures are returned wrapped for the handler to log.
package accesskey

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"slices"
	"time"

	"github.com/fil-forge/hilt/pkg/invalidation"
	"github.com/fil-forge/hilt/pkg/s3perm"
	"github.com/fil-forge/hilt/pkg/store"
	accesskeystore "github.com/fil-forge/hilt/pkg/store/accesskey"
	"github.com/fil-forge/hilt/pkg/store/bucket"
	delegationstore "github.com/fil-forge/hilt/pkg/store/delegation"
	"github.com/fil-forge/hilt/pkg/store/principal"
	"github.com/fil-forge/hilt/pkg/store/tenant"
	"github.com/fil-forge/hilt/pkg/vault"
	swarfclient "github.com/fil-forge/swarf/pkg/client"
	"github.com/fil-forge/ucantone/did"
	"github.com/fil-forge/ucantone/multikey"
	"github.com/fil-forge/ucantone/multikey/ed25519"
	"github.com/fil-forge/ucantone/multikey/secp256k1"
	"github.com/fil-forge/ucantone/ucan"
	"github.com/fil-forge/ucantone/ucan/delegation"
	"github.com/fil-forge/ucantone/validator"
	"github.com/multiformats/go-multibase"
	"go.uber.org/zap"
)

const maxNameLength = 64

// RevocationPublisher is the subset of the revocation service (Swarf) that access
// key deletion needs. It is satisfied by [*swarfclient.Client]; the interface
// lets the logic be unit tested without a live revocation service.
type RevocationPublisher interface {
	// Publish submits a /ucan/revoke invocation self-signed by revoker for the
	// revoked delegation, which revoker must have issued unless a witness path is
	// supplied with [swarfclient.WithWitnessPath].
	Publish(ctx context.Context, revoker ucan.Issuer, revoked ucan.Delegation, opts ...swarfclient.PublishOption) error
}

// Service implements S3 access-key operations shared by the REST handlers.
type Service struct {
	logger        *zap.Logger
	tenants       tenant.Store
	accessKeys    accesskeystore.Store
	principals    principal.Store
	buckets       bucket.Store
	delegations   delegationstore.Store
	secrets       vault.Vault
	revocations   RevocationPublisher
	invalidations invalidation.Publisher
}

// New constructs the access-key service.
func New(
	logger *zap.Logger,
	tenants tenant.Store,
	accessKeys accesskeystore.Store,
	principals principal.Store,
	buckets bucket.Store,
	delegations delegationstore.Store,
	secrets vault.Vault,
	revocations RevocationPublisher,
	invalidations invalidation.Publisher,
) *Service {
	return &Service{
		logger:        logger,
		tenants:       tenants,
		accessKeys:    accessKeys,
		principals:    principals,
		buckets:       buckets,
		delegations:   delegations,
		secrets:       secrets,
		revocations:   revocations,
		invalidations: invalidations,
	}
}

// Create creates an S3 access key for the tenant. With no principal it is a
// service key: the tenant→access-key delegations for the requested permissions
// are issued (scoped to the named buckets, or tenant-wide when none are given)
// and the name must be unique within the tenant. With a principal the key is
// bound to it: permissions and buckets must be empty, no delegation is issued,
// and the name must be unique within the principal. It returns the stored
// record and the secret access key (the one time it is exposed).
func (s *Service) Create(ctx context.Context, externalID, name string, permissions, bucketNames []string, principalID string, expiresAt *time.Time) (accesskeystore.Record, string, error) {
	if name == "" || len(name) > maxNameLength {
		return accesskeystore.Record{}, "", ErrInvalidName
	}
	if principalID != "" {
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

	var principalRef *string
	if principalID != "" {
		_, err := s.principals.Get(ctx, tenantRec.ID, principalID)
		if errors.Is(err, store.ErrRecordNotFound) {
			return accesskeystore.Record{}, "", ErrUnknownPrincipal
		} else if err != nil {
			return accesskeystore.Record{}, "", fmt.Errorf("looking up principal: %w", err)
		}
		principalRef = &principalID
		log = log.With(zap.String("principal", principalID))
	}

	// Load the tenant signer up front: it is required to issue a service key's
	// delegations and its absence is unrecoverable, so fail before creating any
	// state. A principal-bound key is issued nothing.
	var issuer ucan.Issuer
	if principalRef == nil {
		issuer, err = s.tenantIssuer(ctx, tenantRec.ID)
		if err != nil {
			return accesskeystore.Record{}, "", err
		}
	}

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
		if err := s.accessKeys.Delete(cleanupCtx, accessKeyID, nil); err != nil {
			log.Warn("rollback: deleting access key", zap.Error(err))
		}
		if err := s.secrets.Delete(cleanupCtx, vaultPath); err != nil {
			log.Warn("rollback: deleting access key from vault", zap.Error(err))
		}
	}

	if err := s.accessKeys.Add(ctx, accesskeystore.Input{
		ID:          accessKeyID,
		Tenant:      tenantRec.ID,
		Name:        name,
		Buckets:     bucketIDs,
		Permissions: permissions,
		Principal:   principalRef,
		ExpiresAt:   expiresAt,
	}); err != nil {
		rollback()
		// Name uniqueness is enforced by the store: per tenant for a service key,
		// per principal for a principal-bound key. A fresh random access-key DID
		// colliding is not a realistic case.
		if errors.Is(err, store.ErrRecordExists) {
			return accesskeystore.Record{}, "", ErrNameConflict
		}
		// The principal was looked up above, so a rejected reference means it was
		// removed in between.
		if principalRef != nil && errors.Is(err, store.ErrInvalidArgument) {
			return accesskeystore.Record{}, "", ErrUnknownPrincipal
		}
		// The principal row is referenced by the new key; a removal holding it
		// past the store's lock timeout means nothing was written and the
		// call can be repeated.
		if errors.Is(err, store.ErrLockTimeout) {
			return accesskeystore.Record{}, "", ErrConcurrentChange
		}
		return accesskeystore.Record{}, "", fmt.Errorf("storing access key record: %w", err)
	}

	if principalRef != nil {
		rec, err := s.accessKeys.Get(ctx, accessKeyID)
		if err != nil {
			rollback()
			return accesskeystore.Record{}, "", fmt.Errorf("loading created access key: %w", err)
		}
		log.Info("created principal-bound access key")
		return rec, secretAccessKey, nil
	}

	// Issue tenant→access-key delegations: one per (command × subject), where
	// subject is each bucket DID or a single powerline (undefined subject).
	// They live as long as the key does: its expiry when set, otherwise forever —
	// without WithNoExpiration, ucantone defaults to a 30-second expiry, which
	// killed every proof chain through the key.
	opts := []delegation.Option{delegation.WithNoExpiration()}
	if expiresAt != nil {
		opts = []delegation.Option{delegation.WithExpiration(ucan.UnixTimestamp(expiresAt.Unix()))}
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

// Delete removes an access key belonging to the tenant. A service key's
// delegations are revoked first: publishing before anything is removed leaves
// the key intact when the revocation service fails, so the call is cleanly
// retryable — otherwise the delegations would live on with nothing for a
// verifier to check. A principal-bound key holds no delegation a revocation
// could name, so the gateway is told to drop what it cached for the key's
// principal instead: the invalidation is published while the row is locked and
// before the delete commits, so a publish failure leaves the key usable. A row
// another write holds past the store's lock timeout is [ErrConcurrentChange].
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

	if rec.Principal != nil {
		return s.deletePrincipalKey(ctx, tenantRec.ID, id, *rec.Principal)
	}
	return s.deleteServiceKey(ctx, tenantRec.ID, id)
}

// deleteServiceKey publishes revocations for the key's delegations, then
// removes them, its vault key, and its record.
func (s *Service) deleteServiceKey(ctx context.Context, tenantID, id did.DID) error {
	if err := s.revokeDelegations(ctx, tenantID, id); err != nil {
		return err
	}

	if err := s.delegations.DeleteByAudience(ctx, id); err != nil {
		return fmt.Errorf("deleting access key delegations: %w", err)
	}
	if err := s.secrets.Delete(ctx, vault.AccessKeyPath(tenantID, id)); err != nil {
		s.logger.Warn("removing access key from vault", zap.Error(err))
	}
	if err := s.accessKeys.Delete(ctx, id, nil); err != nil {
		if errors.Is(err, store.ErrLockTimeout) {
			return ErrConcurrentChange
		}
		return fmt.Errorf("deleting access key: %w", err)
	}
	s.logger.Info("deleted access key",
		zap.Stringer("tenant", tenantID),
		zap.Stringer("access_key", id),
	)
	return nil
}

// deletePrincipalKey removes the row under its lock, publishing the principal
// invalidation from the callback the store runs before it commits, then
// removes the vault key.
func (s *Service) deletePrincipalKey(ctx context.Context, tenantID, id did.DID, principal string) error {
	if err := s.accessKeys.Delete(ctx, id, func(ctx context.Context) error {
		return s.invalidations.Invalidate(ctx, tenantID, principal)
	}); err != nil {
		// A lock the delete waited on means another writer holds the row.
		// Nothing was committed, so the caller repeats the call.
		if errors.Is(err, store.ErrLockTimeout) {
			s.logger.Info("access key removal lost a race with a concurrent write",
				zap.Stringer("tenant", tenantID), zap.Stringer("access_key", id), zap.Error(err))
			return ErrConcurrentChange
		}
		return fmt.Errorf("deleting access key: %w", err)
	}

	// Everything that makes the key unusable happens once the row is gone, so a
	// failed publish leaves a working key rather than a broken one. A
	// principal-bound key holds no delegation; the ones it may have been issued
	// in error are removed with it, and nothing is revoked.
	if err := s.delegations.DeleteByAudience(ctx, id); err != nil {
		return fmt.Errorf("deleting access key delegations: %w", err)
	}
	if err := s.secrets.Delete(ctx, vault.AccessKeyPath(tenantID, id)); err != nil {
		s.logger.Warn("removing access key from vault", zap.Error(err))
	}
	s.logger.Info("deleted access key",
		zap.Stringer("tenant", tenantID),
		zap.Stringer("access_key", id),
		zap.String("principal", principal),
	)
	return nil
}

// revokeDelegations publishes a UCAN revocation for every delegation issued to
// the access key, signed by the tenant that issued them.
//
// No witness path accompanies them: the revocation service only requires one to
// prove authority over a delegation the revoker did not issue, and the tenant
// issues every delegation its access keys hold.
func (s *Service) revokeDelegations(ctx context.Context, tenantID, accessKeyID did.DID) error {
	dels, err := store.Collect(ctx, func(ctx context.Context, opts store.PaginationConfig) (store.Page[ucan.Delegation], error) {
		var listOpts []store.PaginationOption
		if opts.Cursor != nil {
			listOpts = append(listOpts, store.WithCursor(*opts.Cursor))
		}
		return s.delegations.ListByAudience(ctx, accessKeyID, listOpts...)
	})
	if err != nil {
		return fmt.Errorf("listing access key delegations: %w", err)
	}
	if len(dels) == 0 {
		return nil
	}

	issuer, err := s.tenantIssuer(ctx, tenantID)
	if err != nil {
		return err
	}
	log := s.logger.With(zap.Stringer("tenant", tenantID), zap.Stringer("access_key", accessKeyID))

	now := ucan.UnixTimestamp(time.Now().Unix())
	for _, d := range dels {
		// An expired delegation is rejected by the revocation service, and is
		// unusable regardless, so revoking it is moot.
		if err := validator.ValidateNotExpired(d, now); err != nil {
			log.Info("skipping revocation of expired delegation", zap.Stringer("delegation", d.Link()))
			continue
		}
		if err := s.revocations.Publish(ctx, issuer, d); err != nil {
			return fmt.Errorf("publishing revocation for %s: %w", d.Link(), err)
		}
		log.Info("published revocation", zap.Stringer("delegation", d.Link()))
	}
	return nil
}

// tenantIssuer loads the tenant's secp256k1 signing key from the vault and
// returns an issuer that signs as the tenant.
func (s *Service) tenantIssuer(ctx context.Context, tenantID did.DID) (ucan.Issuer, error) {
	keyBytes, err := s.secrets.Read(ctx, vault.TenantKeyPath(tenantID))
	if err != nil {
		return nil, fmt.Errorf("reading tenant key: %w", err)
	}
	signer, err := secp256k1.Decode(keyBytes)
	if err != nil {
		return nil, fmt.Errorf("decoding tenant key: %w", err)
	}
	return multikey.NewIssuer(tenantID, signer), nil
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
