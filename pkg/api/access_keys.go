package api

import (
	"context"
	"errors"
	"maps"
	"net/http"
	"slices"

	"github.com/fil-forge/hilt/pkg/store"
	"github.com/fil-forge/hilt/pkg/store/accesskey"
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
	"github.com/labstack/echo/v4"
	"github.com/multiformats/go-multibase"
	"go.uber.org/zap"
)

const maxAccessKeyNameLength = 100

// vaultTenantKeyPath is the vault key under which a tenant's private key is
// stored.
func vaultTenantKeyPath(tenantDID did.DID) string {
	return "/tenant/" + tenantDID.String()
}

// vaultAccessKeyPath is the vault key under which an access key's private key is
// stored. It MUST match the path used by the tenant delete cascade.
func vaultAccessKeyPath(tenantDID, accessKeyDID did.DID) string {
	return vaultTenantKeyPath(tenantDID) + "/access/" + accessKeyDID.String()
}

// NewCreateAccessKeyHandler handles POST /tenants/{tenantId}/access-keys —
// create an S3 access-key pair (returns the secret once only) and issue the
// tenant→access-key UCAN delegations for the requested permissions.
func NewCreateAccessKeyHandler(
	logger *zap.Logger,
	tenants tenant.Store,
	accessKeys accesskey.Store,
	buckets bucket.Store,
	delegations delegationstore.Store,
	secrets vault.Vault,
) Route {
	log := logger.With(zap.String("handler", "CreateAccessKey"))
	return NewRoute(http.MethodPost, "/tenants/:tenantId/access-keys", func(c echo.Context) error {
		ctx := c.Request().Context()

		var req CreateAccessKeyRequest
		if err := c.Bind(&req); err != nil {
			return echo.NewHTTPError(http.StatusBadRequest, "invalid request body")
		}
		if req.Name == "" || len(req.Name) > maxAccessKeyNameLength {
			return echo.NewHTTPError(http.StatusUnprocessableEntity, "name must be between 1 and 100 characters")
		}
		if len(req.Permissions) == 0 {
			return echo.NewHTTPError(http.StatusUnprocessableEntity, "at least one permission is required")
		}
		for _, p := range req.Permissions {
			if !validS3Permission(p) {
				return echo.NewHTTPError(http.StatusUnprocessableEntity, "unknown permission: "+p)
			}
		}

		tenantRec, err := tenants.GetByExternalID(ctx, c.Param("tenantId"))
		if errors.Is(err, store.ErrRecordNotFound) {
			return echo.NewHTTPError(http.StatusNotFound, "tenant not found")
		} else if err != nil {
			log.Error("looking up tenant", zap.Error(err))
			return echo.NewHTTPError(http.StatusInternalServerError, "internal error")
		}
		log := log.With(zap.Stringer("tenant", tenantRec.ID))

		// Load the tenant signer up front: it is required to issue delegations and
		// its absence is unrecoverable, so fail before creating any state.
		tenantKeyBytes, err := secrets.Read(ctx, vaultTenantKeyPath(tenantRec.ID))
		if err != nil {
			log.Error("reading tenant key", zap.Error(err))
			return echo.NewHTTPError(http.StatusInternalServerError, "internal error")
		}
		tenantSigner, err := secp256k1.Decode(tenantKeyBytes)
		if err != nil {
			log.Error("decoding tenant key", zap.Error(err))
			return echo.NewHTTPError(http.StatusInternalServerError, "internal error")
		}
		issuer := multikey.NewIssuer(tenantRec.ID, tenantSigner)

		// Resolve the named buckets to DIDs in a single tenant-scoped list query.
		// The query is scoped to the tenant, so a name owned by another tenant (or
		// one that doesn't exist) simply won't come back. An empty list means
		// tenant-wide (powerline) access.
		bucketDIDs := make([]did.DID, 0, len(req.Buckets))
		if len(req.Buckets) > 0 {
			recs, err := store.Collect(ctx, func(ctx context.Context, opts store.PaginationConfig) (store.Page[bucket.Record], error) {
				listOpts := []bucket.ListOption{bucket.WithNames(req.Buckets...)}
				if opts.Cursor != nil {
					listOpts = append(listOpts, bucket.WithCursor(*opts.Cursor))
				}
				return buckets.ListByTenant(ctx, tenantRec.ID, listOpts...)
			})
			if err != nil {
				log.Error("resolving buckets", zap.Error(err))
				return echo.NewHTTPError(http.StatusInternalServerError, "internal error")
			}
			byName := make(map[string]did.DID, len(recs))
			for _, b := range recs {
				byName[b.Name] = b.ID
			}
			for _, name := range req.Buckets {
				id, ok := byName[name]
				if !ok {
					return echo.NewHTTPError(http.StatusUnprocessableEntity, "unknown bucket: "+name)
				}
				bucketDIDs = append(bucketDIDs, id)
			}
		}

		// Generate the ed25519 access key. accessKeyId is the bare did:key
		// identifier; secretAccessKey is the multibase base64url private key.
		signer, err := ed25519.Generate()
		if err != nil {
			log.Error("generating access key", zap.Error(err))
			return echo.NewHTTPError(http.StatusInternalServerError, "internal error")
		}
		accessKeyDID := signer.KeyDID()
		secretAccessKey, err := multibase.Encode(multibase.Base64url, signer.Bytes())
		if err != nil {
			log.Error("encoding secret access key", zap.Error(err))
			return echo.NewHTTPError(http.StatusInternalServerError, "internal error")
		}
		log = log.With(zap.Stringer("access_key", accessKeyDID))

		vaultPath := vaultAccessKeyPath(tenantRec.ID, accessKeyDID)
		if err := secrets.Write(ctx, vaultPath, signer.Bytes()); err != nil {
			log.Error("storing access key", zap.Error(err))
			return echo.NewHTTPError(http.StatusInternalServerError, "internal error")
		}

		// Best-effort rollback of the (idempotent) state created below, so a
		// partial failure leaves nothing behind and is retryable.
		rollback := func() {
			if err := delegations.DeleteByAudience(ctx, accessKeyDID); err != nil {
				log.Warn("rollback: deleting delegations", zap.Error(err))
			}
			if err := accessKeys.Delete(ctx, accessKeyDID); err != nil {
				log.Warn("rollback: deleting access key", zap.Error(err))
			}
			if err := secrets.Delete(ctx, vaultPath); err != nil {
				log.Warn("rollback: deleting access key from vault", zap.Error(err))
			}
		}

		if err := accessKeys.Add(ctx, accessKeyDID, tenantRec.ID, req.Name, bucketDIDs, req.Permissions, req.ExpiresAt); err != nil {
			rollback()
			// Name uniqueness is enforced by the store's (tenant, name) constraint;
			// a fresh random access-key DID colliding is not a realistic case.
			if errors.Is(err, store.ErrRecordExists) {
				return echo.NewHTTPError(http.StatusConflict, "an access key with this name already exists")
			}
			log.Error("storing access key record", zap.Error(err))
			return echo.NewHTTPError(http.StatusInternalServerError, "internal error")
		}

		// Issue tenant→access-key delegations: one per (command × subject), where
		// subject is each bucket DID or a single powerline (undefined subject).
		var opts []delegation.Option
		if req.ExpiresAt != nil {
			opts = append(opts, delegation.WithExpiration(ucan.UnixTimestamp(req.ExpiresAt.Unix())))
		}
		subjects := bucketDIDs
		if len(subjects) == 0 {
			subjects = []did.DID{did.Undef} // powerline: undefined subject
		}
		var dels []ucan.Delegation
		for _, sub := range subjects {
			for _, cmd := range commandsForPermissions(req.Permissions) {
				d, err := delegation.Delegate(issuer, accessKeyDID, sub, cmd, opts...)
				if err != nil {
					rollback()
					log.Error("issuing delegation", zap.Error(err))
					return echo.NewHTTPError(http.StatusInternalServerError, "internal error")
				}
				dels = append(dels, d)
			}
		}
		if len(dels) > 0 {
			if err := delegations.PutBatch(ctx, dels); err != nil {
				rollback()
				log.Error("storing delegations", zap.Error(err))
				return echo.NewHTTPError(http.StatusInternalServerError, "internal error")
			}
		}

		rec, err := accessKeys.Get(ctx, accessKeyDID)
		if err != nil {
			log.Error("loading created access key", zap.Error(err))
			return echo.NewHTTPError(http.StatusInternalServerError, "internal error")
		}
		log.Info("created access key")
		return c.JSON(http.StatusCreated, CreatedAccessKey{
			AccessKey: AccessKey{
				AccessKeyID: rec.ID.Identifier(),
				Name:        rec.Name,
				Permissions: rec.Permissions,
				Buckets:     req.Buckets,
				ExpiresAt:   rec.ExpiresAt,
				CreatedAt:   rec.CreatedAt,
			},
			SecretAccessKey: secretAccessKey,
		})
	})
}

// NewListAccessKeysHandler handles GET /tenants/{tenantId}/access-keys — list
// all S3 access keys for a tenant (excludes secrets).
func NewListAccessKeysHandler(
	logger *zap.Logger,
	tenants tenant.Store,
	accessKeys accesskey.Store,
	buckets bucket.Store,
) Route {
	log := logger.With(zap.String("handler", "ListAccessKeys"))
	return NewRoute(http.MethodGet, "/tenants/:tenantId/access-keys", func(c echo.Context) error {
		ctx := c.Request().Context()

		tenantRec, err := tenants.GetByExternalID(ctx, c.Param("tenantId"))
		if errors.Is(err, store.ErrRecordNotFound) {
			return echo.NewHTTPError(http.StatusNotFound, "tenant not found")
		} else if err != nil {
			log.Error("looking up tenant", zap.Error(err))
			return echo.NewHTTPError(http.StatusInternalServerError, "internal error")
		}

		recs, err := accessKeys.ListByTenant(ctx, tenantRec.ID)
		if err != nil {
			log.Error("listing access keys", zap.Error(err))
			return echo.NewHTTPError(http.StatusInternalServerError, "internal error")
		}

		// Resolve names only for the buckets actually referenced across all keys.
		bucketIDs := map[did.DID]struct{}{}
		for _, rec := range recs {
			for _, b := range rec.Buckets {
				if _, ok := bucketIDs[b]; !ok {
					bucketIDs[b] = struct{}{}
				}
			}
		}
		bucketNames, err := bucketNamesByID(ctx, buckets, tenantRec.ID, slices.Collect(maps.Keys(bucketIDs)))
		if err != nil {
			log.Error("listing buckets", zap.Error(err))
			return echo.NewHTTPError(http.StatusInternalServerError, "internal error")
		}

		items := make([]AccessKey, 0, len(recs))
		for _, rec := range recs {
			items = append(items, accessKeyResponse(rec, bucketNames))
		}
		return c.JSON(http.StatusOK, AccessKeyList{Items: items})
	})
}

// NewGetAccessKeyHandler handles GET /tenants/{tenantId}/access-keys/{accessKeyId}
// — retrieve access-key metadata (secret never returned).
func NewGetAccessKeyHandler(
	logger *zap.Logger,
	tenants tenant.Store,
	accessKeys accesskey.Store,
	buckets bucket.Store,
) Route {
	log := logger.With(zap.String("handler", "GetAccessKey"))
	return NewRoute(http.MethodGet, "/tenants/:tenantId/access-keys/:accessKeyId", func(c echo.Context) error {
		ctx := c.Request().Context()

		tenantRec, err := tenants.GetByExternalID(ctx, c.Param("tenantId"))
		if errors.Is(err, store.ErrRecordNotFound) {
			return echo.NewHTTPError(http.StatusNotFound, "tenant not found")
		} else if err != nil {
			log.Error("looking up tenant", zap.Error(err))
			return echo.NewHTTPError(http.StatusInternalServerError, "internal error")
		}

		accessKeyDID, err := did.Parse(did.KeyPrefix + c.Param("accessKeyId"))
		if err != nil {
			return echo.NewHTTPError(http.StatusNotFound, "access key not found")
		}
		rec, err := accessKeys.Get(ctx, accessKeyDID)
		if errors.Is(err, store.ErrRecordNotFound) || (err == nil && rec.Tenant != tenantRec.ID) {
			return echo.NewHTTPError(http.StatusNotFound, "access key not found")
		} else if err != nil {
			log.Error("looking up access key", zap.Error(err))
			return echo.NewHTTPError(http.StatusInternalServerError, "internal error")
		}

		bucketNames, err := bucketNamesByID(ctx, buckets, tenantRec.ID, rec.Buckets)
		if err != nil {
			log.Error("listing buckets", zap.Error(err))
			return echo.NewHTTPError(http.StatusInternalServerError, "internal error")
		}
		return c.JSON(http.StatusOK, accessKeyResponse(rec, bucketNames))
	})
}

// NewDeleteAccessKeyHandler handles DELETE /tenants/{tenantId}/access-keys/{accessKeyId}
// — revoke an S3 access key (idempotent): remove its delegations, vault key, and
// record. Sending UCAN revocations to a revocation service is out of scope (no
// such service exists yet, as with Sprue deprovisioning).
func NewDeleteAccessKeyHandler(
	logger *zap.Logger,
	tenants tenant.Store,
	accessKeys accesskey.Store,
	delegations delegationstore.Store,
	secrets vault.Vault,
) Route {
	log := logger.With(zap.String("handler", "DeleteAccessKey"))
	return NewRoute(http.MethodDelete, "/tenants/:tenantId/access-keys/:accessKeyId", func(c echo.Context) error {
		ctx := c.Request().Context()

		tenantRec, err := tenants.GetByExternalID(ctx, c.Param("tenantId"))
		if errors.Is(err, store.ErrRecordNotFound) {
			return echo.NewHTTPError(http.StatusNotFound, "tenant not found")
		} else if err != nil {
			log.Error("looking up tenant", zap.Error(err))
			return echo.NewHTTPError(http.StatusInternalServerError, "internal error")
		}

		accessKeyDID, err := did.Parse(did.KeyPrefix + c.Param("accessKeyId"))
		if err != nil {
			return echo.NewHTTPError(http.StatusNotFound, "access key not found") // unparseable id ⇒ nothing to delete
		}

		// Idempotent: a missing key (or one owned by another tenant) is a no-op.
		rec, err := accessKeys.Get(ctx, accessKeyDID)
		if errors.Is(err, store.ErrRecordNotFound) || (err == nil && rec.Tenant != tenantRec.ID) {
			return echo.NewHTTPError(http.StatusNotFound, "access key not found")
		} else if err != nil {
			log.Error("looking up access key", zap.Error(err))
			return echo.NewHTTPError(http.StatusInternalServerError, "internal error")
		}

		if err := delegations.DeleteByAudience(ctx, accessKeyDID); err != nil {
			log.Error("deleting access key delegations", zap.Error(err))
			return echo.NewHTTPError(http.StatusInternalServerError, "internal error")
		}
		if err := secrets.Delete(ctx, vaultAccessKeyPath(tenantRec.ID, accessKeyDID)); err != nil {
			log.Warn("removing access key from vault", zap.Error(err))
		}
		if err := accessKeys.Delete(ctx, accessKeyDID); err != nil {
			log.Error("deleting access key", zap.Error(err))
			return echo.NewHTTPError(http.StatusInternalServerError, "internal error")
		}
		return c.NoContent(http.StatusNoContent)
	})
}

// accessKeyResponse builds the API representation of an access key, resolving
// stored bucket DIDs back to their names (a DID with no known name is rendered
// as the DID string). The secret is never included.
func accessKeyResponse(rec accesskey.Record, bucketNames map[did.DID]string) AccessKey {
	var bucketList []string
	for _, b := range rec.Buckets {
		if name, ok := bucketNames[b]; ok {
			bucketList = append(bucketList, name)
		} else {
			bucketList = append(bucketList, b.String())
		}
	}
	return AccessKey{
		AccessKeyID: rec.ID.Identifier(),
		Name:        rec.Name,
		Permissions: rec.Permissions,
		Buckets:     bucketList,
		ExpiresAt:   rec.ExpiresAt,
		CreatedAt:   rec.CreatedAt,
	}
}

// bucketNamesByID returns a DID→name map for the given bucket IDs owned by the
// tenant. IDs that don't resolve (e.g. a deleted bucket) are simply absent.
func bucketNamesByID(ctx context.Context, buckets bucket.Store, tenantID did.DID, ids []did.DID) (map[did.DID]string, error) {
	if len(ids) == 0 {
		return map[did.DID]string{}, nil
	}
	recs, err := store.Collect(ctx, func(ctx context.Context, opts store.PaginationConfig) (store.Page[bucket.Record], error) {
		listOpts := []bucket.ListOption{bucket.WithIDs(ids...)}
		if opts.Cursor != nil {
			listOpts = append(listOpts, bucket.WithCursor(*opts.Cursor))
		}
		return buckets.ListByTenant(ctx, tenantID, listOpts...)
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
