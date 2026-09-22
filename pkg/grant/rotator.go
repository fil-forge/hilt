package grant

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"slices"
	"time"

	"github.com/fil-forge/hilt/pkg/store"
	accesskeystore "github.com/fil-forge/hilt/pkg/store/accesskey"
	delegationstore "github.com/fil-forge/hilt/pkg/store/delegation"
	"github.com/fil-forge/hilt/pkg/vault"
	"github.com/fil-forge/ucantone/did"
	"github.com/fil-forge/ucantone/ucan"
	"github.com/fil-forge/ucantone/validator"
	"go.uber.org/zap"
)

// BatchTimeout bounds every rotation of one write together. A policy write
// rotates the keys of each principal whose actions changed, the wildcard
// fanning out to all of the tenant's, and a principal removal revokes each of
// its keys' delegations; both hold a row lock throughout, while a share-locked
// reader of that row gives up after [store.LockTimeout]. The batch as a whole
// gets this deadline, below the reader's bound, so a large batch cannot lock
// the data path out.
const BatchTimeout = 8 * time.Second

// The batch bound must stay below the reader's; a negative difference fails
// to compile.
const _ = uint(store.LockTimeout - BatchTimeout)

// RevocationPublisher is the subset of the revocation service (Swarf) Hilt
// needs. It is satisfied by [*swarfclient.Client]; the interface lets the logic
// be unit tested without a live revocation service.
type RevocationPublisher interface {
	// PublishBatch submits one /ucan/revoke invocation per revoked delegation,
	// self-signed by revoker, which must have issued every one of them, in a
	// single request. A repeat for a delegation already revoked is a duplicate
	// the service records once.
	PublishBatch(ctx context.Context, revoker ucan.Issuer, revoked []ucan.Delegation) error
}

// Rotator rewrites the stored delegations of principal-bound access keys as
// the bucket policies change. The delegations a change replaces are revoked
// through the revocation service, which makes the gateway drop what it cached
// for the key, and the whole rewrite runs under the keys' delegation locks so
// a concurrent rotation or deletion of one of the keys serializes behind it.
type Rotator struct {
	logger      *zap.Logger
	delegations delegationstore.Store
	accessKeys  accesskeystore.Store
	secrets     vault.Vault
	revocations RevocationPublisher
}

// NewRotator constructs a Rotator signing revocations and delegations as the
// tenant, whose key it reads from secrets.
func NewRotator(
	logger *zap.Logger,
	delegations delegationstore.Store,
	accessKeys accesskeystore.Store,
	secrets vault.Vault,
	revocations RevocationPublisher,
) *Rotator {
	return &Rotator{
		logger:      logger,
		delegations: delegations,
		accessKeys:  accessKeys,
		secrets:     secrets,
		revocations: revocations,
	}
}

// Rotate sets, for every key of each principal in actions, the key's
// delegations over bucket to those the principal's actions map to, and leaves
// its delegations over other buckets alone. The delegations replaced are
// revoked in one request before anything is stored, so a publish failure
// leaves every key unchanged; a key that held nothing over the bucket costs no
// revocation. An empty action set leaves the key with nothing over the bucket.
func (r *Rotator) Rotate(ctx context.Context, tenant, bucket did.DID, actions map[string][]string) error {
	principalOf := map[did.DID]string{}
	var keys []accesskeystore.Record
	for _, p := range slices.Sorted(maps.Keys(actions)) {
		recs, err := r.accessKeys.ListByTenant(ctx, tenant, accesskeystore.WithPrincipal(p))
		if err != nil {
			return fmt.Errorf("listing keys of principal %q: %w", p, err)
		}
		for _, rec := range recs {
			principalOf[rec.ID] = p
		}
		keys = append(keys, recs...)
	}
	if len(keys) == 0 {
		return nil
	}
	issuer, err := vault.TenantIssuer(ctx, r.secrets, tenant)
	if err != nil {
		return err
	}
	log := r.logger.With(zap.Stringer("tenant", tenant), zap.Stringer("bucket", bucket))

	return r.delegations.Replace(ctx, audiences(keys), func(ctx context.Context, current map[did.DID][]ucan.Delegation) (map[did.DID][]ucan.Delegation, error) {
		var revoked []ucan.Delegation
		next := make(map[did.DID][]ucan.Delegation, len(keys))
		for _, key := range keys {
			// The listing above is a snapshot: a key deleted while this waited
			// on the lock is left with nothing rather than issued fresh grants.
			if _, err := r.accessKeys.Get(ctx, key.ID); errors.Is(err, store.ErrRecordNotFound) {
				continue
			} else if err != nil {
				return nil, fmt.Errorf("looking up key %s: %w", key.ID, err)
			}
			for _, d := range current[key.ID] {
				if d.Subject() == bucket {
					revoked = append(revoked, d)
				} else {
					next[key.ID] = append(next[key.ID], d)
				}
			}
			fresh, err := Issue(issuer, key.ID, []did.DID{bucket}, actions[principalOf[key.ID]], key.ExpiresAt)
			if err != nil {
				return nil, fmt.Errorf("issuing delegations of %s: %w", key.ID, err)
			}
			next[key.ID] = append(next[key.ID], fresh...)
		}
		if err := PublishRevocations(ctx, log, r.revocations, issuer, revoked); err != nil {
			return nil, err
		}
		return next, nil
	})
}

// Revoke revokes every delegation of every key bound to the principal, in one
// request, and leaves the keys with none, for a principal being removed.
func (r *Rotator) Revoke(ctx context.Context, tenant did.DID, principal string) error {
	keys, err := r.accessKeys.ListByTenant(ctx, tenant, accesskeystore.WithPrincipal(principal))
	if err != nil {
		return fmt.Errorf("listing keys of principal %q: %w", principal, err)
	}
	if len(keys) == 0 {
		return nil
	}
	issuer, err := vault.TenantIssuer(ctx, r.secrets, tenant)
	if err != nil {
		return err
	}
	log := r.logger.With(zap.Stringer("tenant", tenant), zap.String("principal", principal))

	return r.delegations.Replace(ctx, audiences(keys), func(ctx context.Context, current map[did.DID][]ucan.Delegation) (map[did.DID][]ucan.Delegation, error) {
		var all []ucan.Delegation
		for _, key := range keys {
			all = append(all, current[key.ID]...)
		}
		return nil, PublishRevocations(ctx, log, r.revocations, issuer, all)
	})
}

func audiences(keys []accesskeystore.Record) []did.DID {
	ids := make([]did.DID, len(keys))
	for i, key := range keys {
		ids[i] = key.ID
	}
	return ids
}

// PublishRevocations publishes a revocation for each unexpired delegation in
// one request, signed by the tenant that issued them. It is the callback body
// of a [delegationstore.Store.Replace] that removes or replaces what keys hold.
func PublishRevocations(ctx context.Context, log *zap.Logger, publisher RevocationPublisher, issuer ucan.Issuer, dels []ucan.Delegation) error {
	now := ucan.UnixTimestamp(time.Now().Unix())
	live := make([]ucan.Delegation, 0, len(dels))
	for _, d := range dels {
		// An expired delegation is rejected by the revocation service, and is
		// unusable regardless, so revoking it is moot.
		if err := validator.ValidateNotExpired(d, now); err != nil {
			log.Info("skipping revocation of expired delegation", zap.Stringer("delegation", d.Link()))
			continue
		}
		live = append(live, d)
	}
	if len(live) == 0 {
		return nil
	}
	if err := publisher.PublishBatch(ctx, issuer, live); err != nil {
		return fmt.Errorf("publishing revocations for %d delegations: %w", len(live), err)
	}
	for _, d := range live {
		log.Info("published revocation", zap.Stringer("delegation", d.Link()))
	}
	return nil
}
