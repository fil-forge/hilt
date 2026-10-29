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

// BatchTimeout caps one Rotate or Revoke call, which covers every key the
// write touches, and every [PublishRevocations]. An earlier caller deadline
// still wins.
const BatchTimeout = 8 * time.Second

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
// through the revocation service before the write that replaces them stores
// anything, which makes the gateway drop what it cached for the key. A rotation takes no
// lock: it replaces only the keys' delegations over the bucket it rotates, so
// rotations over different buckets never undo each other.
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
// its delegations over other buckets alone. The delegations it replaces are
// revoked in one request before anything is written (see
// [PublishRevocations]), so a publish failure leaves every key unchanged; a key
// that held nothing over the bucket costs no revocation. An empty action set
// leaves the key with nothing over the bucket.
// Two concurrent rotations over the same bucket each delete what they read and
// insert their own set, so the keys may end up holding both sets, and a set
// the other write deleted is never revoked.
func (r *Rotator) Rotate(ctx context.Context, tenant, bucket did.DID, actions map[string][]string) error {
	ctx, cancel := context.WithTimeout(ctx, BatchTimeout)
	defer cancel()
	keys, issuer, err := r.load(ctx, tenant, slices.Sorted(maps.Keys(actions))...)
	if err != nil || len(keys) == 0 {
		return err
	}
	principalOf := make(map[did.DID]string, len(keys))
	for _, key := range keys {
		principalOf[key.ID] = *key.Principal
	}

	log := r.logger.With(zap.Stringer("tenant", tenant), zap.Stringer("bucket", bucket))
	return r.delegations.ReplaceBySubject(ctx, bucket, audiences(keys), func(ctx context.Context, current map[did.DID][]ucan.Delegation) (map[did.DID][]ucan.Delegation, error) {
		var revoked []ucan.Delegation
		next := make(map[did.DID][]ucan.Delegation, len(keys))
		for _, key := range keys {
			revoked = append(revoked, current[key.ID]...)
			// The listing above is a snapshot: a key deleted since is left with
			// nothing rather than issued fresh grants.
			if _, err := r.accessKeys.Get(ctx, key.ID); errors.Is(err, store.ErrRecordNotFound) {
				continue
			} else if err != nil {
				return nil, fmt.Errorf("looking up key %s: %w", key.ID, err)
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
// request before anything is written, and leaves the keys with none, for a
// principal being removed.
func (r *Rotator) Revoke(ctx context.Context, tenant did.DID, principal string) error {
	ctx, cancel := context.WithTimeout(ctx, BatchTimeout)
	defer cancel()
	keys, issuer, err := r.load(ctx, tenant, principal)
	if err != nil || len(keys) == 0 {
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

// Publish revokes dels, which the tenant issued, in one request (see
// [PublishRevocations]), for a caller that removes them in its own write. It
// reads the tenant's key only when there is something to revoke.
func (r *Rotator) Publish(ctx context.Context, tenant did.DID, dels []ucan.Delegation) error {
	if len(dels) == 0 {
		return nil
	}
	issuer, err := vault.TenantIssuer(ctx, r.secrets, tenant)
	if err != nil {
		return err
	}
	return PublishRevocations(ctx, r.logger.With(zap.Stringer("tenant", tenant)), r.revocations, issuer, dels)
}

// load lists the keys bound to the principals, in principal order, and, when
// there are any, the tenant's issuer.
func (r *Rotator) load(ctx context.Context, tenant did.DID, principals ...string) ([]accesskeystore.Record, ucan.Issuer, error) {
	var keys []accesskeystore.Record
	for _, p := range principals {
		recs, err := r.accessKeys.ListByTenant(ctx, tenant, accesskeystore.WithPrincipal(p))
		if err != nil {
			return nil, nil, fmt.Errorf("listing keys of principal %q: %w", p, err)
		}
		keys = append(keys, recs...)
	}
	if len(keys) == 0 {
		return nil, nil, nil
	}
	issuer, err := vault.TenantIssuer(ctx, r.secrets, tenant)
	if err != nil {
		return nil, nil, err
	}
	return keys, issuer, nil
}

func audiences(keys []accesskeystore.Record) []did.DID {
	ids := make([]did.DID, len(keys))
	for i, key := range keys {
		ids[i] = key.ID
	}
	return ids
}

// PublishRevocations publishes a revocation for each unexpired delegation in
// one request, signed by the tenant that issued them. Every caller runs it
// inside the write that removes or replaces the delegations, after that
// write's reads and before its first row write: a failed publish then rolls
// the write back and leaves the delegations in place, and the transaction
// holds no row lock while it waits for the revocation service, so no other
// write waits on Swarf. Keep it before the first row write. It shortens its
// ctx to [BatchTimeout] itself; an earlier caller deadline still wins.
func PublishRevocations(ctx context.Context, log *zap.Logger, publisher RevocationPublisher, issuer ucan.Issuer, dels []ucan.Delegation) error {
	ctx, cancel := context.WithTimeout(ctx, BatchTimeout)
	defer cancel()
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
