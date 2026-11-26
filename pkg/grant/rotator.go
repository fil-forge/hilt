package grant

import (
	"context"
	"fmt"
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

// BatchTimeout caps one Revoke call, which covers every key of the principal
// being removed, and every publish made under a delegation lock. A principal
// removal revokes each of its keys' delegations while it holds a row lock,
// and a share-locked reader of that row gives up after [store.LockTimeout].
// Revoke shortens its ctx to this deadline, below the reader's bound (an
// earlier caller deadline still wins), so a large batch or a stalled publish
// cannot lock the data path out. [PublishRevocations] applies the same bound,
// so every publish made under a delegation lock, a bucket deletion's and a
// tenant removal's included, has it.
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

// Rotator revokes the stored delegations of a principal's access keys when the
// principal is removed. The delegations are revoked through the revocation
// service, which makes the gateway drop what it cached for the keys, under
// the keys' delegation locks. The grants a policy change takes away or adds
// are written by the policy's task on the tenant's queue
// (pkg/tasks/tenantqueue).
type Rotator struct {
	logger      *zap.Logger
	delegations delegationstore.Store
	accessKeys  accesskeystore.Store
	secrets     vault.Vault
	revocations RevocationPublisher
}

// NewRotator constructs a Rotator signing revocations as the tenant, whose key
// it reads from secrets.
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

// Revoke revokes every delegation of every key bound to the principal, in one
// request, and leaves the keys with none, for a principal being removed.
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

// load lists the keys bound to the principal and, when there are any, the
// tenant's issuer.
func (r *Rotator) load(ctx context.Context, tenant did.DID, principal string) ([]accesskeystore.Record, ucan.Issuer, error) {
	keys, err := r.accessKeys.ListByTenant(ctx, tenant, accesskeystore.WithPrincipal(principal))
	if err != nil {
		return nil, nil, fmt.Errorf("listing the principal's keys: %w", err)
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
// one request, signed by the tenant that issued them. It is the callback body
// of a [delegationstore.Store.Replace] that removes what keys hold, so it
// runs while their delegations are locked, and it
// shortens its ctx to [BatchTimeout] itself: whoever calls it, a stalled
// publish releases the locks at the bound. An earlier caller deadline still
// wins.
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
