package marker

import (
	"context"
	"fmt"
	"time"

	accesskeystore "github.com/fil-forge/hilt/pkg/store/accesskey"
	delegationstore "github.com/fil-forge/hilt/pkg/store/delegation"
	"github.com/fil-forge/hilt/pkg/vault"
	swarfclient "github.com/fil-forge/swarf/pkg/client"
	"github.com/fil-forge/ucantone/did"
	"github.com/fil-forge/ucantone/ucan"
	"github.com/fil-forge/ucantone/ucan/nonce"
	"github.com/fil-forge/ucantone/validator"
	"go.uber.org/zap"
)

// RevocationPublisher is the subset of the revocation service (Swarf) that
// marker rotation needs. It is satisfied by [*swarfclient.Client]; the
// interface lets the logic be unit tested without a live revocation service.
type RevocationPublisher interface {
	// Publish submits a /ucan/revoke invocation self-signed by revoker for the
	// revoked delegation, which revoker must have issued.
	Publish(ctx context.Context, revoker ucan.Issuer, revoked ucan.Delegation, opts ...swarfclient.PublishOption) error
}

// Rotator revokes and reissues the markers of principal-bound access keys. A
// key's marker is revoked through the revocation service, which makes the
// gateway drop what it cached for the key, and replaced under the key's
// delegation lock so a concurrent rotation or deletion of the same key
// serializes behind it.
type Rotator struct {
	logger      *zap.Logger
	delegations delegationstore.Store
	accessKeys  accesskeystore.Store
	secrets     vault.Vault
	revocations RevocationPublisher
}

// NewRotator constructs a Rotator signing revocations and markers as the
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

// Rotate replaces the marker of every key bound to each of the tenant's
// principals: the key's current marker is revoked and a fresh one stored in
// its place, so the gateway picks the new one up on the key's next authorize.
// A key that holds no marker (deleted meanwhile) is left with none. It stops
// at the first failure, leaving that key's marker unchanged. A caller running
// several rotations under one context may cancel one between its publish and
// its commit; the revoked marker then stays stored, and the retry revokes it
// again under a fresh nonce.
func (r *Rotator) Rotate(ctx context.Context, tenant did.DID, principals []string) error {
	for _, p := range principals {
		if err := r.replace(ctx, tenant, p, true); err != nil {
			return err
		}
	}
	return nil
}

// Revoke revokes the marker of every key bound to the principal and leaves
// the keys with none, for a principal being removed.
func (r *Rotator) Revoke(ctx context.Context, tenant did.DID, principal string) error {
	return r.replace(ctx, tenant, principal, false)
}

// replace revokes the current delegations of each of the principal's keys
// and, when reissue is set, stores a fresh marker in their place.
func (r *Rotator) replace(ctx context.Context, tenant did.DID, principal string, reissue bool) error {
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

	for _, key := range keys {
		err := r.delegations.Replace(ctx, key.ID, func(ctx context.Context, current []ucan.Delegation) ([]ucan.Delegation, error) {
			if len(current) == 0 {
				return nil, nil
			}
			if err := PublishRevocations(ctx, log.With(zap.Stringer("access_key", key.ID)), r.revocations, issuer, current); err != nil {
				return nil, err
			}
			if !reissue {
				return nil, nil
			}
			m, err := Issue(issuer, key.ID, tenant, key.ExpiresAt)
			if err != nil {
				return nil, fmt.Errorf("issuing marker: %w", err)
			}
			return []ucan.Delegation{m}, nil
		})
		if err != nil {
			return fmt.Errorf("replacing marker of %s: %w", key.ID, err)
		}
	}
	return nil
}

// PublishRevocations publishes a revocation for each unexpired delegation,
// signed by the tenant that issued them. Each revocation carries a fresh
// nonce: the revocation service records one revocation per invocation CID,
// and a marker revoked once already (a rotation retried after a rolled-back
// write) must still reach the gateway. It is the callback body of a
// [delegationstore.Store.Replace] that removes or replaces a key's marker.
func PublishRevocations(ctx context.Context, log *zap.Logger, publisher RevocationPublisher, issuer ucan.Issuer, dels []ucan.Delegation) error {
	now := ucan.UnixTimestamp(time.Now().Unix())
	for _, d := range dels {
		// An expired delegation is rejected by the revocation service, and is
		// unusable regardless, so revoking it is moot.
		if err := validator.ValidateNotExpired(d, now); err != nil {
			log.Info("skipping revocation of expired delegation", zap.Stringer("delegation", d.Link()))
			continue
		}
		if err := publisher.Publish(ctx, issuer, d, swarfclient.WithNonce(nonce.Generate(16))); err != nil {
			return fmt.Errorf("publishing revocation for %s: %w", d.Link(), err)
		}
		log.Info("published revocation", zap.Stringer("delegation", d.Link()))
	}
	return nil
}
