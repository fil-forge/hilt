package grant

import (
	"context"
	"fmt"
	"time"

	"github.com/fil-forge/ucantone/ucan"
	"github.com/fil-forge/ucantone/validator"
	"go.uber.org/zap"
)

// BatchTimeout caps every publish [PublishRevocations] makes. Every publish
// runs inside a task that holds its tenant's subject on a queue, so a stalled
// revocation service fails the task at the bound rather than holding up the
// tenant's tasks behind it. An earlier caller deadline still wins.
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

// PublishRevocations publishes a revocation for each unexpired delegation in
// one request, signed by the tenant that issued them. It shortens its ctx to
// [BatchTimeout] itself, so whoever calls it, a stalled publish gives up at
// the bound, releasing any lock its caller holds. An earlier caller deadline
// still wins.
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
