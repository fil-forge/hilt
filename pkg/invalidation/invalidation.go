// Package invalidation publishes principal invalidations: the record that
// tells the S3 gateway every proof and effective action set it cached for a
// principal's access keys is void. A principal holds no delegation, so no
// revocation can name what it must drop.
//
// Publishing happens inside the transaction that commits the change, from the
// beforeCommit callback the principal, policy and access-key stores run while
// holding the row lock. The publish is therefore on the critical path of a
// locked write, and [Timeout] bounds it so a hung revocation service fails the
// write instead of holding the lock.
package invalidation

import (
	"context"
	"fmt"
	"time"

	"github.com/fil-forge/hilt/pkg/store"
	"github.com/fil-forge/libforge/identity"
	"github.com/fil-forge/ucantone/did"
	"github.com/fil-forge/ucantone/ucan"
	"go.uber.org/zap"
)

// Timeout bounds one publish. A write that holds a row lock waits no longer
// than this for the revocation service before failing and releasing the lock.
const Timeout = 5 * time.Second

// BatchTimeout bounds every publish of one write together. A policy write
// invalidates each principal whose actions changed, the wildcard fanning out
// to all of the tenant's, and holds the bucket's exclusive lock throughout,
// while a share-locked reader of that bucket gives up after
// [store.LockTimeout]. Giving each publish its own [Timeout] in turn would let
// a large batch outlive the reader's wait and lock the bucket's data path out,
// so the batch as a whole gets this deadline, below the reader's bound. A
// single publish still waits at most [Timeout].
const BatchTimeout = 8 * time.Second

// The batch bound must stay below the reader's; a negative difference fails
// to compile.
const _ = uint(store.LockTimeout - BatchTimeout)

// Publisher records that a principal's cached authority is void. Callers hold
// a row lock while they call it and roll the write back when it errors, so a
// failed publish leaves the principal with its old access and never with more.
type Publisher interface {
	// Invalidate publishes an invalidation for the tenant's principal.
	Invalidate(ctx context.Context, tenant did.DID, principal string) error
}

// Invalidator is the subset of the revocation service (Swarf) that publishing
// needs. It is satisfied by [*swarfclient.Client]; the interface lets the logic
// be unit tested without a live revocation service.
//
// [swarfclient]: github.com/fil-forge/swarf/pkg/client
type Invalidator interface {
	// Invalidate submits a /principal/invalidate invocation self-signed by
	// issuer, which the revocation service accepts only from a publisher it is
	// configured to trust.
	Invalidate(ctx context.Context, issuer ucan.Issuer, tenant did.DID, principal string) error
}

// SwarfPublisher publishes invalidations to the revocation service, signed as
// Hilt's own service identity: the command carries no delegation, so the
// service authorizes it by the issuer alone.
type SwarfPublisher struct {
	logger *zap.Logger
	swarf  Invalidator
	issuer ucan.Issuer
}

// NewSwarfPublisher constructs the revocation-service-backed publisher signing
// as the given service identity.
func NewSwarfPublisher(logger *zap.Logger, swarf Invalidator, id identity.Identity) *SwarfPublisher {
	return &SwarfPublisher{logger: logger, swarf: swarf, issuer: id}
}

// Invalidate publishes the invalidation, giving the call [Timeout] to complete.
func (p *SwarfPublisher) Invalidate(ctx context.Context, tenant did.DID, principal string) error {
	ctx, cancel := context.WithTimeout(ctx, Timeout)
	defer cancel()

	if err := p.swarf.Invalidate(ctx, p.issuer, tenant, principal); err != nil {
		return fmt.Errorf("publishing invalidation for principal %q: %w", principal, err)
	}
	p.logger.Info("published principal invalidation",
		zap.Stringer("tenant", tenant),
		zap.String("principal", principal),
	)
	return nil
}
