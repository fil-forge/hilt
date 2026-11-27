// Package revocation defines the store of revocations owed: the delegations
// that no longer stand and whose revocations are still to be published to
// the revocation service. A delegation is recorded here in the same commit
// that takes it out of the delegation store, and is deleted once its
// revocation is published.
package revocation

import (
	"context"
	"time"

	"github.com/fil-forge/hilt/pkg/store"
	"github.com/fil-forge/ucantone/did"
	"github.com/fil-forge/ucantone/ucan"
	"github.com/ipfs/go-cid"
)

// Stats summarizes the revocations owed across every tenant.
type Stats struct {
	// Count is the number of revocations owed.
	Count int64
	// OldestAge is how long ago the oldest was recorded, zero when none is
	// owed.
	OldestAge time.Duration
}

type Store interface {
	// Add records the delegations as revocations the tenant owes, together or
	// not at all. One already recorded is left as it is, so a repeat changes
	// nothing. When ctx carries a transaction (pglock.WithTx) the rows commit
	// with it. It returns [store.ErrInvalidArgument] if the tenant is undef,
	// a delegation is nil, or a delegation was not issued by the tenant,
	// whose key is the only one that can sign its revocation.
	Add(ctx context.Context, tenant did.DID, delegations []ucan.Delegation) error
	// AddStatement returns the write [Store.Add] makes, for a task that
	// records the revocations in its own commit. It refuses what Add
	// refuses.
	AddStatement(tenant did.DID, delegations []ucan.Delegation) (store.Statement, error)
	// Oldest returns up to limit of the delegations the tenant owes
	// revocations for, the longest recorded first, ordered by recording time
	// and then CID.
	Oldest(ctx context.Context, tenant did.DID, limit int) ([]ucan.Delegation, error)
	// Delete removes the revocations owed for the delegations with the given
	// CIDs. A CID with no row is ignored. When ctx carries a transaction
	// (pglock.WithTx) the removal commits with it.
	Delete(ctx context.Context, ids []cid.Cid) error
	// Stats returns the number of revocations owed across every tenant and
	// the age of the oldest.
	Stats(ctx context.Context) (Stats, error)
}
