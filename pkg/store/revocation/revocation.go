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

// Cursor is a place in a tenant's revocations owed, in the order
// [Store.Oldest] returns them. The zero Cursor is before the first.
type Cursor struct {
	// RecordedAt is when the row at the cursor was recorded.
	RecordedAt time.Time
	// ID is the CID string of the delegation at the cursor.
	ID string
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
	// revocations for that come after the cursor, the longest recorded first,
	// and the cursor of the last one returned (after itself when none is).
	// The order is by recording time and then CID, so a reader that passes
	// each call's cursor to the next sees every row once, whether or not the
	// rows it has read are deleted meanwhile.
	Oldest(ctx context.Context, tenant did.DID, after Cursor, limit int) ([]ucan.Delegation, Cursor, error)
	// DeleteStatement returns the write that removes the revocations owed
	// for the delegations with the given CIDs, for a task that removes the
	// rows in its own commit. A CID with no row is ignored.
	DeleteStatement(ids []cid.Cid) store.Statement
	// Stats returns the number of revocations owed across every tenant and
	// the age of the oldest.
	Stats(ctx context.Context) (Stats, error)
}
