package delegation

import (
	"context"

	"github.com/fil-forge/hilt/pkg/store"
	"github.com/fil-forge/ucantone/did"
	"github.com/fil-forge/ucantone/ucan"
	"github.com/ipfs/go-cid"
)

type Store interface {
	// DeleteByAudience removes all delegation records for a given audience,
	// under that audience's lock.
	DeleteByAudience(ctx context.Context, audience did.DID) error
	// DeleteBySubject removes all delegation records for a given subject.
	// The undefined DID (powerline) is not removed by this method: it returns
	// [store.ErrInvalidArgument] for an undef subject.
	DeleteBySubject(ctx context.Context, subject did.DID) error
	// ListByAudience retrieves a paginated list of delegation records for a given
	// audience.
	ListByAudience(ctx context.Context, audience did.DID, opts ...store.PaginationOption) (store.Page[ucan.Delegation], error)
	// ListBySubject retrieves a paginated list of delegation records for a given
	// subject. Powerline delegations (undefined subject) are not returned by this
	// method: it returns [store.ErrInvalidArgument] for an undef subject.
	ListBySubject(ctx context.Context, subject did.DID, opts ...store.PaginationOption) (store.Page[ucan.Delegation], error)
	// ProofChain recursively builds a proof chain of delegations from the given
	// audience to the given subject for the specified command. It returns the list
	// of delegations and their corresponding links in the order required for
	// invocation. i.e. starting from the root Delegation (issued by the Subject),
	// in strict sequence where the aud of the previous Delegation matches the iss
	// of the next Delegation. It returns [store.ErrInvalidArgument] for an undef
	// subject.
	ProofChain(ctx context.Context, aud did.DID, cmd ucan.Command, sub did.DID) ([]ucan.Delegation, []cid.Cid, error)
	// PutBatch stores a batch of delegation records. It takes the lock of
	// every audience the batch touches, so it does not interleave with a
	// Replace of any of them. It returns [store.ErrInvalidArgument] if the
	// batch contains a nil delegation.
	PutBatch(ctx context.Context, delegation []ucan.Delegation) error
	// Replace atomically swaps the audience's delegations: it locks the
	// audience, hands next the current set, deletes it, stores what next
	// returns, and commits. next may return nil to leave the audience with
	// none; an error from next rolls everything back and is returned. An
	// audience holding nothing is handed a nil current set and stores what
	// next returns, so Replace also stores a first delegation. next runs while
	// the audience is locked and must not call back into the store. It returns
	// [store.ErrInvalidArgument] if next returns a nil delegation.
	Replace(ctx context.Context, audience did.DID, next func(ctx context.Context, current []ucan.Delegation) ([]ucan.Delegation, error)) error
}
