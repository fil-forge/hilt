package delegation

import (
	"context"
	"fmt"

	"github.com/fil-forge/hilt/pkg/store"
	"github.com/fil-forge/ucantone/did"
	"github.com/fil-forge/ucantone/ucan"
	"github.com/ipfs/go-cid"
)

type Store interface {
	// Delete removes the delegation records with the given links. Links with no
	// record are ignored.
	Delete(ctx context.Context, links ...cid.Cid) error
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
	// Replace atomically swaps the delegations of every listed audience in one
	// transaction: it locks the audiences, hands next the current set of each,
	// deletes them, stores what next returns, and commits. An audience missing
	// from next's result, or mapped to nil, is left with none; an error from
	// next rolls everything back and is returned. An audience holding nothing
	// is handed a nil set, so Replace also stores a first delegation. next runs
	// while the audiences are locked and must not call back into the store. It
	// returns [store.ErrInvalidArgument] if next returns a nil delegation or
	// one whose audience is not the audience it is filed under; entries for
	// audiences not listed are ignored. On Postgres next's
	// ctx carries the transaction, so a store that opens with pglock.Begin
	// writes inside it. The lock wait is bounded at [store.LockTimeout] and
	// returns [store.ErrLockTimeout] when it runs out.
	Replace(ctx context.Context, audiences []did.DID, next func(ctx context.Context, current map[did.DID][]ucan.Delegation) (map[did.DID][]ucan.Delegation, error)) error
	// ReplaceOver is Replace narrowed to the delegations over subject: next is
	// handed each audience's delegations over subject alone, and its result
	// replaces those, leaving the audiences' delegations over every other
	// subject as they are. On Postgres its cost follows what the audiences
	// hold over subject, not everything they hold. It takes the same locks as Replace,
	// so the two serialize. Besides Replace's checks, it returns
	// [store.ErrInvalidArgument] for an undef subject and for a delegation from
	// next over another subject, which would be written beside the set it
	// leaves alone.
	ReplaceOver(ctx context.Context, audiences []did.DID, subject did.DID, next func(ctx context.Context, current map[did.DID][]ucan.Delegation) (map[did.DID][]ucan.Delegation, error)) error
}

// CheckReplacement refuses a replacement that holds a nil delegation or one
// filed under an audience other than its own, which would be written under an
// audience the call did not lock. Both backends call it after next returns.
func CheckReplacement(audiences []did.DID, replacement map[did.DID][]ucan.Delegation) error {
	for _, aud := range audiences {
		for _, d := range replacement[aud] {
			if d == nil {
				return fmt.Errorf("delegations must not be nil: %w", store.ErrInvalidArgument)
			}
			if d.Audience() != aud {
				return fmt.Errorf("delegation %s is for %s, filed under %s: %w", d.Link(), d.Audience(), aud, store.ErrInvalidArgument)
			}
		}
	}
	return nil
}

// CheckReplacementOver is [CheckReplacement] for a ReplaceOver of subject: it
// also refuses a delegation over another subject.
func CheckReplacementOver(audiences []did.DID, subject did.DID, replacement map[did.DID][]ucan.Delegation) error {
	if err := CheckReplacement(audiences, replacement); err != nil {
		return err
	}
	for _, aud := range audiences {
		for _, d := range replacement[aud] {
			if d.Subject() != subject {
				return fmt.Errorf("delegation %s is over %s, replacing those over %s: %w", d.Link(), d.Subject(), subject, store.ErrInvalidArgument)
			}
		}
	}
	return nil
}
