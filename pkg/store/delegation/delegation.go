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
	// DeleteByAudience removes all delegation records for a given audience.
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
	// PutBatch stores a batch of delegation records. It returns
	// [store.ErrInvalidArgument] if the batch contains a nil delegation.
	PutBatch(ctx context.Context, delegation []ucan.Delegation) error
	// Replace swaps the delegations of every listed audience in one
	// transaction: it hands next the current set of each, deletes them,
	// stores what next returns, and commits. An audience missing from next's
	// result, or mapped to nil, is left with none; an error from next rolls
	// everything back and is returned. An audience holding nothing is handed a
	// nil set, so Replace also stores a first delegation. next must not call
	// back into the store. It returns [store.ErrInvalidArgument] if next
	// returns a nil delegation or one whose audience is not the audience it is
	// filed under; entries for audiences not listed are ignored. On Postgres
	// next's ctx carries the transaction, so a store that opens with
	// pglock.Begin writes inside it. Replace takes no lock: a concurrent
	// write's delegations stored after the read are deleted with the rest.
	Replace(ctx context.Context, audiences []did.DID, next func(ctx context.Context, current map[did.DID][]ucan.Delegation) (map[did.DID][]ucan.Delegation, error)) error
	// ReplaceBySubject is [Store.Replace] over the audiences' delegations
	// whose subject is subject: next is handed only those, only those are
	// deleted, and every delegation next returns must be over subject. The
	// audiences' delegations over other subjects are left alone, so two
	// replacements over different subjects never undo each other. It returns
	// [store.ErrInvalidArgument] for an undef subject or a returned delegation
	// over another subject.
	ReplaceBySubject(ctx context.Context, subject did.DID, audiences []did.DID, next func(ctx context.Context, current map[did.DID][]ucan.Delegation) (map[did.DID][]ucan.Delegation, error)) error
}

// CheckReplacement refuses a replacement that holds a nil delegation or one
// filed under an audience other than its own, which would be written under an
// audience the call did not read. Both backends call it after next returns.
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

// CheckSubject refuses a replacement holding, under one of the audiences, a
// delegation over a subject other than subject, which
// [Store.ReplaceBySubject] would store outside the rows it replaces. Both
// backends call it after [CheckReplacement], which refuses a nil delegation.
func CheckSubject(audiences []did.DID, subject string, replacement map[did.DID][]ucan.Delegation) error {
	for _, aud := range audiences {
		for _, d := range replacement[aud] {
			if d.Subject().String() != subject {
				return fmt.Errorf("delegation %s is over %s, not %s: %w", d.Link(), d.Subject(), subject, store.ErrInvalidArgument)
			}
		}
	}
	return nil
}
