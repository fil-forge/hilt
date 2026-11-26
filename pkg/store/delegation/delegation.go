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
	// WithdrawKeyGrantsStatements returns the writes, to run in order in one
	// transaction, that take every delegation the tenant issued to one of its
	// access keys out of the store and record each as a revocation the tenant
	// owes. They are for a task that withdraws a tenant's grants in its own
	// commit. The rows are chosen when the statements run, so the task
	// withdraws what the keys hold at its commit, whatever its handler read.
	// The first statement takes the lock of every key of the tenant, as a
	// Replace does. The lock is there for principal removal, which revokes
	// and deletes a principal's keys under their locks outside the tenant's
	// task queue: a task that goes on to store grants for the keys
	// ([Store.PutForKeysStatement]) either waits for a removal that holds
	// them and finds the keys gone, or commits first and has its grants
	// revoked by the removal. A delegation the tenant did not issue, such as
	// a bucket's root delegation to the tenant, is left alone.
	WithdrawKeyGrantsStatements(tenant did.DID) []store.Statement
	// WithdrawGrantsOverStatements is [Store.WithdrawKeyGrantsStatements]
	// narrowed to the delegations over subject held by the tenant's access
	// keys that are bound to one of principals, for a task that changes what
	// those principals may do on one bucket in its own commit. The keys'
	// delegations over every other subject are left alone. The first
	// statement takes the locks of those keys, for the same writer and the
	// same reason.
	WithdrawGrantsOverStatements(tenant, subject did.DID, principals []string) []store.Statement
	// WithdrawGrantsOfKeyStatement is [Store.WithdrawKeyGrantsStatements]
	// narrowed to one access key, for a task that deletes the key in its own
	// commit: the delegations the tenant issued to the key leave the store
	// and are recorded as revocations the tenant owes. It takes no lock: the
	// task stores the key nothing, and the writers outside the tenant's task
	// queue only ever remove a key's delegations.
	WithdrawGrantsOfKeyStatement(tenant, key did.DID) store.Statement
	// PutForKeysStatement returns the write that stores the delegations whose
	// audience is an access key when the statement runs, for a task that
	// issues grants in its own commit: a key deleted since the task listed
	// the keys is left with none. The filter is there for principal removal,
	// which deletes keys outside the tenant's task queue. The statement takes
	// no lock of its own. A task that issues grants to keys that exist
	// already runs it after the statements of
	// [Store.WithdrawKeyGrantsStatements] or
	// [Store.WithdrawGrantsOverStatements], which hold the keys' locks, in
	// the same transaction; a task that creates the key in the same commit
	// needs no lock, since no other writer sees the key until then. It
	// returns [store.ErrInvalidArgument] if the batch contains a nil
	// delegation.
	PutForKeysStatement(delegations []ucan.Delegation) (store.Statement, error)
}

// CheckReplacement refuses a replacement that holds a nil delegation or one
// filed under an audience other than its own, which would be written under an
// audience the call did not lock. The store calls it after next returns.
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
