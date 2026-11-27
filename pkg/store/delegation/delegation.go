package delegation

import (
	"context"
	"time"

	"github.com/fil-forge/hilt/pkg/store"
	"github.com/fil-forge/ucantone/did"
	"github.com/fil-forge/ucantone/ucan"
	"github.com/ipfs/go-cid"
)

type Store interface {
	// ListByAudience retrieves a paginated list of delegation records for a given
	// audience.
	ListByAudience(ctx context.Context, audience did.DID, opts ...store.PaginationOption) (store.Page[ucan.Delegation], error)
	// ProofChain recursively builds a proof chain of delegations from the given
	// audience to the given subject for the specified command. It returns the list
	// of delegations and their corresponding links in the order required for
	// invocation. i.e. starting from the root Delegation (issued by the Subject),
	// in strict sequence where the aud of the previous Delegation matches the iss
	// of the next Delegation. An expired delegation is in no chain, and of two
	// chains of the same length the one that lasts longer is returned, so a
	// key that holds a grant and its renewal is answered with the renewal. It
	// returns [store.ErrInvalidArgument] for an undef subject.
	ProofChain(ctx context.Context, aud did.DID, cmd ucan.Command, sub did.DID) ([]ucan.Delegation, []cid.Cid, error)
	// PutBatch stores a batch of delegation records in one transaction,
	// leaving one already stored alone. It returns [store.ErrInvalidArgument]
	// if the batch contains a nil delegation.
	PutBatch(ctx context.Context, delegation []ucan.Delegation) error
	// ListKeyGrants returns every delegation the tenant issued to one of its
	// access keys, for tenant deletion to revoke before the tenant's DID is
	// deactivated.
	ListKeyGrants(ctx context.Context, tenant did.DID) ([]ucan.Delegation, error)
	// WithdrawKeyGrantsStatement returns the write that takes every
	// delegation the tenant issued to one of its access keys out of the store
	// and records each as a revocation the tenant owes, for a task that
	// withdraws a tenant's grants in its own commit. The rows are chosen when
	// the statement runs, so the task withdraws what the keys hold at its
	// commit. A delegation the tenant did not issue, such as a bucket's root
	// delegation to the tenant, is left alone.
	WithdrawKeyGrantsStatement(tenant did.DID) store.Statement
	// WithdrawGrantsOverStatement is [Store.WithdrawKeyGrantsStatement]
	// narrowed to the delegations over subject held by the tenant's access
	// keys that are bound to one of principals, for a task that changes what
	// those principals may do on one bucket in its own commit. The keys'
	// delegations over every other subject are left alone.
	WithdrawGrantsOverStatement(tenant, subject did.DID, principals []string) store.Statement
	// WithdrawGrantsOfKeyStatement is [Store.WithdrawKeyGrantsStatement]
	// narrowed to one access key, for a task that deletes the key in its own
	// commit: the delegations the tenant issued to the key leave the store
	// and are recorded as revocations the tenant owes.
	WithdrawGrantsOfKeyStatement(tenant, key did.DID) store.Statement
	// WithdrawSubjectStatements returns the writes, to run in order in one
	// transaction, that take every delegation over subject out of the store,
	// for a task that deletes the bucket subject names in its own commit.
	// Those the tenant issued, whoever holds them, are recorded as
	// revocations the tenant owes; the rest, the bucket's root delegation to
	// the tenant among them, are deleted and not revoked. Powerline
	// delegations, which carry no subject, are left alone.
	WithdrawSubjectStatements(tenant, subject did.DID) []store.Statement
	// PutStatement returns the write that stores the delegations, leaving
	// one already stored alone, for a task that issues grants in its own
	// commit. It returns [store.ErrInvalidArgument] if the batch contains a
	// nil delegation.
	PutStatement(delegations []ucan.Delegation) (store.Statement, error)
	// DeleteTenantStatement returns the write that removes every delegation
	// of the tenant, for tenant deletion to run in its commit before the
	// rows of the tenant's keys and buckets go: those the tenant issued or
	// was issued, those its access keys hold, and those over its buckets. It
	// records no revocation.
	DeleteTenantStatement(tenant did.DID) store.Statement
	// TenantsWithGrantsDue returns the tenants that have an access key with a
	// grant due for renewal: the newest delegation the tenant issued to the
	// key for its subject and command expires before the given time. A
	// delegation that expires with its key is never due, since the next one
	// would expire with the key as well.
	TenantsWithGrantsDue(ctx context.Context, before time.Time) ([]did.DID, error)
	// KeysWithGrantsDue returns the tenant's access keys that have a grant
	// due for renewal, as [Store.TenantsWithGrantsDue] finds them.
	KeysWithGrantsDue(ctx context.Context, tenant did.DID, before time.Time) ([]did.DID, error)
	// DeleteExpired removes the delegations that expired before the given
	// time and returns how many it removed. An expired delegation is in no
	// proof chain and needs no revocation. A grant that is due for renewal
	// ([Store.TenantsWithGrantsDue]) is kept even once it has expired: it is
	// the record that its key should hold a grant, which a late renewal
	// issues from.
	DeleteExpired(ctx context.Context, before time.Time) (int64, error)
}
