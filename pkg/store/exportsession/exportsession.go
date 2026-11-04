// Package exportsession defines the credible-exit export session: Hilt's record
// of one customer exporting one bucket to a key they hold (fil-one/RFC #24,
// Tier 1).
//
// Hilt owns the session and the customer-facing steps; the gateway serving the
// bucket performs the export and reports its own steps back. The record carries
// no key material: the customer key is a public key, and the pinned root is a
// CID.
package exportsession

import (
	"context"
	"time"

	"github.com/fil-forge/ucantone/did"
	"github.com/ipfs/go-cid"
)

// State is how far an export session has got. States only move forward, and
// [Aborted] is reachable from any open state.
type State string

const (
	// Opened is a new session: nothing about the customer key is verified yet.
	Opened State = "opened"
	// PoPVerified means the customer proved possession of the receiving key.
	PoPVerified State = "pop_verified"
	// Pinned means the gateway pinned a bucket root for the export.
	Pinned State = "pinned"
	// Acked means the customer acknowledged the (bucket, root, pinned-at) triple.
	Acked State = "acked"
	// ManifestBuilt means the gateway built and checked the key manifest.
	ManifestBuilt State = "manifest_built"
	// CarReady means the gateway materialized the exit CAR.
	CarReady State = "car_ready"
	// Validated means the customer validated the delivered artifact.
	Validated State = "validated"
	// Released is terminal: the export completed and the pin is lifted.
	Released State = "released"
	// Aborted is terminal: the session ended without an artifact.
	Aborted State = "aborted"
)

// next is the forward edge out of each open state.
var next = map[State]State{
	Opened:        PoPVerified,
	PoPVerified:   Pinned,
	Pinned:        Acked,
	Acked:         ManifestBuilt,
	ManifestBuilt: CarReady,
	CarReady:      Validated,
	Validated:     Released,
}

// Open reports whether s is a non-terminal state of the machine.
func (s State) Open() bool {
	_, ok := next[s]
	return ok
}

// ValidTransition reports whether from → to is an edge of the state machine: the
// single forward step out of an open state, or an abort from one. A state
// outside the machine has no edges.
func ValidTransition(from, to State) bool {
	n, ok := next[from]
	if !ok {
		return false
	}
	return to == Aborted || to == n
}

// Record is one export session.
type Record struct {
	// ID identifies the session. The gateway keys its own pin by the same ID.
	ID string
	// Tenant is the tenant DID (did:plc) the exported bucket belongs to.
	Tenant did.DID
	// Bucket is the DID of the bucket (space) being exported.
	Bucket did.DID
	// CustomerKey is the customer's X25519 receiving key, as a multikey string.
	CustomerKey string
	// State is how far the session has got.
	State State
	// Root is the pinned bucket root; undefined before [Pinned].
	Root cid.Cid
	// PinnedAt is when the root was pinned; zero before [Pinned].
	PinnedAt time.Time
	// Audit is the session's append-only event log, a JSON array.
	Audit []byte
	// CreatedAt is when the session was opened.
	CreatedAt time.Time
	// UpdatedAt is when the session last changed.
	UpdatedAt time.Time
	// ExpiresAt is when an open session becomes a candidate for abort.
	ExpiresAt time.Time
}

// Input is the data needed to open an export session.
type Input struct {
	// ID identifies the session.
	ID string
	// Tenant is the tenant DID (did:plc) the exported bucket belongs to.
	Tenant did.DID
	// Bucket is the DID of the bucket (space) being exported.
	Bucket did.DID
	// CustomerKey is the customer's X25519 receiving key, as a multikey string.
	CustomerKey string
	// ExpiresAt is when the session becomes a candidate for abort if still open.
	ExpiresAt time.Time
}

// Store persists export sessions.
type Store interface {
	// Add opens a session in [Opened]. It returns [store.ErrRecordExists] if a
	// session with the same ID exists, and [store.ErrInvalidArgument] for an
	// empty ID or customer key.
	Add(ctx context.Context, input Input) error
	// Get returns the session with the given ID. It returns
	// [store.ErrRecordNotFound] if there is none.
	Get(ctx context.Context, id string) (Record, error)
	// Transition moves a session from one state to the next iff it is currently
	// in from. It returns [store.ErrInvalidArgument] if from → to is not an edge
	// of the state machine, or if to is [Pinned] (use Pin), and
	// [store.ErrRecordNotFound] if no session with the ID is in from.
	Transition(ctx context.Context, id string, from, to State) error
	// Pin moves a session from [PoPVerified] to [Pinned], recording the pinned
	// bucket root and the time. It returns [store.ErrRecordNotFound] if no
	// session with the ID is in [PoPVerified].
	Pin(ctx context.Context, id string, root cid.Cid) error
	// AppendAudit appends one JSON value to the session's audit log. It returns
	// [store.ErrInvalidArgument] if entry is not JSON and
	// [store.ErrRecordNotFound] if there is no session with the ID.
	AppendAudit(ctx context.Context, id string, entry []byte) error
	// HasOpen reports whether the tenant has any open session.
	HasOpen(ctx context.Context, tenant did.DID) (bool, error)
	// HasOpenForBucket reports whether the bucket has any open session.
	HasOpenForBucket(ctx context.Context, bucket did.DID) (bool, error)
	// DeleteByTenant removes every session of a tenant. It is used by tenant
	// deletion, which refuses while a session is open, and is idempotent.
	DeleteByTenant(ctx context.Context, tenant did.DID) error
}
