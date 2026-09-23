package testutil

import (
	"context"
	"sync"

	"github.com/fil-forge/ucantone/did"
	"github.com/fil-forge/ucantone/ucan"
	"github.com/ipfs/go-cid"
)

// Revocation is one delegation a [FakeSwarf] was asked to revoke.
type Revocation struct {
	Revoker    did.DID
	Revoked    cid.Cid
	Delegation ucan.Delegation
}

// FakeSwarf stands in for the revocation service. It records every
// PublishBatch call, fails each one with Err while it is set, and runs
// OnPublish after each successful call.
type FakeSwarf struct {
	Err       error
	OnPublish func()

	mu      sync.Mutex
	batches [][]Revocation
}

func (f *FakeSwarf) PublishBatch(_ context.Context, revoker ucan.Issuer, revoked []ucan.Delegation) error {
	if f.Err != nil {
		return f.Err
	}
	b := make([]Revocation, 0, len(revoked))
	for _, d := range revoked {
		b = append(b, Revocation{Revoker: revoker.DID(), Revoked: d.Link(), Delegation: d})
	}
	f.mu.Lock()
	f.batches = append(f.batches, b)
	f.mu.Unlock()
	if f.OnPublish != nil {
		f.OnPublish()
	}
	return nil
}

// Reset forgets every recorded call.
func (f *FakeSwarf) Reset() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.batches = nil
}

// Calls is the number of PublishBatch calls that succeeded.
func (f *FakeSwarf) Calls() int { return len(f.Batches()) }

// Batches returns the revocations of each successful call, in call order.
func (f *FakeSwarf) Batches() [][]Revocation {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([][]Revocation(nil), f.batches...)
}

// Revocations returns every revocation across all calls.
func (f *FakeSwarf) Revocations() []Revocation {
	var out []Revocation
	for _, b := range f.Batches() {
		out = append(out, b...)
	}
	return out
}

// Revoked returns the CID of every revoked delegation across all calls.
func (f *FakeSwarf) Revoked() []cid.Cid {
	var out []cid.Cid
	for _, r := range f.Revocations() {
		out = append(out, r.Revoked)
	}
	return out
}
