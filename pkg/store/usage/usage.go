// Package usage defines the store of the usage counts gateways report: the
// figures only a gateway knows, which the upload service cannot supply.
//
// It holds egress, the bytes of object data a gateway sent to its clients, by
// bucket and by hour. A count is a total for its hour, which only grows, so
// the store keeps the largest total reported for the hour: reports may be
// repeated, and may arrive in any order.
package usage

import (
	"context"
	"math"
	"time"

	"github.com/fil-forge/ucantone/did"
)

// MaxBytes is the largest count the store holds for one hour, and the largest
// total it returns: a sum that would exceed it is MaxBytes.
const MaxBytes uint64 = math.MaxInt64

// AddBytes returns the sum of two byte counts, or [MaxBytes] if the sum would
// exceed it.
func AddBytes(a, b uint64) uint64 {
	if a > MaxBytes || b > MaxBytes-a {
		return MaxBytes
	}
	return a + b
}

// EgressCount is the bytes a provider's gateway sent from one bucket in one
// hour.
type EgressCount struct {
	// Bucket the bytes were read from.
	Bucket did.DID
	// Tenant the bucket belongs to, or belonged to if it has been deleted.
	Tenant did.DID
	// Hour is the start of the hour. It must be a whole hour.
	Hour time.Time
	// Bytes sent in the hour so far. It must not exceed [MaxBytes].
	Bytes uint64
}

// HourlyEgress is the bytes sent in one hour.
type HourlyEgress struct {
	// Hour is the start of the hour, in UTC.
	Hour time.Time
	// Bytes sent in the hour.
	Bytes uint64
}

type Store interface {
	// SetEgress stores the counts a provider reported. A count larger than
	// the one the provider last reported for its bucket and hour takes its
	// place, and one that is not changes nothing. The counts are stored
	// together or not at all. It returns [store.ErrInvalidArgument] if
	// the provider, a bucket or a tenant is undef, an hour is not a whole
	// hour, a count exceeds [MaxBytes], or a bucket and hour appear twice.
	SetEgress(ctx context.Context, provider did.DID, counts []EgressCount) error
	// BucketEgress returns the bytes sent from a bucket in each hour starting
	// in [from, to), summed across providers, in ascending order. An hour
	// with no count is absent. A sum is at most [MaxBytes].
	BucketEgress(ctx context.Context, bucket did.DID, from, to time.Time) ([]HourlyEgress, error)
	// TenantEgress returns the bytes sent from a tenant's buckets, deleted
	// ones included, in each hour starting in [from, to), in ascending order.
	// An hour with no count is absent. A sum is at most [MaxBytes].
	TenantEgress(ctx context.Context, tenant did.DID, from, to time.Time) ([]HourlyEgress, error)
}

// Validate checks the counts of one report as [Store.SetEgress] states. It is
// shared by the backends so they refuse the same reports.
func Validate(provider did.DID, counts []EgressCount) error {
	if provider == did.Undef {
		return invalid("provider is required")
	}
	for _, c := range counts {
		if c.Tenant == did.Undef {
			return invalid("tenant is required")
		}
	}
	return ValidateCounts(counts)
}

// ValidateCounts checks what a report says of each bucket and hour, whoever
// the buckets belong to: every bucket is named, every hour is a whole hour,
// no count exceeds [MaxBytes], and no bucket and hour appear twice. A caller
// that stores only some of a report's counts checks all of them with it, so
// the report is refused for a fault in a count it would not have stored.
func ValidateCounts(counts []EgressCount) error {
	type key struct {
		bucket did.DID
		hour   int64
	}
	seen := make(map[key]struct{}, len(counts))
	for _, c := range counts {
		switch {
		case c.Bucket == did.Undef:
			return invalid("bucket is required")
		case !c.Hour.Equal(c.Hour.Truncate(time.Hour)):
			return invalid("hour must be a whole hour")
		case c.Bytes > MaxBytes:
			return invalid("count is too large")
		}
		k := key{c.Bucket, c.Hour.Unix()}
		if _, ok := seen[k]; ok {
			return invalid("a bucket and hour may appear once")
		}
		seen[k] = struct{}{}
	}
	return nil
}
