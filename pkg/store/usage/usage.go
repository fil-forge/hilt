// Package usage defines the store of the usage counts gateways report: the
// figures only a gateway knows, which the upload service cannot supply.
//
// It holds egress, the bytes of object data a gateway sent to its clients, by
// bucket and by hour. A count is a total for its hour, and a later report for
// the same hour replaces it.
package usage

import (
	"context"
	"math"
	"time"

	"github.com/fil-forge/ucantone/did"
)

// MaxBytes is the largest count the store holds for one hour.
const MaxBytes uint64 = math.MaxInt64

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
	// SetEgress stores the counts a provider reported, each replacing the
	// count the provider last reported for its bucket and hour. The counts are
	// stored together or not at all. It returns [store.ErrInvalidArgument] if
	// the provider, a bucket or a tenant is undef, an hour is not a whole
	// hour, a count exceeds [MaxBytes], or a bucket and hour appear twice.
	SetEgress(ctx context.Context, provider did.DID, counts []EgressCount) error
	// BucketEgress returns the bytes sent from a bucket in each hour starting
	// in [from, to), summed across providers, in ascending order. An hour
	// with no count is absent.
	BucketEgress(ctx context.Context, bucket did.DID, from, to time.Time) ([]HourlyEgress, error)
	// TenantEgress returns the bytes sent from a tenant's buckets, deleted
	// ones included, in each hour starting in [from, to), in ascending order.
	// An hour with no count is absent.
	TenantEgress(ctx context.Context, tenant did.DID, from, to time.Time) ([]HourlyEgress, error)
}

// Validate checks the counts of one report as [Store.SetEgress] states. It is
// shared by the backends so they refuse the same reports.
func Validate(provider did.DID, counts []EgressCount) error {
	if provider == did.Undef {
		return invalid("provider is required")
	}
	type key struct {
		bucket did.DID
		hour   int64
	}
	seen := make(map[key]struct{}, len(counts))
	for _, c := range counts {
		switch {
		case c.Bucket == did.Undef:
			return invalid("bucket is required")
		case c.Tenant == did.Undef:
			return invalid("tenant is required")
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
