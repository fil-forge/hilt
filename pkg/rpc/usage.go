package rpc

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/fil-forge/hilt/pkg/store"
	"github.com/fil-forge/hilt/pkg/store/bucket"
	usagestore "github.com/fil-forge/hilt/pkg/store/usage"
	"github.com/fil-forge/libforge/commands/s3/usage"
	"github.com/fil-forge/ucantone/binding"
	"github.com/fil-forge/ucantone/did"
	ucanerrors "github.com/fil-forge/ucantone/errors"
	"github.com/fil-forge/ucantone/server"
	"go.uber.org/zap"
)

// MaxReportCounts is the most counts one usage report may carry, across all
// its buckets and both kinds of count. A gateway with more to report sends
// several.
const MaxReportCounts = 8192

// Error names for a usage report that is refused whole, exported so callers
// can match on the stable Name() of a serialized failure.
const (
	InvalidUsageReportErrorName = "InvalidUsageReport"
	TooManyCountsErrorName      = "TooManyCounts"
)

var (
	// ErrInvalidUsageReport is returned for a report that is not well formed:
	// an hour that is not a whole hour, a count too large to hold, or a
	// bucket or hour named twice among the counts of one kind.
	ErrInvalidUsageReport = ucanerrors.New(InvalidUsageReportErrorName, "the usage report is not well formed")
	// ErrTooManyCounts is returned for a report carrying more than
	// [MaxReportCounts] counts.
	ErrTooManyCounts = ucanerrors.New(TooManyCountsErrorName, fmt.Sprintf("a usage report may carry at most %d counts", MaxReportCounts))
)

// BucketOwners is the subset of the bucket store the usage report needs.
type BucketOwners interface {
	Owner(ctx context.Context, id did.DID) (bucket.Owner, error)
}

// NewReportUsageHandler handles /s3/usage/report — a gateway's own counts of
// what it did and what it holds: the bytes it sent to its clients from each
// bucket in each hour, and the objects each bucket has gained and lost. The
// gateway invokes it on its own authority, so the route is served behind the
// check that the issuer is a registered provider (see pkg/fx); what is
// checked here is that each bucket is one that provider serves.
func NewReportUsageHandler(logger *zap.Logger, buckets bucket.Store, counts usagestore.Store) server.Route {
	log := logger.With(zap.Stringer("command", usage.Report.Command))
	return usage.Report.Route(func(req *binding.Request[*usage.ReportArguments], res *binding.Response[*usage.ReportOK]) error {
		issuer := req.Invocation().Issuer()
		ok, err := ReportUsage(req.Context(), log, buckets, counts, issuer, req.Task().Arguments())
		if err != nil {
			log.Error("usage report failed", zap.Stringer("provider", issuer), zap.Error(err))
			if errors.Is(err, ErrInvalidUsageReport) || errors.Is(err, ErrTooManyCounts) {
				return res.SetFailure(err)
			}
			return err
		}
		return res.SetSuccess(ok)
	})
}

// ReportUsage stores the counts a provider reported and returns a warning for
// each bucket whose counts it did not store.
//
// One count that cannot be used does not fail the report: the counts for a
// bucket no record was ever kept of ([usage.UnknownBucketWarningName]), or
// one another provider serves ([usage.BucketRegionMismatchWarningName]), are
// left out, with one warning naming the bucket and the reason however many of
// its counts the report carried, and the rest are stored. The gateway then
// stops sending those counts, where failing the report would have it resend
// them, and everything queued behind them, without end. A deleted bucket is
// not left out: its last hours are reported after it has gone.
//
// A report is refused whole, as [ErrInvalidUsageReport] or [ErrTooManyCounts],
// only when it is not well formed. Every count is checked for that, those of
// a bucket that would be left out included.
//
// The egress is stored before the object counts, each together or not at
// all. A report that fails between the two is one the gateway sends again,
// and storing a count twice changes nothing.
func ReportUsage(ctx context.Context, log *zap.Logger, buckets BucketOwners, counts usagestore.Store, provider did.DID, args *usage.ReportArguments) (*usage.ReportOK, error) {
	total := 0
	for _, space := range args.Egress {
		total += len(space.Hours)
	}
	for _, space := range args.Objects {
		total += len(space.Hours)
	}
	if total > MaxReportCounts {
		return nil, ErrTooManyCounts
	}

	allEgress := make([]usagestore.EgressCount, 0, total)
	for _, space := range args.Egress {
		for _, h := range space.Hours {
			allEgress = append(allEgress, usagestore.EgressCount{Bucket: space.Space, Hour: time.Unix(h.Hour, 0).UTC(), Bytes: h.Bytes})
		}
	}
	if err := usagestore.ValidateCounts(allEgress); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidUsageReport, err)
	}
	allObjects := make([]usagestore.ObjectCount, 0, total)
	for _, space := range args.Objects {
		for _, h := range space.Hours {
			allObjects = append(allObjects, usagestore.ObjectCount{Bucket: space.Space, Hour: time.Unix(h.Hour, 0).UTC(), Added: h.Added, Removed: h.Removed})
		}
	}
	if err := usagestore.ValidateObjectCounts(allObjects); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidUsageReport, err)
	}

	// A bucket is looked up once, and warned about once, whichever of the
	// report's counts name it. tenants holds the buckets whose counts are
	// stored, and skipped those already warned about.
	warnings := []usage.Warning{}
	tenants := map[did.DID]did.DID{}
	skipped := map[did.DID]struct{}{}
	tenantOf := func(space did.DID) (did.DID, bool, error) {
		if tenant, ok := tenants[space]; ok {
			return tenant, true, nil
		}
		if _, ok := skipped[space]; ok {
			return did.Undef, false, nil
		}
		owner, err := buckets.Owner(ctx, space)
		switch {
		case errors.Is(err, store.ErrRecordNotFound):
			log.Warn("skipping usage for an unknown bucket",
				zap.Stringer("provider", provider), zap.Stringer("bucket", space))
			warnings = append(warnings, usage.Warning{
				Name:    usage.UnknownBucketWarningName,
				Message: "no bucket has this space, so its counts were not stored",
				Space:   space,
			})
		case err != nil:
			return did.Undef, false, fmt.Errorf("looking up the owner of bucket %s: %w", space, err)
		case owner.Provider != provider:
			log.Warn("skipping usage for a bucket another provider serves",
				zap.Stringer("provider", provider), zap.Stringer("bucket", space),
				zap.Stringer("bucket_provider", owner.Provider))
			warnings = append(warnings, usage.Warning{
				Name:    usage.BucketRegionMismatchWarningName,
				Message: "another provider serves this space's bucket, so its counts were not stored",
				Space:   space,
			})
		default:
			tenants[space] = owner.Tenant
			return owner.Tenant, true, nil
		}
		skipped[space] = struct{}{}
		return did.Undef, false, nil
	}

	egress := make([]usagestore.EgressCount, 0, len(allEgress))
	for _, c := range allEgress {
		tenant, ok, err := tenantOf(c.Bucket)
		if err != nil {
			return nil, err
		}
		if ok {
			c.Tenant = tenant
			egress = append(egress, c)
		}
	}
	objects := make([]usagestore.ObjectCount, 0, len(allObjects))
	for _, c := range allObjects {
		tenant, ok, err := tenantOf(c.Bucket)
		if err != nil {
			return nil, err
		}
		if ok {
			c.Tenant = tenant
			objects = append(objects, c)
		}
	}

	if err := counts.SetEgress(ctx, provider, egress); err != nil {
		if errors.Is(err, store.ErrInvalidArgument) {
			return nil, fmt.Errorf("%w: %w", ErrInvalidUsageReport, err)
		}
		return nil, fmt.Errorf("storing egress counts: %w", err)
	}
	if err := counts.SetObjects(ctx, provider, objects); err != nil {
		if errors.Is(err, store.ErrInvalidArgument) {
			return nil, fmt.Errorf("%w: %w", ErrInvalidUsageReport, err)
		}
		return nil, fmt.Errorf("storing object counts: %w", err)
	}
	return &usage.ReportOK{Warnings: warnings}, nil
}
