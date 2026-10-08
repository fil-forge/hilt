// Package metrics provides the usage-metering business logic for the REST API:
// the storage and ingress series a tenant or one of its buckets accrued over a
// range of time.
//
// The readings come from the upload service (Sprue), which holds them per space.
// A bucket is a space, so a bucket's series is one call; a tenant's is the sum
// of its buckets'. It returns the known errors in errors.go so handlers can map
// them to HTTP responses; unexpected failures are returned wrapped for the
// handler to log.
package metrics

import (
	"context"
	"errors"
	"fmt"
	"math"
	"regexp"
	"slices"
	"strconv"
	"sync"
	"time"

	"github.com/fil-forge/hilt/pkg/client/upload"
	"github.com/fil-forge/hilt/pkg/store"
	"github.com/fil-forge/hilt/pkg/store/bucket"
	delegationstore "github.com/fil-forge/hilt/pkg/store/delegation"
	tenantstore "github.com/fil-forge/hilt/pkg/store/tenant"
	"github.com/fil-forge/hilt/pkg/vault"
	metricscmds "github.com/fil-forge/libforge/commands/metrics"
	"github.com/fil-forge/ucantone/did"
	"github.com/fil-forge/ucantone/multikey"
	"github.com/fil-forge/ucantone/multikey/secp256k1"
	"github.com/fil-forge/ucantone/ucan"
	"go.uber.org/zap"
	"golang.org/x/sync/errgroup"
)

// sampleConcurrency bounds the calls a tenant-wide query makes at once. A tenant
// holding many buckets would otherwise pay a round trip each, one after another,
// for a series consumers fetch on a schedule.
const sampleConcurrency = 8

// windowPattern is the window format the API accepts: a whole number of hours.
var windowPattern = regexp.MustCompile(`^([0-9]+)h$`)

// UsageSampler is the subset of the upload service (Sprue) the metrics
// operations need. It is satisfied by [*upload.Client]; the interface lets the
// logic be unit tested without a live Sprue.
type UsageSampler interface {
	SampleUsage(ctx context.Context, space did.DID, from, to time.Time, window time.Duration, opts ...upload.MethodOption) (*metricscmds.SampleOK, error)
}

// Sample is one bucket of a usage series.
type Sample struct {
	// End is the instant the bucket closes.
	End time.Time
	// BytesStored is the bytes held as of End.
	BytesStored uint64
	// BytesIngested is the bytes written during the bucket.
	BytesIngested uint64
	// ObjectCount is the objects held as of End.
	ObjectCount uint64
}

type Service struct {
	logger      *zap.Logger
	tenants     tenantstore.Store
	buckets     bucket.Store
	secrets     vault.Vault
	uploads     UsageSampler
	delegations delegationstore.Store
	now         func() time.Time
}

// Option configures the service.
type Option func(*Service)

// WithClock replaces the service's reading of the present, which bounds every
// range it answers. Tests use it to pin the instant a range is clamped against.
func WithClock(now func() time.Time) Option {
	return func(s *Service) {
		if now != nil {
			s.now = now
		}
	}
}

// New constructs the metrics service.
func New(
	logger *zap.Logger,
	tenants tenantstore.Store,
	buckets bucket.Store,
	secrets vault.Vault,
	uploads UsageSampler,
	delegations delegationstore.Store,
	opts ...Option,
) *Service {
	s := &Service{
		logger:      logger,
		tenants:     tenants,
		buckets:     buckets,
		secrets:     secrets,
		uploads:     uploads,
		delegations: delegations,
		now:         time.Now,
	}
	for _, opt := range opts {
		opt(s)
	}
	return s
}

// ParseRange validates the query as the API states it: RFC 3339 bounds with the
// end after the start, and a window of whole hours. It may return
// [ErrInvalidRange] or [ErrInvalidWindow].
//
// Bounds are resolved to whole seconds, which is the precision the upload
// service's range carries, and the ordering check runs on the resolved values.
// An interval finer than a second therefore reads as empty and is rejected here,
// with a reason the caller can act on, rather than being accepted and then
// collapsing to an inverted or empty range on the wire.
func ParseRange(from, to, window string) (time.Time, time.Time, time.Duration, error) {
	start, err := time.Parse(time.RFC3339, from)
	if err != nil {
		return time.Time{}, time.Time{}, 0, ErrInvalidRange
	}
	end, err := time.Parse(time.RFC3339, to)
	if err != nil {
		return time.Time{}, time.Time{}, 0, ErrInvalidRange
	}
	start, end = start.UTC().Truncate(time.Second), end.UTC().Truncate(time.Second)
	if !end.After(start) {
		return time.Time{}, time.Time{}, 0, ErrInvalidRange
	}

	match := windowPattern.FindStringSubmatch(window)
	if match == nil {
		return time.Time{}, time.Time{}, 0, ErrInvalidWindow
	}
	hours, err := strconv.ParseInt(match[1], 10, 64)
	if err != nil || hours <= 0 {
		return time.Time{}, time.Time{}, 0, ErrInvalidWindow
	}
	// Bounded so the multiplication below cannot overflow a duration; the
	// upload service rejects anything this wide anyway.
	if hours > math.MaxInt64/int64(time.Hour) {
		return time.Time{}, time.Time{}, 0, ErrInvalidWindow
	}
	return start, end, time.Duration(hours) * time.Hour, nil
}

// Bucket returns the usage series for one of the tenant's buckets. It may return
// [ErrTenantNotFound] or [ErrBucketNotFound], or a failure named by the upload
// service. A range starting in the future holds no samples yet and returns none.
func (s *Service) Bucket(ctx context.Context, externalID, bucketName string, from, to time.Time, window time.Duration) ([]Sample, error) {
	tenantRec, err := s.tenant(ctx, externalID)
	if err != nil {
		return nil, err
	}

	// Scoped to the tenant, so a name owned by another tenant simply does not
	// come back and reads as absent. GetByName is not tenant scoped and would
	// confirm the bucket exists before the ownership check could reject it.
	page, err := s.buckets.ListByTenant(ctx, tenantRec.ID, bucket.WithNames(bucketName))
	if err != nil {
		return nil, fmt.Errorf("listing buckets: %w", err)
	}
	if len(page.Results) == 0 {
		return nil, ErrBucketNotFound
	}

	end := s.clamp(to)
	if !end.After(from) {
		return []Sample{}, nil
	}

	issuer, err := s.tenantIssuer(ctx, tenantRec.ID)
	if err != nil {
		return nil, err
	}
	return s.sample(ctx, issuer, page.Results[0].ID, from, end, window)
}

// Tenant returns the usage series for every bucket the tenant holds, summed. It
// may return [ErrTenantNotFound], or a failure named by the upload service. A
// tenant holding no buckets, and a range starting in the future, each have
// nothing to report and return no samples.
func (s *Service) Tenant(ctx context.Context, externalID string, from, to time.Time, window time.Duration) ([]Sample, error) {
	tenantRec, err := s.tenant(ctx, externalID)
	if err != nil {
		return nil, err
	}

	// Clamped once, before the fan out. The upload service shortens a range
	// running past its own clock, so sampling each bucket against its own
	// reading of "now" would end their last buckets at different instants and
	// leave the sum carrying two nearly identical trailing samples.
	//
	// An emptied range is answered before the buckets are paged in, since the
	// answer is the same however many there are.
	end := s.clamp(to)
	if !end.After(from) {
		return []Sample{}, nil
	}

	buckets, err := store.Collect(ctx, func(ctx context.Context, opts store.PaginationConfig) (store.Page[bucket.Record], error) {
		var listOpts []bucket.ListOption
		if opts.Cursor != nil {
			listOpts = append(listOpts, bucket.WithCursor(*opts.Cursor))
		}
		return s.buckets.ListByTenant(ctx, tenantRec.ID, listOpts...)
	})
	if err != nil {
		return nil, fmt.Errorf("listing buckets: %w", err)
	}
	if len(buckets) == 0 {
		return []Sample{}, nil
	}

	issuer, err := s.tenantIssuer(ctx, tenantRec.ID)
	if err != nil {
		return nil, err
	}

	var mu sync.Mutex
	runs := make([][]Sample, len(buckets))

	group, ctx := errgroup.WithContext(ctx)
	group.SetLimit(sampleConcurrency)
	for i, b := range buckets {
		i, b := i, b
		group.Go(func() error {
			samples, err := s.sample(ctx, issuer, b.ID, from, end, window)
			if err != nil {
				return err
			}
			mu.Lock()
			defer mu.Unlock()
			runs[i] = samples
			return nil
		})
	}
	if err := group.Wait(); err != nil {
		return nil, err
	}

	return s.sum(runs), nil
}

// sample reads one space's series, signing as the tenant that owns it.
//
// The proof chain runs from the tenant to the bucket through the root the bucket
// issued when it was created, which lives in the delegation store. The client's
// own proofs are the static set loaded from configuration and hold nothing about
// a bucket, so the store has to be named per call.
func (s *Service) sample(ctx context.Context, issuer ucan.Issuer, space did.DID, from, to time.Time, window time.Duration) ([]Sample, error) {
	ok, err := s.uploads.SampleUsage(ctx, space, from, to, window,
		upload.WithIssuer(issuer), upload.WithProofs(s.delegations))
	if err != nil {
		return nil, err
	}
	samples := make([]Sample, 0, len(ok.Samples))
	for _, item := range ok.Samples {
		samples = append(samples, Sample{
			End:           time.Unix(item.Timestamp, 0).UTC(),
			BytesStored:   item.BytesStored,
			BytesIngested: item.BytesIngested,
			ObjectCount:   item.UploadCount,
		})
	}
	return samples, nil
}

// sum folds the buckets' series into the tenant's. Each bucket holds its own
// bytes and its own objects, so a tenant's usage at an instant is their total.
//
// The runs share a grid, having been asked for the same range and window, but
// they are keyed by timestamp rather than by position so a short run cannot
// shift the ones beside it.
//
// Only instants every run reached are reported. The upload service ends a range
// at its own clock, and every bucket but the last falls on the shared grid, so a
// run that was shortened differs from its siblings only in its tail. Summing
// those tails anyway would publish a timestamp carrying some of the tenant's
// buckets and call it the tenant's total, which reads as a drop in usage rather
// than as the missing reading it is.
func (s *Service) sum(runs [][]Sample) []Sample {
	totals := map[int64]Sample{}
	seen := map[int64]int{}
	for _, run := range runs {
		for _, smp := range run {
			at := smp.End.Unix()
			acc, ok := totals[at]
			if !ok {
				acc = Sample{End: smp.End}
			}
			acc.BytesStored += smp.BytesStored
			acc.BytesIngested += smp.BytesIngested
			acc.ObjectCount += smp.ObjectCount
			totals[at] = acc
			seen[at]++
		}
	}

	ends := make([]int64, 0, len(totals))
	for at, count := range seen {
		if count == len(runs) {
			ends = append(ends, at)
		}
	}
	slices.Sort(ends)

	if dropped := len(totals) - len(ends); dropped > 0 {
		// Reaching here means the upload service clamped some calls and not
		// others, which happens when this service's clock runs ahead of its.
		s.logger.Warn("tenant usage series trimmed to the instants every bucket reported",
			zap.Int("buckets", len(runs)),
			zap.Int("dropped", dropped))
	}

	samples := make([]Sample, 0, len(ends))
	for _, at := range ends {
		samples = append(samples, totals[at])
	}
	return samples
}

// clamp keeps the end of a range at or before the present, so every bucket of a
// tenant-wide query is asked for the same one.
//
// A range lying wholly in the future clamps to an end at or before its start.
// That is a well-formed question with no data to answer it yet, so callers
// return an empty series rather than asking the upload service, which would
// reject the inverted range as invalid.
func (s *Service) clamp(to time.Time) time.Time {
	// Truncated for the same reason the bounds are: the present carries
	// sub-second precision the wire does not, and an untruncated end could put
	// From and To in the same second.
	if now := s.now().UTC().Truncate(time.Second); to.After(now) {
		return now
	}
	return to
}

// tenant resolves the caller-facing id to the tenant record.
func (s *Service) tenant(ctx context.Context, externalID string) (tenantstore.Record, error) {
	rec, err := s.tenants.GetByExternalID(ctx, externalID)
	if errors.Is(err, store.ErrRecordNotFound) {
		return tenantstore.Record{}, ErrTenantNotFound
	} else if err != nil {
		return tenantstore.Record{}, fmt.Errorf("looking up tenant: %w", err)
	}
	return rec, nil
}

// tenantIssuer loads the tenant's secp256k1 signing key from the vault and
// returns an issuer that signs as the tenant. A bucket delegates authority over
// itself to its tenant, so the tenant is who the upload service expects to ask.
func (s *Service) tenantIssuer(ctx context.Context, tenantID did.DID) (ucan.Issuer, error) {
	keyBytes, err := s.secrets.Read(ctx, vault.TenantKeyPath(tenantID))
	if err != nil {
		return nil, fmt.Errorf("reading tenant key: %w", err)
	}
	signer, err := secp256k1.Decode(keyBytes)
	if err != nil {
		return nil, fmt.Errorf("decoding tenant key: %w", err)
	}
	return multikey.NewIssuer(tenantID, signer), nil
}
