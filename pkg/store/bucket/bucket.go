package bucket

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"time"

	"github.com/fil-forge/hilt/pkg/store"
	"github.com/fil-forge/ucantone/did"
)

// ErrConflictingFilters is returned by [Store.ListByTenant] when both [WithIDs]
// and [WithNames] are supplied.
var ErrConflictingFilters = errors.New("bucket: WithIDs and WithNames cannot be combined")

// nameRegexp mirrors the bucket_name_valid CHECK constraint: 3-63 characters,
// lowercase letters, digits, dots and hyphens, starting and ending with a
// letter or digit.
var nameRegexp = regexp.MustCompile(`^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$`)

// ValidateName checks that name is a valid bucket name. It returns
// [store.ErrInvalidArgument] if it is not.
func ValidateName(name string) error {
	if !nameRegexp.MatchString(name) {
		return fmt.Errorf("bucket name must be 3-63 lowercase letters, digits, dots or hyphens, starting and ending with a letter or digit: %w", store.ErrInvalidArgument)
	}
	return nil
}

type Record struct {
	// Identifier for the bucket.
	ID did.DID
	// Tenant the bucket belongs to.
	Tenant did.DID
	// Human readable name of the bucket.
	Name string
	// When the bucket record was created.
	CreatedAt time.Time
}

// ListConfig configures [Store.ListByTenant].
type ListConfig struct {
	store.PaginationConfig // promotes Cursor and Limit
	// IDs optionally restricts results to buckets with these IDs. When empty, no
	// ID filtering is applied.
	IDs []did.DID
	// Names optionally restricts results to buckets with these names. When empty,
	// no name filtering is applied. Must not be combined with IDs.
	Names []string
	// Prefix optionally restricts results to buckets whose name starts with it
	// (matched literally). When empty, no prefix filtering is applied.
	Prefix string
}

// ListOption configures a [ListConfig].
type ListOption func(*ListConfig)

// WithIDs restricts results to buckets with the given IDs. It must not be
// combined with [WithNames].
func WithIDs(ids ...did.DID) ListOption {
	return func(c *ListConfig) { c.IDs = ids }
}

// WithNames restricts results to buckets with the given names. It must not be
// combined with [WithIDs].
func WithNames(names ...string) ListOption {
	return func(c *ListConfig) { c.Names = names }
}

// WithPrefix restricts results to buckets whose name starts with the given
// prefix (matched literally).
func WithPrefix(prefix string) ListOption {
	return func(c *ListConfig) { c.Prefix = prefix }
}

// WithLimit sets the maximum number of results per page.
func WithLimit(limit int) ListOption {
	return func(c *ListConfig) { c.Limit = &limit }
}

// WithCursor sets the page cursor (the bucket name after which to start).
// Results resume strictly after it, whether or not a bucket with that exact
// name exists.
func WithCursor(cursor string) ListOption {
	return func(c *ListConfig) { c.Cursor = &cursor }
}

type Store interface {
	// Add creates a new bucket record. It returns [store.ErrInvalidArgument] if
	// the ID or tenant is undef or the name is not valid (see [ValidateName]),
	// and [store.ErrRecordExists] if a record with the same ID already exists.
	Add(ctx context.Context, id did.DID, tenant did.DID, name string) error
	// GetByName retrieves the bucket record for a given name. It returns
	// [store.ErrRecordNotFound] if no bucket exists with the specified name.
	GetByName(ctx context.Context, name string) (Record, error)
	// ListByTenant retrieves a paginated list of bucket records for a given
	// tenant in lexicographic name order, optionally filtered to a set of bucket
	// IDs (see [WithIDs]), names (see [WithNames]) or a name prefix (see
	// [WithPrefix]). Supplying both IDs and Names returns
	// [ErrConflictingFilters]. The cursor of a truncated page is the name of the
	// last record it includes (see [WithCursor]).
	ListByTenant(ctx context.Context, tenant did.DID, opts ...ListOption) (store.Page[Record], error)
	// Delete removes the bucket record for a given ID. It is idempotent:
	// deleting an absent record returns nil.
	Delete(ctx context.Context, id did.DID) error
}
