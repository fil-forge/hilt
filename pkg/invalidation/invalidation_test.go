package invalidation_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/fil-forge/hilt/internal/testutil"
	"github.com/fil-forge/hilt/pkg/invalidation"
	"github.com/fil-forge/libforge/identity"
	"github.com/fil-forge/ucantone/did"
	"github.com/fil-forge/ucantone/ucan"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap/zaptest"
)

// fakeInvalidator records the calls made to it and returns a canned error.
type fakeInvalidator struct {
	calls       []invalidateCall
	deadline    time.Duration
	hasDeadline bool
	err         error
}

type invalidateCall struct {
	issuer    ucan.Issuer
	tenant    did.DID
	principal string
}

func (f *fakeInvalidator) Invalidate(ctx context.Context, issuer ucan.Issuer, tenant did.DID, principal string) error {
	f.calls = append(f.calls, invalidateCall{issuer: issuer, tenant: tenant, principal: principal})
	if deadline, ok := ctx.Deadline(); ok {
		f.hasDeadline = true
		f.deadline = time.Until(deadline)
	}
	return f.err
}

func TestSwarfPublisher(t *testing.T) {
	logger := zaptest.NewLogger(t)
	id, err := identity.New("", "")
	require.NoError(t, err)
	tenant := testutil.RandomDID(t)

	t.Run("publishes as the service identity", func(t *testing.T) {
		swarf := &fakeInvalidator{}
		p := invalidation.NewSwarfPublisher(logger, swarf, id)

		require.NoError(t, p.Invalidate(t.Context(), tenant, "user-1"))

		require.Len(t, swarf.calls, 1)
		require.Equal(t, tenant, swarf.calls[0].tenant)
		require.Equal(t, "user-1", swarf.calls[0].principal)
		require.Equal(t, id.DID(), swarf.calls[0].issuer.DID())
	})

	t.Run("bounds the call so a hung service fails the write", func(t *testing.T) {
		swarf := &fakeInvalidator{}
		p := invalidation.NewSwarfPublisher(logger, swarf, id)

		require.NoError(t, p.Invalidate(t.Context(), tenant, "user-1"))

		require.True(t, swarf.hasDeadline, "the publish must carry a deadline")
		require.Positive(t, swarf.deadline)
		require.LessOrEqual(t, swarf.deadline, invalidation.Timeout)
	})

	t.Run("keeps a caller deadline shorter than the timeout", func(t *testing.T) {
		swarf := &fakeInvalidator{}
		p := invalidation.NewSwarfPublisher(logger, swarf, id)

		ctx, cancel := context.WithTimeout(t.Context(), 20*time.Millisecond)
		defer cancel()
		require.NoError(t, p.Invalidate(ctx, tenant, "user-1"))

		require.True(t, swarf.hasDeadline)
		require.Less(t, swarf.deadline, invalidation.Timeout)
	})

	t.Run("returns the publish failure naming the principal", func(t *testing.T) {
		boom := errors.New("swarf unreachable")
		swarf := &fakeInvalidator{err: boom}
		p := invalidation.NewSwarfPublisher(logger, swarf, id)

		err := p.Invalidate(t.Context(), tenant, "user-1")

		require.ErrorIs(t, err, boom)
		require.ErrorContains(t, err, "user-1")
	})
}
