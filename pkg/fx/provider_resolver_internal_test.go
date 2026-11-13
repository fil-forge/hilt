package fx

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/fil-forge/hilt/internal/testutil"
	providerstore "github.com/fil-forge/hilt/pkg/store/provider"
	providermemory "github.com/fil-forge/hilt/pkg/store/provider/memory"
	"github.com/fil-forge/ucantone/did"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

// countingProviders counts the reads of the provider store, fails them while
// err is set, and holds each one until release is closed when block is set.
type countingProviders struct {
	providerstore.Store
	lists int
	err   error
	// block makes a read announce itself on entered and wait for release.
	block   bool
	entered chan struct{}
	release chan struct{}
}

func (c *countingProviders) List(ctx context.Context) ([]providerstore.Record, error) {
	c.lists++
	if c.block {
		c.entered <- struct{}{}
		<-c.release
	}
	if c.err != nil {
		return nil, c.err
	}
	return c.Store.List(ctx)
}

// blockReads makes the next reads of the store wait until the returned
// function is called.
func (c *countingProviders) blockReads() (release func()) {
	c.block = true
	c.entered = make(chan struct{})
	c.release = make(chan struct{})
	return func() { close(c.release) }
}

// resolverFixture is a providerResolver over an in-memory provider store, a
// next resolver that counts its calls, and a clock the test moves.
type resolverFixture struct {
	resolver  *providerResolver
	providers *countingProviders
	resolved  int
	now       time.Time
}

func newResolverFixture(t *testing.T) *resolverFixture {
	t.Helper()
	f := &resolverFixture{
		providers: &countingProviders{Store: providermemory.New()},
		now:       time.Now(),
	}
	next := did.ResolverFunc(func(_ context.Context, d did.DID) (did.Document, error) {
		f.resolved++
		return did.NewDocument(d), nil
	})
	f.resolver = newProviderResolver(f.providers, next, zap.NewNop())
	f.resolver.now = func() time.Time { return f.now }
	return f
}

func TestProviderResolver(t *testing.T) {
	t.Run("resolves a registered provider", func(t *testing.T) {
		f := newResolverFixture(t)
		provider := testutil.RandomDID(t)
		require.NoError(t, f.providers.Add(t.Context(), provider, "us-east-1", nil))

		doc, err := f.resolver.Resolve(t.Context(), provider)
		require.NoError(t, err)
		require.Equal(t, provider, doc.ID)
		require.Equal(t, 1, f.resolved)
	})

	t.Run("refuses any other DID without calling the next resolver", func(t *testing.T) {
		f := newResolverFixture(t)
		require.NoError(t, f.providers.Add(t.Context(), testutil.RandomDID(t), "us-east-1", nil))

		_, err := f.resolver.Resolve(t.Context(), testutil.RandomDID(t))
		require.ErrorIs(t, err, errDIDNotPermitted)
		require.Zero(t, f.resolved)
	})

	t.Run("reads the store once per interval however many DIDs are refused", func(t *testing.T) {
		f := newResolverFixture(t)

		for range 100 {
			_, err := f.resolver.Resolve(t.Context(), testutil.RandomDID(t))
			require.ErrorIs(t, err, errDIDNotPermitted)
		}
		require.Equal(t, 1, f.providers.lists)

		f.now = f.now.Add(providerReloadInterval)
		_, err := f.resolver.Resolve(t.Context(), testutil.RandomDID(t))
		require.ErrorIs(t, err, errDIDNotPermitted)
		require.Equal(t, 2, f.providers.lists)
	})

	t.Run("resolves a known provider without reading the store", func(t *testing.T) {
		f := newResolverFixture(t)
		provider := testutil.RandomDID(t)
		require.NoError(t, f.providers.Add(t.Context(), provider, "us-east-1", nil))

		for range 3 {
			_, err := f.resolver.Resolve(t.Context(), provider)
			require.NoError(t, err)
		}
		require.Equal(t, 1, f.providers.lists)
	})

	t.Run("recognizes a provider registered later once the interval has passed", func(t *testing.T) {
		f := newResolverFixture(t)
		provider := testutil.RandomDID(t)

		_, err := f.resolver.Resolve(t.Context(), provider)
		require.ErrorIs(t, err, errDIDNotPermitted)

		require.NoError(t, f.providers.Add(t.Context(), provider, "us-east-1", nil))
		f.now = f.now.Add(providerReloadInterval - time.Second)
		_, err = f.resolver.Resolve(t.Context(), provider)
		require.ErrorIs(t, err, errDIDNotPermitted)

		f.now = f.now.Add(time.Second)
		_, err = f.resolver.Resolve(t.Context(), provider)
		require.NoError(t, err)
	})

	t.Run("keeps the known providers when a reload fails", func(t *testing.T) {
		f := newResolverFixture(t)
		provider := testutil.RandomDID(t)
		require.NoError(t, f.providers.Add(t.Context(), provider, "us-east-1", nil))
		_, err := f.resolver.Resolve(t.Context(), provider)
		require.NoError(t, err)

		f.providers.err = errors.New("store unavailable")
		f.now = f.now.Add(providerReloadInterval)
		_, err = f.resolver.Resolve(t.Context(), testutil.RandomDID(t))
		require.ErrorIs(t, err, errDIDNotPermitted)

		_, err = f.resolver.Resolve(t.Context(), provider)
		require.NoError(t, err)
	})

	t.Run("reloads even when the triggering request is cancelled", func(t *testing.T) {
		f := newResolverFixture(t)
		provider := testutil.RandomDID(t)
		require.NoError(t, f.providers.Add(t.Context(), provider, "us-east-1", nil))

		ctx, cancel := context.WithCancel(t.Context())
		cancel()
		_, err := f.resolver.Resolve(ctx, testutil.RandomDID(t))
		require.ErrorIs(t, err, errDIDNotPermitted)

		// Still inside the interval: the provider is known only if the reload
		// the cancelled request triggered went through.
		_, err = f.resolver.Resolve(t.Context(), provider)
		require.NoError(t, err)
		require.Equal(t, 1, f.providers.lists)
	})

	t.Run("resolves a known provider while a reload is in flight", func(t *testing.T) {
		f := newResolverFixture(t)
		provider := testutil.RandomDID(t)
		require.NoError(t, f.providers.Add(t.Context(), provider, "us-east-1", nil))
		_, err := f.resolver.Resolve(t.Context(), provider)
		require.NoError(t, err)

		// An unrecognized DID starts a reload, and the store does not answer.
		f.now = f.now.Add(providerReloadInterval)
		release := f.providers.blockReads()
		stranger := testutil.RandomDID(t)
		refused := make(chan error, 1)
		go func() {
			_, err := f.resolver.Resolve(context.Background(), stranger)
			refused <- err
		}()
		<-f.providers.entered

		resolved := make(chan error, 1)
		go func() {
			_, err := f.resolver.Resolve(context.Background(), provider)
			resolved <- err
		}()
		select {
		case err := <-resolved:
			require.NoError(t, err)
		case <-time.After(5 * time.Second):
			require.Fail(t, "a known provider waited for the reload")
		}

		release()
		require.ErrorIs(t, <-refused, errDIDNotPermitted)
	})

	t.Run("recognizes a provider that asks while the reload finding it is in flight", func(t *testing.T) {
		f := newResolverFixture(t)
		provider := testutil.RandomDID(t)
		require.NoError(t, f.providers.Add(t.Context(), provider, "us-east-1", nil))

		release := f.providers.blockReads()
		stranger := testutil.RandomDID(t)
		refused := make(chan error, 1)
		go func() {
			_, err := f.resolver.Resolve(context.Background(), stranger)
			refused <- err
		}()
		<-f.providers.entered

		resolved := make(chan error, 1)
		go func() {
			_, err := f.resolver.Resolve(context.Background(), provider)
			resolved <- err
		}()
		release()

		require.NoError(t, <-resolved)
		require.ErrorIs(t, <-refused, errDIDNotPermitted)
		require.Equal(t, 1, f.providers.lists)
	})
}
