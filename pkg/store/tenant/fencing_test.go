package tenant_test

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/fil-forge/hilt/pkg/store"
	"github.com/fil-forge/hilt/pkg/store/accesskey"
	keypostgres "github.com/fil-forge/hilt/pkg/store/accesskey/postgres"
	"github.com/fil-forge/hilt/pkg/store/tenant"
	tenantpostgres "github.com/fil-forge/hilt/pkg/store/tenant/postgres"
	"github.com/fil-forge/libforge/testutil"
	"github.com/stretchr/testify/require"
)

func TestTenantStatusFence(t *testing.T) {
	for _, kind := range storeKinds {
		t.Run(string(kind), func(t *testing.T) {
			s, _ := makeStore(t, kind)
			id, other := testutil.RandomDID(t), testutil.RandomDID(t)
			require.NoError(t, s.Add(t.Context(), id, "fenced", tenant.Active))
			require.NoError(t, s.Add(t.Context(), other, "control", tenant.Active))

			t.Run("callback failure retains the old status", func(t *testing.T) {
				failure := errors.New("publish unavailable")
				err := s.ChangeStatus(t.Context(), id, tenant.Disabled, func(ctx context.Context, previous tenant.Record) error {
					require.Equal(t, tenant.Active, previous.Status)
					return failure
				})
				require.ErrorIs(t, err, failure)
				rec, err := s.Get(t.Context(), id)
				require.NoError(t, err)
				require.Equal(t, tenant.Active, rec.Status)
			})

			t.Run("an authority writer excludes status changes but not another tenant", func(t *testing.T) {
				held, release, finished := make(chan struct{}), make(chan struct{}), make(chan error, 1)
				var once sync.Once
				unblock := func() { once.Do(func() { close(release) }) }
				defer unblock()
				go func() {
					finished <- s.WithReadLock(t.Context(), id, func(context.Context, tenant.Record) error {
						close(held)
						<-release
						return nil
					})
				}()
				<-held
				ctx, cancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
				defer cancel()
				err := s.ChangeStatus(ctx, id, tenant.Disabled, nil)
				require.Error(t, err)
				require.NoError(t, s.ChangeStatus(t.Context(), other, tenant.WriteLocked, nil))
				unblock()
				require.NoError(t, <-finished)
				require.NoError(t, s.ChangeStatus(t.Context(), id, tenant.Disabled, nil))
				require.NoError(t, s.WithReadLock(t.Context(), id, func(_ context.Context, current tenant.Record) error {
					require.Equal(t, tenant.Disabled, current.Status)
					return nil
				}))
			})
		})
	}
}

// The status callback must carry the outer transaction to authority stores:
// releasing their nested savepoint is not permission to commit independently.
func TestStatusCallbackAuthorityTransaction(t *testing.T) {
	pool := createPostgresPool(t)
	tenants, keys := tenantpostgres.New(pool), keypostgres.New(pool)
	id, keyID := testutil.RandomDID(t), testutil.RandomDID(t)
	require.NoError(t, tenants.Add(t.Context(), id, "transaction-fixture", tenant.Active))
	failure := errors.New("authority operation failed after nested write")
	err := tenants.ChangeStatus(t.Context(), id, tenant.WriteLocked, func(ctx context.Context, _ tenant.Record) error {
		require.NoError(t, keys.Add(ctx, accesskey.Input{ID: keyID, Tenant: id, Name: "rollback-key", Permissions: []string{"s3:GetObject"}}))
		return failure
	})
	require.ErrorIs(t, err, failure)
	_, err = keys.Get(t.Context(), keyID)
	require.ErrorIs(t, err, store.ErrRecordNotFound)
	current, err := tenants.Get(t.Context(), id)
	require.NoError(t, err)
	require.Equal(t, tenant.Active, current.Status)
	require.NoError(t, tenants.ChangeStatus(t.Context(), id, tenant.WriteLocked, func(ctx context.Context, _ tenant.Record) error {
		return keys.Add(ctx, accesskey.Input{ID: keyID, Tenant: id, Name: "committed-key", Permissions: []string{"s3:GetObject"}})
	}))
	_, err = keys.Get(t.Context(), keyID)
	require.NoError(t, err)
	current, err = tenants.Get(t.Context(), id)
	require.NoError(t, err)
	require.Equal(t, tenant.WriteLocked, current.Status)
}
