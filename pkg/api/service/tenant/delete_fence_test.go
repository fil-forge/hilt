package tenant_test

import (
	"context"
	"testing"
	"time"

	"github.com/fil-forge/hilt/internal/testutil"
	tenantsvc "github.com/fil-forge/hilt/pkg/api/service/tenant"
	"github.com/fil-forge/hilt/pkg/store"
	"github.com/fil-forge/hilt/pkg/store/tenant"
	tenantmemory "github.com/fil-forge/hilt/pkg/store/tenant/memory"
	tenantpostgres "github.com/fil-forge/hilt/pkg/store/tenant/postgres"
	"github.com/stretchr/testify/require"
)

// Park after the initial disabled check but before the destructive PLC/cascade
// work. A restoration must not issue fresh roots or reopen key creation here.
func TestDeleteFencesConcurrentRestoration(t *testing.T) {
	for _, postgres := range []bool{false, true} {
		t.Run(map[bool]string{false: "memory", true: "postgres"}[postgres], func(t *testing.T) {
			var env deleteEnv
			if postgres {
				env = deleteSetup(t, tenant.Disabled, tenantpostgres.New(testutil.PostgresOrSkip(t)))
			} else {
				env = deleteSetup(t, tenant.Disabled)
			}
			env.directory.lookupStarted = make(chan struct{})
			env.directory.lookupRelease = make(chan struct{})
			finished := make(chan error, 1)
			go func() { finished <- env.svc.Delete(t.Context(), "tenant-1") }()
			<-env.directory.lookupStarted
			ctx, cancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
			defer cancel()
			restoreErr := env.svc.SetStatus(ctx, "tenant-1", "active")
			close(env.directory.lookupRelease)
			deleteErr := <-finished
			require.Error(t, restoreErr, "restoration crossed a destructive disabled-tenant cascade")
			require.NoError(t, deleteErr)
			_, err := env.tenants.Get(t.Context(), env.tenantID)
			require.ErrorIs(t, err, store.ErrRecordNotFound)
		})
	}
}

type restoredBeforeFence struct{ tenant.Store }

func (s restoredBeforeFence) GetByExternalID(ctx context.Context, id string) (tenant.Record, error) {
	rec, err := s.Store.GetByExternalID(ctx, id)
	if err == nil {
		err = s.Store.SetStatus(ctx, rec.ID, tenant.Active)
	}
	return rec, err
}

func TestDeleteRechecksDisabledAfterAcquiringFence(t *testing.T) {
	base := tenantmemory.New()
	env := deleteSetup(t, tenant.Disabled, restoredBeforeFence{base})
	require.ErrorIs(t, env.svc.Delete(t.Context(), "tenant-1"), tenantsvc.ErrTenantNotDisabled)
	require.Zero(t, env.directory.deactivations)
	rec, err := base.Get(t.Context(), env.tenantID)
	require.NoError(t, err)
	require.Equal(t, tenant.Active, rec.Status)
}
