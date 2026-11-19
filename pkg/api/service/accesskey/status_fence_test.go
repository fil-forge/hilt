package accesskey_test

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/fil-forge/hilt/pkg/s3perm"
	"github.com/fil-forge/hilt/pkg/store/accesskey"
	"github.com/fil-forge/hilt/pkg/store/tenant"
	"github.com/fil-forge/ucantone/ucan"
	"github.com/stretchr/testify/require"
)

type parkedKeyInsert struct {
	accesskey.Store
	reached, release chan struct{}
}

func (p *parkedKeyInsert) Add(ctx context.Context, in accesskey.Input) error {
	close(p.reached)
	select {
	case <-p.release:
		return p.Store.Add(ctx, in)
	case <-ctx.Done():
		return ctx.Err()
	}
}

func TestKeyCreationHoldsStatusFence(t *testing.T) {
	for _, postgres := range []bool{false, true} {
		t.Run(map[bool]string{false: "memory", true: "postgres"}[postgres], func(t *testing.T) {
			parked := &parkedKeyInsert{reached: make(chan struct{}), release: make(chan struct{})}
			wrap := func(s accesskey.Store) accesskey.Store { parked.Store = s; return parked }
			var d deps
			if postgres {
				d = setupPostgres(t, wrap)
			} else {
				d = setup(t, wrap)
			}
			var once sync.Once
			unblock := func() { once.Do(func() { close(parked.release) }) }
			defer unblock()
			finished := make(chan error, 1)
			go func() {
				_, _, err := d.svc.Create(t.Context(), "tenant-1", "pending-key", []string{"s3:GetObject", "s3:PutObject"}, nil, nil, nil)
				finished <- err
			}()
			<-parked.reached
			ctx, cancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
			defer cancel()
			require.Error(t, d.tenants.ChangeStatus(ctx, d.tenantID, tenant.WriteLocked, nil))
			unblock()
			require.NoError(t, <-finished)
			require.NoError(t, d.tenants.SetStatus(t.Context(), d.tenantID, tenant.WriteLocked))
		})
	}
}

func TestNewWriteLockedKeyStoresOnlyAllowedAuthority(t *testing.T) {
	d := setup(t)
	require.NoError(t, d.tenants.SetStatus(t.Context(), d.tenantID, tenant.WriteLocked))
	key, _, err := d.svc.Create(t.Context(), "tenant-1", "cleanup-key", []string{"s3:GetObject", "s3:DeleteObject", "s3:PutObject", "s3:DeleteBucketPolicy"}, nil, nil, nil)
	require.NoError(t, err)
	page, err := d.delegations.ListByAudience(t.Context(), key.ID)
	require.NoError(t, err)
	var commands []ucan.Command
	for _, d := range page.Results {
		commands = append(commands, d.Command())
	}
	require.ElementsMatch(t, s3perm.CommandsFor("s3:GetObject", "s3:DeleteObject"), commands)
	require.Contains(t, key.Permissions, "s3:PutObject", "configuration survives for restoration")
}
