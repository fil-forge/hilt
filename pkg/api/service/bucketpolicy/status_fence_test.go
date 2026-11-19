package bucketpolicy_test

import (
	"context"
	"sync"
	"testing"
	"time"

	bucketpolicysvc "github.com/fil-forge/hilt/pkg/api/service/bucketpolicy"
	"github.com/fil-forge/hilt/pkg/store/tenant"
	tenantmemory "github.com/fil-forge/hilt/pkg/store/tenant/memory"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

func TestPolicyRotationHoldsStatusFence(t *testing.T) {
	d := setup(t)
	d.principal(t, "alice")
	tenants := tenantmemory.New()
	require.NoError(t, tenants.Add(t.Context(), d.tenantID, "tenant-1", tenant.Active))
	parked := &parkedPolicies{Store: d.policies, reached: make(chan struct{}), resume: make(chan struct{})}
	svc := bucketpolicysvc.New(zap.NewNop(), tenants, d.buckets, d.principals, parked, d.rotator(d.swarf))
	var once sync.Once
	unblock := func() { once.Do(func() { close(parked.resume) }) }
	defer unblock()
	finished := make(chan error, 1)
	go func() {
		_, _, err := svc.Write(t.Context(), d.tenantID, d.photos, "photos", doc(allow(only("alice"), "s3:GetObject", "s3:PutObject")))
		finished <- err
	}()
	<-parked.reached
	ctx, cancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
	defer cancel()
	require.Error(t, tenants.ChangeStatus(ctx, d.tenantID, tenant.WriteLocked, nil))
	unblock()
	require.NoError(t, <-finished)
}

func TestWriteLockedPolicyRotationKeepsConfiguredPolicy(t *testing.T) {
	d := setup(t)
	d.principal(t, "alice")
	tenants := tenantmemory.New()
	require.NoError(t, tenants.Add(t.Context(), d.tenantID, "tenant-1", tenant.WriteLocked))
	svc := bucketpolicysvc.New(zap.NewNop(), tenants, d.buckets, d.principals, d.policies, d.rotator(d.swarf))
	wanted := doc(allow(only("alice"), "s3:GetObject", "s3:PutObject"))
	_, _, err := svc.Write(t.Context(), d.tenantID, d.photos, "photos", wanted)
	require.NoError(t, err)
	for key := range d.keys {
		require.Equal(t, commandsFor("s3:GetObject"), d.over(t, key, d.photos))
	}
	stored, err := d.policies.Get(t.Context(), d.photos)
	require.NoError(t, err)
	require.Equal(t, wanted, stored.Policy)
}
