package tenant_test

import (
	"context"
	"fmt"
	"testing"
	"time"

	tenantsvc "github.com/fil-forge/hilt/pkg/api/service/tenant"
	"github.com/fil-forge/hilt/pkg/grant"
	"github.com/fil-forge/hilt/pkg/store/accesskey"
	keymemory "github.com/fil-forge/hilt/pkg/store/accesskey/memory"
	bucketmemory "github.com/fil-forge/hilt/pkg/store/bucket/memory"
	policymemory "github.com/fil-forge/hilt/pkg/store/bucketpolicy/memory"
	delegationmemory "github.com/fil-forge/hilt/pkg/store/delegation/memory"
	principalmemory "github.com/fil-forge/hilt/pkg/store/principal/memory"
	"github.com/fil-forge/hilt/pkg/store/tenant"
	tenantmemory "github.com/fil-forge/hilt/pkg/store/tenant/memory"
	wrapmemory "github.com/fil-forge/hilt/pkg/store/wrapkey/memory"
	"github.com/fil-forge/hilt/pkg/vault"
	vaultmemory "github.com/fil-forge/hilt/pkg/vault/memory"
	"github.com/fil-forge/ucantone/multikey"
	"github.com/fil-forge/ucantone/multikey/ed25519"
	"github.com/fil-forge/ucantone/multikey/secp256k1"
	"github.com/fil-forge/ucantone/ucan"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

type cardinalityPublisher struct{ wait bool }

func (p cardinalityPublisher) PublishBatch(ctx context.Context, _ ucan.Issuer, _ []ucan.Delegation) error {
	if p.wait {
		<-ctx.Done()
	}
	return ctx.Err()
}

// Fixed-size local fixture only. The benchmark deliberately excludes Postgres,
// Swarf signing, wire encoding and network, so its timings are lower-bound work
// measurements, not production latency or a safe cardinality limit.
func cardinalityFixture(t testing.TB, count int, publisher grant.RevocationPublisher) (*tenantsvc.Service, *tenantmemory.Store) {
	t.Helper()
	ctx := context.Background()
	tenants, keys, dels := tenantmemory.New(), keymemory.New(), delegationmemory.New()
	secrets := vaultmemory.New()
	signer, err := secp256k1.Generate()
	require.NoError(t, err)
	id := signer.KeyDID()
	require.NoError(t, tenants.Add(ctx, id, "cardinality-fixture", tenant.Active))
	require.NoError(t, secrets.Write(ctx, vault.TenantKeyPath(id), signer.Bytes()))
	issuer := multikey.NewIssuer(id, signer)
	for i := 0; i < count; i++ {
		key, err := ed25519.Generate()
		require.NoError(t, err)
		perms := []string{"s3:GetObject", "s3:PutObject", "s3:DeleteObject"}
		require.NoError(t, keys.Add(ctx, accesskey.Input{ID: key.KeyDID(), Tenant: id, Name: fmt.Sprintf("synthetic-%d", i), Permissions: perms}))
		roots, err := grant.Issue(issuer, key.KeyDID(), nil, perms, nil)
		require.NoError(t, err)
		require.NoError(t, dels.PutBatch(ctx, roots))
	}
	return tenantsvc.New(zap.NewNop(), tenants, bucketmemory.New(), keys, principalmemory.New(), policymemory.New(), dels, secrets, wrapmemory.New(), nil, nil, publisher), tenants
}

func TestManyKeyRestrictionFailurePreservesPriorStatus(t *testing.T) {
	svc, tenants := cardinalityFixture(t, 256, cardinalityPublisher{wait: true})
	ctx, cancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
	defer cancel()
	require.ErrorIs(t, svc.SetStatus(ctx, "cardinality-fixture", "disabled"), context.DeadlineExceeded)
	rec, err := tenants.GetByExternalID(t.Context(), "cardinality-fixture")
	require.NoError(t, err)
	require.Equal(t, tenant.Active, rec.Status, "a failed all-or-nothing restriction leaves prior authority active")
}

func BenchmarkStatusCardinality(b *testing.B) {
	for _, count := range []int{128, 512, 2048} {
		b.Run(fmt.Sprintf("keys_%d", count), func(b *testing.B) {
			b.ReportAllocs()
			for range b.N {
				b.StopTimer()
				svc, tenants := cardinalityFixture(b, count, cardinalityPublisher{})
				b.StartTimer()
				err := svc.SetStatus(context.Background(), "cardinality-fixture", "write-locked")
				b.StopTimer()
				rec, getErr := tenants.GetByExternalID(context.Background(), "cardinality-fixture")
				require.NoError(b, getErr)
				if err != nil {
					require.Equal(b, tenant.Active, rec.Status)
					b.ReportMetric(1, "failed_transitions/op")
				} else {
					require.Equal(b, tenant.WriteLocked, rec.Status)
				}
				b.Logf("keys=%d roots=%d status=%s transition_failed=%t; memory/fake-publisher lower-bound only", count, count*7, rec.Status, err != nil)
			}
		})
	}
}
