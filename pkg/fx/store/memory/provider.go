// Package memory wires the in-memory store implementations into the
// application via uber-go/fx.
package memory

import (
	"github.com/fil-forge/hilt/pkg/store/accesskey"
	memaccesskey "github.com/fil-forge/hilt/pkg/store/accesskey/memory"
	"github.com/fil-forge/hilt/pkg/store/bucket"
	membucket "github.com/fil-forge/hilt/pkg/store/bucket/memory"
	"github.com/fil-forge/hilt/pkg/store/bucketpolicy"
	membucketpolicy "github.com/fil-forge/hilt/pkg/store/bucketpolicy/memory"
	"github.com/fil-forge/hilt/pkg/store/delegation"
	memdelegation "github.com/fil-forge/hilt/pkg/store/delegation/memory"
	"github.com/fil-forge/hilt/pkg/store/principal"
	memprincipal "github.com/fil-forge/hilt/pkg/store/principal/memory"
	"github.com/fil-forge/hilt/pkg/store/provider"
	memprovider "github.com/fil-forge/hilt/pkg/store/provider/memory"
	"github.com/fil-forge/hilt/pkg/store/tenant"
	memtenant "github.com/fil-forge/hilt/pkg/store/tenant/memory"
	"github.com/fil-forge/hilt/pkg/store/usage"
	memusage "github.com/fil-forge/hilt/pkg/store/usage/memory"
	"github.com/fil-forge/hilt/pkg/store/wrapkey"
	memwrapkey "github.com/fil-forge/hilt/pkg/store/wrapkey/memory"
	"go.uber.org/fx"
)

// Module provides the in-memory store implementations.
var Module = fx.Module("memory-store",
	fx.Provide(
		// The key store refuses a principal the principal store has removed,
		// and a disabled tenant, as the Postgres insert's row locks do.
		fx.Annotate(func(principals *memprincipal.Store, tenants tenant.Store) *memaccesskey.Store {
			return memaccesskey.New(memaccesskey.WithPrincipals(principals.WithLive), memaccesskey.WithTenants(tenants))
		}, fx.As(new(accesskey.Store))),
		fx.Annotate(membucket.New, fx.As(new(bucket.Store)), fx.As(fx.Self())),
		fx.Annotate(memdelegation.New, fx.As(new(delegation.Store))),
		// The policy store refuses a bucket the bucket store does not hold,
		// as the Postgres backend's bucket lock does.
		fx.Annotate(func(buckets *membucket.Store) *membucketpolicy.Store {
			return membucketpolicy.New(membucketpolicy.WithBuckets(buckets.Has))
		}, fx.As(new(bucketpolicy.Store))),
		fx.Annotate(memprincipal.New, fx.As(new(principal.Store)), fx.As(fx.Self())),
		fx.Annotate(memprovider.New, fx.As(new(provider.Store))),
		// Deleting a tenant drops what the bucket and usage stores keep for
		// it, as the Postgres backend's foreign keys do.
		fx.Annotate(func(buckets *membucket.Store, counts *memusage.Store) *memtenant.Store {
			return memtenant.New(memtenant.WithOnDelete(buckets.ForgetTenant), memtenant.WithOnDelete(counts.ForgetTenant))
		}, fx.As(new(tenant.Store))),
		fx.Annotate(memusage.New, fx.As(new(usage.Store)), fx.As(fx.Self())),
		fx.Annotate(memwrapkey.New, fx.As(new(wrapkey.Store))),
	),
)
