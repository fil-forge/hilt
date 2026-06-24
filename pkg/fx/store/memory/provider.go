// Package memory wires the in-memory store implementations into the
// application via uber-go/fx.
package memory

import (
	"github.com/fil-forge/hilt/pkg/store/accesskey"
	memaccesskey "github.com/fil-forge/hilt/pkg/store/accesskey/memory"
	"github.com/fil-forge/hilt/pkg/store/bucket"
	membucket "github.com/fil-forge/hilt/pkg/store/bucket/memory"
	"github.com/fil-forge/hilt/pkg/store/delegation"
	memdelegation "github.com/fil-forge/hilt/pkg/store/delegation/memory"
	"github.com/fil-forge/hilt/pkg/store/provider"
	memprovider "github.com/fil-forge/hilt/pkg/store/provider/memory"
	"github.com/fil-forge/hilt/pkg/store/tenant"
	memtenant "github.com/fil-forge/hilt/pkg/store/tenant/memory"
	"go.uber.org/fx"
)

// Module provides the in-memory store implementations.
var Module = fx.Module("memory-store",
	fx.Provide(
		NewAccessKeyStore,
		NewBucketStore,
		NewDelegationStore,
		NewProviderStore,
		NewTenantStore,
	),
)

func NewAccessKeyStore() accesskey.Store {
	return memaccesskey.New()
}

func NewBucketStore() bucket.Store {
	return membucket.New()
}

func NewDelegationStore() delegation.Store {
	return memdelegation.New()
}

func NewProviderStore() provider.Store {
	return memprovider.New()
}

func NewTenantStore() tenant.Store {
	return memtenant.New()
}
