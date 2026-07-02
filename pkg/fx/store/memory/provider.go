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
		fx.Annotate(memaccesskey.New, fx.As(new(accesskey.Store))),
		fx.Annotate(membucket.New, fx.As(new(bucket.Store))),
		fx.Annotate(memdelegation.New, fx.As(new(delegation.Store))),
		fx.Annotate(memprovider.New, fx.As(new(provider.Store))),
		fx.Annotate(memtenant.New, fx.As(new(tenant.Store))),
	),
)
