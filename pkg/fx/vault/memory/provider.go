// Package memory wires the in-memory vault implementation into the application
// via uber-go/fx.
package memory

import (
	"github.com/fil-forge/hilt/pkg/vault"
	vaultmemory "github.com/fil-forge/hilt/pkg/vault/memory"
	"go.uber.org/fx"
)

// Module provides the in-memory vault implementation.
var Module = fx.Module("memory-vault",
	fx.Provide(
		fx.Annotate(vaultmemory.New, fx.As(new(vault.Vault))),
	),
)
