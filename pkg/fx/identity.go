package fx

import (
	"fmt"

	"github.com/fil-forge/hilt/pkg/config"
	"github.com/fil-forge/libforge/identity"
	"go.uber.org/fx"
	"go.uber.org/zap"
)

// IdentityModule provides the Hilt service identity used by the UCAN RPC server.
var IdentityModule = fx.Module("identity",
	fx.Provide(NewIdentity),
)

// NewIdentity builds the service identity from configuration. With a key file
// it loads the PEM-encoded Ed25519 key (wrapping it with the configured did:web
// when set); otherwise it generates an ephemeral identity (whose DID changes
// each restart).
func NewIdentity(cfg config.IdentityConfig, logger *zap.Logger) (identity.Identity, error) {
	if cfg.KeyFile == "" {
		id, err := identity.New("", cfg.ServiceID)
		if err != nil {
			return identity.Identity{}, fmt.Errorf("creating ephemeral identity: %w", err)
		}
		logger.Warn("no identity.key_file configured; generated an ephemeral identity (DID changes each restart)",
			zap.Stringer("id", id.DID()),
		)
		return id, nil
	}

	id, err := identity.NewFromPEMFileWithDID(cfg.KeyFile, cfg.ServiceID)
	if err != nil {
		return identity.Identity{}, fmt.Errorf("loading identity from key file: %w", err)
	}
	logger.Info("loaded service identity from PEM",
		zap.Stringer("id", id.DID()),
		zap.String("key_file", cfg.KeyFile),
	)
	return id, nil
}
