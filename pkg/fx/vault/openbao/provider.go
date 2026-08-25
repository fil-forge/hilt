// Package openbao wires the OpenBao-backed vault implementation into
// the application via uber-go/fx.
package openbao

import (
	"context"
	"fmt"

	"github.com/fil-forge/hilt/pkg/config"
	hiltvault "github.com/fil-forge/hilt/pkg/vault"
	vaultopenbao "github.com/fil-forge/hilt/pkg/vault/openbao"
	vaultclient "github.com/hashicorp/vault-client-go"
	"go.uber.org/fx"
)

// Module provides the OpenBao-backed vault implementation.
var Module = fx.Module("openbao-vault",
	fx.Provide(NewVault),
)

// NewVault builds an OpenBao-backed vault from configuration and
// authenticates the client on startup (via token or AppRole).
func NewVault(cfg config.OpenBaoConfig, lc fx.Lifecycle) (hiltvault.Vault, error) {
	if cfg.Address == "" {
		return nil, fmt.Errorf("vault.openbao.address is required when vault.type is %q", config.VaultTypeOpenBao)
	}
	client, err := vaultclient.New(vaultclient.WithAddress(cfg.Address))
	if err != nil {
		return nil, fmt.Errorf("creating vault client: %w", err)
	}
	mount := cfg.Mount
	if mount == "" {
		mount = "secret"
	}

	// Authenticate on start so network/auth happens at startup rather than at
	// construction (mirrors the postgres pool lifecycle).
	lc.Append(fx.Hook{
		OnStart: func(ctx context.Context) error {
			return authenticate(ctx, client, cfg)
		},
	})

	return vaultopenbao.New(client, mount), nil
}

func authenticate(ctx context.Context, client *vaultclient.Client, cfg config.OpenBaoConfig) error {
	switch cfg.AuthMethod {
	case config.VaultAuthToken, "":
		if cfg.Token == "" {
			return fmt.Errorf("vault.openbao.token is required when vault.openbao.auth_method is %q", config.VaultAuthToken)
		}
		if err := client.SetToken(cfg.Token); err != nil {
			return fmt.Errorf("setting vault token: %w", err)
		}
		return nil
	case config.VaultAuthAppRole:
		if cfg.AppRole.RoleID == "" || cfg.AppRole.SecretID == "" {
			return fmt.Errorf("vault.openbao.approle.role_id and secret_id are required when vault.openbao.auth_method is %q", config.VaultAuthAppRole)
		}
		mount := cfg.AppRole.Mount
		if mount == "" {
			mount = "approle"
		}
		return vaultopenbao.AppRoleLogin(ctx, client, mount, cfg.AppRole.RoleID, cfg.AppRole.SecretID)
	default:
		return fmt.Errorf("unknown vault.openbao.auth_method %q (valid: token, approle)", cfg.AuthMethod)
	}
}
