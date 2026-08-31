// Package openbao wires the OpenBao-backed vault implementation into
// the application via uber-go/fx.
package openbao

import (
	"context"
	"fmt"

	"github.com/fil-forge/hilt/pkg/config"
	hiltvault "github.com/fil-forge/hilt/pkg/vault"
	vaultopenbao "github.com/fil-forge/hilt/pkg/vault/openbao"
	api "github.com/openbao/openbao/api/v2"
	"go.uber.org/fx"
	"go.uber.org/zap"
)

// Module provides the OpenBao-backed vault implementation.
var Module = fx.Module("openbao-vault",
	fx.Provide(NewVault),
)

// NewVault builds an OpenBao-backed vault from configuration and
// authenticates the client on startup (via token or AppRole). With AppRole,
// the store also logs in again and retries once when OpenBao rejects the
// token with 403, which is what an expired token looks like.
func NewVault(cfg config.OpenBaoConfig, logger *zap.Logger, lc fx.Lifecycle) (hiltvault.Vault, error) {
	if cfg.Address == "" {
		return nil, fmt.Errorf("vault.openbao.address is required when vault.type is %q", config.VaultTypeOpenBao)
	}
	clientCfg := api.DefaultConfig()
	clientCfg.Address = cfg.Address
	client, err := api.NewClient(clientCfg)
	if err != nil {
		return nil, fmt.Errorf("creating vault client: %w", err)
	}
	mount := cfg.Mount
	if mount == "" {
		mount = "secret"
	}

	login, refreshable, err := loginFunc(client, cfg)
	if err != nil {
		return nil, err
	}

	// Authenticate on start so network/auth happens at startup rather than at
	// construction (mirrors the postgres pool lifecycle).
	lc.Append(fx.Hook{OnStart: login})

	var reauth func(context.Context) error
	if refreshable {
		reauth = func(ctx context.Context) error {
			logger.Warn("openbao rejected the vault token; logging in again via approle")
			return login(ctx)
		}
	}

	return vaultopenbao.New(client, mount, reauth), nil
}

// loginFunc validates the auth configuration and returns the login function
// for the configured method. refreshable reports whether calling login again
// yields a new token (AppRole); a static token cannot be refreshed.
func loginFunc(client *api.Client, cfg config.OpenBaoConfig) (login func(context.Context) error, refreshable bool, err error) {
	switch cfg.AuthMethod {
	case config.VaultAuthToken, "":
		if cfg.Token == "" {
			return nil, false, fmt.Errorf("vault.openbao.token is required when vault.openbao.auth_method is %q", config.VaultAuthToken)
		}
		return func(context.Context) error {
			client.SetToken(cfg.Token)
			return nil
		}, false, nil
	case config.VaultAuthAppRole:
		if cfg.AppRole.RoleID == "" || cfg.AppRole.SecretID == "" {
			return nil, false, fmt.Errorf("vault.openbao.approle.role_id and secret_id are required when vault.openbao.auth_method is %q", config.VaultAuthAppRole)
		}
		mount := cfg.AppRole.Mount
		if mount == "" {
			mount = "approle"
		}
		return func(ctx context.Context) error {
			return vaultopenbao.AppRoleLogin(ctx, client, mount, cfg.AppRole.RoleID, cfg.AppRole.SecretID)
		}, true, nil
	default:
		return nil, false, fmt.Errorf("unknown vault.openbao.auth_method %q (valid: token, approle)", cfg.AuthMethod)
	}
}
