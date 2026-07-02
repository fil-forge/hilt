package testutil

import (
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
)

// VaultRootToken is the dev-mode root token used by the throwaway Vault
// container created by CreateVault.
const VaultRootToken = "root"

// CreateVault starts a throwaway HashiCorp Vault dev-mode container (which
// auto-mounts a KV v2 engine at "secret") and returns its address and root
// token. The container is cleaned up when the test finishes.
func CreateVault(t *testing.T) (address, token string) {
	t.Helper()

	ctx := t.Context()
	req := testcontainers.ContainerRequest{
		Image:        "hashicorp/vault:1.15",
		ExposedPorts: []string{"8200/tcp"},
		Cmd:          []string{"server", "-dev"},
		Env: map[string]string{
			"VAULT_DEV_ROOT_TOKEN_ID":  VaultRootToken,
			"VAULT_DEV_LISTEN_ADDRESS": "0.0.0.0:8200",
		},
		WaitingFor: wait.ForLog("Vault server started!").WithStartupTimeout(30 * time.Second),
	}
	container, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
	require.NoError(t, err)
	testcontainers.CleanupContainer(t, container)

	host, err := container.Host(ctx)
	require.NoError(t, err)
	port, err := container.MappedPort(ctx, "8200/tcp")
	require.NoError(t, err)

	address = fmt.Sprintf("http://%s:%s", host, port.Port())
	t.Logf("Vault address: %s", address)
	return address, VaultRootToken
}
