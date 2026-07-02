package hashicorp_test

import (
	"context"
	"runtime"
	"testing"

	"github.com/fil-forge/hilt/internal/testutil"
	"github.com/fil-forge/hilt/pkg/vault"
	vaulthashicorp "github.com/fil-forge/hilt/pkg/vault/hashicorp"
	vaultclient "github.com/hashicorp/vault-client-go"
	"github.com/hashicorp/vault-client-go/schema"
	"github.com/stretchr/testify/require"
)

const appRolePolicy = `path "secret/*" { capabilities = ["create", "read", "update", "delete", "list"] }`

// setupAppRole enables the AppRole auth method on a dev Vault, creates a role
// bound to a policy granting access to secret/*, and returns the role's
// role_id and a fresh secret_id.
func setupAppRole(t *testing.T, address, rootToken string) (roleID, secretID string) {
	t.Helper()
	ctx := t.Context()

	admin, err := vaultclient.New(vaultclient.WithAddress(address))
	require.NoError(t, err)
	require.NoError(t, admin.SetToken(rootToken))

	_, err = admin.System.AuthEnableMethod(ctx, "approle", schema.AuthEnableMethodRequest{Type: "approle"})
	require.NoError(t, err)

	_, err = admin.System.PoliciesWriteAclPolicy(ctx, "hilt", schema.PoliciesWriteAclPolicyRequest{Policy: appRolePolicy})
	require.NoError(t, err)

	_, err = admin.Auth.AppRoleWriteRole(ctx, "hilt", schema.AppRoleWriteRoleRequest{
		TokenPolicies: []string{"hilt"},
	})
	require.NoError(t, err)

	roleResp, err := admin.Auth.AppRoleReadRoleId(ctx, "hilt")
	require.NoError(t, err)
	require.NotEmpty(t, roleResp.Data.RoleId)

	// Use the generic Write rather than the typed AppRoleWriteSecretId: the
	// v0.4.3 typed response models secret_id_ttl as a string but Vault returns a
	// number, which fails to unmarshal.
	secretResp, err := admin.Write(ctx, "auth/approle/role/hilt/secret-id", nil)
	require.NoError(t, err)
	secretID, ok := secretResp.Data["secret_id"].(string)
	require.True(t, ok, "secret_id missing from response")
	require.NotEmpty(t, secretID)

	return roleResp.Data.RoleId, secretID
}

func TestAppRoleLogin(t *testing.T) {
	if testutil.IsRunningInCI(t) && runtime.GOOS == "linux" {
		if !testutil.IsDockerAvailable(t) {
			t.Fatalf("docker is expected in CI linux testing environments, but wasn't found")
		}
	}
	if !testutil.IsDockerAvailable(t) {
		t.SkipNow()
	}

	address, rootToken := testutil.CreateVault(t)
	roleID, secretID := setupAppRole(t, address, rootToken)

	t.Run("logs in and yields a usable token", func(t *testing.T) {
		client, err := vaultclient.New(vaultclient.WithAddress(address))
		require.NoError(t, err)

		require.NoError(t, vaulthashicorp.AppRoleLogin(t.Context(), client, "approle", roleID, secretID))

		// The issued token must be able to read/write the KV engine.
		store := vaulthashicorp.New(client, "secret")
		require.NoError(t, store.Write(t.Context(), "/tenant/alice", []byte("secret")))
		got, err := store.Read(t.Context(), "/tenant/alice")
		require.NoError(t, err)
		require.Equal(t, []byte("secret"), got)
	})

	t.Run("fails with a bogus secret id", func(t *testing.T) {
		client, err := vaultclient.New(vaultclient.WithAddress(address))
		require.NoError(t, err)

		err = vaulthashicorp.AppRoleLogin(context.Background(), client, "approle", roleID, "not-a-real-secret-id")
		require.Error(t, err)
	})

	t.Run("login result satisfies the Vault interface", func(t *testing.T) {
		client, err := vaultclient.New(vaultclient.WithAddress(address))
		require.NoError(t, err)
		require.NoError(t, vaulthashicorp.AppRoleLogin(t.Context(), client, "approle", roleID, secretID))
		var _ vault.Vault = vaulthashicorp.New(client, "secret")
	})
}
