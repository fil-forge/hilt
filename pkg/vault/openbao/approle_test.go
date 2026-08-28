package openbao_test

import (
	"context"
	"net/http"
	"runtime"
	"testing"

	htestutil "github.com/fil-forge/hilt/internal/testutil"
	"github.com/fil-forge/hilt/pkg/vault"
	vaultopenbao "github.com/fil-forge/hilt/pkg/vault/openbao"
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
	if htestutil.IsRunningInCI(t) && runtime.GOOS == "linux" {
		if !htestutil.IsDockerAvailable(t) {
			t.Fatalf("docker is expected in CI linux testing environments, but wasn't found")
		}
	}
	if !htestutil.IsDockerAvailable(t) {
		t.SkipNow()
	}

	address, rootToken := htestutil.CreateVault(t)
	roleID, secretID := setupAppRole(t, address, rootToken)

	t.Run("logs in and yields a usable token", func(t *testing.T) {
		client, err := vaultclient.New(vaultclient.WithAddress(address))
		require.NoError(t, err)

		require.NoError(t, vaultopenbao.AppRoleLogin(t.Context(), client, "approle", roleID, secretID))

		// The issued token must be able to read/write the KV engine.
		store := vaultopenbao.New(client, "secret", nil)
		require.NoError(t, store.Write(t.Context(), "/tenant/alice", []byte("secret")))
		got, err := store.Read(t.Context(), "/tenant/alice")
		require.NoError(t, err)
		require.Equal(t, []byte("secret"), got)
	})

	t.Run("fails with a bogus secret id", func(t *testing.T) {
		client, err := vaultclient.New(vaultclient.WithAddress(address))
		require.NoError(t, err)

		err = vaultopenbao.AppRoleLogin(context.Background(), client, "approle", roleID, "not-a-real-secret-id")
		require.Error(t, err)
	})

	t.Run("login result satisfies the Vault interface", func(t *testing.T) {
		client, err := vaultclient.New(vaultclient.WithAddress(address))
		require.NoError(t, err)
		require.NoError(t, vaultopenbao.AppRoleLogin(t.Context(), client, "approle", roleID, secretID))
		var _ vault.Vault = vaultopenbao.New(client, "secret", nil)
	})

	// invalidateToken simulates an expired token: OpenBao answers a bogus
	// token with the same 403 as an expired one.
	invalidateToken := func(t *testing.T, client *vaultclient.Client) {
		t.Helper()
		require.NoError(t, client.SetToken("bogus-token"))
	}

	newLoggedInClient := func(t *testing.T) *vaultclient.Client {
		t.Helper()
		client, err := vaultclient.New(vaultclient.WithAddress(address))
		require.NoError(t, err)
		require.NoError(t, vaultopenbao.AppRoleLogin(t.Context(), client, "approle", roleID, secretID))
		return client
	}

	reauthWith := func(client *vaultclient.Client, secret string) func(context.Context) error {
		return func(ctx context.Context) error {
			return vaultopenbao.AppRoleLogin(ctx, client, "approle", roleID, secret)
		}
	}

	operations := map[string]func(ctx context.Context, store vault.Vault) error{
		"Write": func(ctx context.Context, store vault.Vault) error {
			return store.Write(ctx, "/tenant/reauth", []byte("secret"))
		},
		"Read": func(ctx context.Context, store vault.Vault) error {
			_, err := store.Read(ctx, "/tenant/reauth")
			return err
		},
		"Delete": func(ctx context.Context, store vault.Vault) error {
			return store.Delete(ctx, "/tenant/reauth")
		},
	}

	for _, name := range []string{"Write", "Read", "Delete"} {
		op := operations[name]
		t.Run(name+" re-logs in and succeeds after the token is invalidated", func(t *testing.T) {
			client := newLoggedInClient(t)
			store := vaultopenbao.New(client, "secret", reauthWith(client, secretID))
			// Seed the secret so Read has something to find.
			require.NoError(t, store.Write(t.Context(), "/tenant/reauth", []byte("secret")))

			invalidateToken(t, client)
			require.NoError(t, op(t.Context(), store))
		})
	}

	t.Run("without reauth the 403 propagates", func(t *testing.T) {
		client := newLoggedInClient(t)
		store := vaultopenbao.New(client, "secret", nil)

		invalidateToken(t, client)
		err := store.Write(t.Context(), "/tenant/noreauth", []byte("secret"))
		require.True(t, vaultclient.IsErrorStatus(err, http.StatusForbidden), "expected 403, got: %v", err)
	})

	t.Run("a failing reauth surfaces both the 403 and the login error", func(t *testing.T) {
		client := newLoggedInClient(t)
		store := vaultopenbao.New(client, "secret", reauthWith(client, "not-a-real-secret-id"))

		invalidateToken(t, client)
		err := store.Write(t.Context(), "/tenant/badreauth", []byte("secret"))
		require.Error(t, err)
		require.True(t, vaultclient.IsErrorStatus(err, http.StatusForbidden), "expected 403, got: %v", err)
		require.Contains(t, err.Error(), "re-login after 403 failed")
		require.Contains(t, err.Error(), "approle login")
	})
}
