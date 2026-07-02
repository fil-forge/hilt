package hashicorp

import (
	"context"
	"fmt"

	vaultclient "github.com/hashicorp/vault-client-go"
	"github.com/hashicorp/vault-client-go/schema"
)

// AppRoleLogin authenticates the client against the AppRole auth method mounted
// at authMount using the given role and secret IDs, and sets the issued token
// on the client for subsequent requests. Role/secret IDs and the issued token
// are never logged.
func AppRoleLogin(ctx context.Context, client *vaultclient.Client, authMount, roleID, secretID string) error {
	resp, err := client.Auth.AppRoleLogin(ctx, schema.AppRoleLoginRequest{
		RoleId:   roleID,
		SecretId: secretID,
	}, vaultclient.WithMountPath(authMount))
	if err != nil {
		return fmt.Errorf("approle login: %w", err)
	}
	if resp.Auth == nil || resp.Auth.ClientToken == "" {
		return fmt.Errorf("approle login returned no client token")
	}
	if err := client.SetToken(resp.Auth.ClientToken); err != nil {
		return fmt.Errorf("setting client token: %w", err)
	}
	return nil
}
