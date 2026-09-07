package openbao

import (
	"context"
	"fmt"

	api "github.com/openbao/openbao/api/v2"
)

// AppRoleLogin authenticates the client against the AppRole auth method mounted
// at authMount using the given role and secret IDs, and sets the issued token
// on the client for subsequent requests. Role/secret IDs and the issued token
// are never logged.
func AppRoleLogin(ctx context.Context, client *api.Client, authMount, roleID, secretID string) error {
	resp, err := client.Logical().WriteWithContext(ctx, "auth/"+authMount+"/login", map[string]any{
		"role_id":   roleID,
		"secret_id": secretID,
	})
	if err != nil {
		return fmt.Errorf("approle login: %w", err)
	}
	if resp == nil || resp.Auth == nil || resp.Auth.ClientToken == "" {
		return fmt.Errorf("approle login returned no client token")
	}
	client.SetToken(resp.Auth.ClientToken)
	return nil
}
