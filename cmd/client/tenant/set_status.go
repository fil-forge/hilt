package tenant

import (
	"fmt"

	"github.com/fil-forge/hilt/cmd/client/lib"
	"github.com/fil-forge/hilt/pkg/api"
	"github.com/spf13/cobra"
)

var setStatusCmd = &cobra.Command{
	Use:   "set-status <tenant-id> <status>",
	Short: "Update a tenant's status",
	Long: fmt.Sprintf("Update a tenant's status to one of: %s, %s, %s.",
		api.TenantStatusActive, api.TenantStatusWriteLocked, api.TenantStatusDisabled),
	Args: cobra.ExactArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		tenantID := args[0]
		status := api.TenantStatus(args[1])
		switch status {
		case api.TenantStatusActive, api.TenantStatusWriteLocked, api.TenantStatusDisabled:
		default:
			return fmt.Errorf("invalid status %q: must be %s, %s or %s",
				args[1], api.TenantStatusActive, api.TenantStatusWriteLocked, api.TenantStatusDisabled)
		}
		c, _, err := lib.InitManagementClient(cmd)
		if err != nil {
			return err
		}
		if err := c.UpdateTenantStatus(cmd.Context(), tenantID, status); err != nil {
			return err
		}
		fmt.Fprintf(cmd.OutOrStdout(), "Set tenant %s status to %s\n", tenantID, status)
		return nil
	},
}
