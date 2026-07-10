package tenant

import (
	"github.com/fil-forge/hilt/cmd/client/lib"
	"github.com/fil-forge/hilt/pkg/api"
	"github.com/spf13/cobra"
)

var provisionCmd = &cobra.Command{
	Use:   "provision <tenant-id> <region>",
	Short: "Provision a tenant in a region",
	Long: "Provision the tenant with the given external ID in a region. " +
		"Provisioning is idempotent: an already-provisioned tenant is returned as-is.",
	Args: cobra.ExactArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		c, _, err := lib.InitManagementClient(cmd)
		if err != nil {
			return err
		}
		rec, err := c.ProvisionTenant(cmd.Context(), args[0], api.ProvisionTenantRequest{Region: args[1]})
		if err != nil {
			return err
		}
		return lib.PrintJSON(cmd, rec)
	},
}
