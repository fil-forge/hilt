package tenant

import (
	"github.com/fil-forge/hilt/cmd/client/lib"
	"github.com/spf13/cobra"
)

var provisionCmd = &cobra.Command{
	Use:   "provision <tenant-id>",
	Short: "Provision a tenant",
	Long: "Provision the tenant with the given external ID. A tenant is not bound to " +
		"a region: each of its buckets is served by the region it is created in. " +
		"Provisioning is idempotent: an already-provisioned tenant is returned as-is.",
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		c, _, err := lib.InitManagementClient(cmd)
		if err != nil {
			return err
		}
		rec, err := c.ProvisionTenant(cmd.Context(), args[0])
		if err != nil {
			return err
		}
		return lib.PrintJSON(cmd, rec)
	},
}
