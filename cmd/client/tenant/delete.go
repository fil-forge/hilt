package tenant

import (
	"fmt"

	"github.com/fil-forge/hilt/cmd/client/lib"
	"github.com/spf13/cobra"
)

var deleteCmd = &cobra.Command{
	Use:   "delete <tenant-id>",
	Short: "Delete a tenant and everything it owns",
	Long: "Delete a tenant, its buckets, access keys and delegations. " +
		"The tenant must be disabled first (see set-status). Deletion is idempotent.",
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		c, _, err := lib.InitManagementClient(cmd)
		if err != nil {
			return err
		}
		if err := c.DeleteTenant(cmd.Context(), args[0]); err != nil {
			return err
		}
		fmt.Fprintf(cmd.OutOrStdout(), "Deleted tenant %s\n", args[0])
		return nil
	},
}
