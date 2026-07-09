package accesskey

import (
	"fmt"

	"github.com/fil-forge/hilt/cmd/client/lib"
	"github.com/spf13/cobra"
)

var deleteCmd = &cobra.Command{
	Use:   "delete <tenant-id> <access-key-id>",
	Short: "Delete one of a tenant's access keys",
	Long:  "Delete an access key, its delegations and its vaulted signing key. Deletion is idempotent.",
	Args:  cobra.ExactArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		c, _, err := lib.InitManagementClient(cmd)
		if err != nil {
			return err
		}
		if err := c.DeleteAccessKey(cmd.Context(), args[0], args[1]); err != nil {
			return err
		}
		fmt.Fprintf(cmd.OutOrStdout(), "Deleted access key %s\n", args[1])
		return nil
	},
}
