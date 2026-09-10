package principal

import (
	"fmt"

	"github.com/fil-forge/hilt/cmd/client/lib"
	"github.com/spf13/cobra"
)

var deleteCmd = &cobra.Command{
	Use:   "delete <tenant-id> <user-id>",
	Short: "Remove a principal from a tenant",
	Long: "Remove a principal, its access to every bucket, and its access keys. " +
		"The call is idempotent.",
	Args: cobra.ExactArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		c, _, err := lib.InitManagementClient(cmd)
		if err != nil {
			return err
		}
		if err := c.DeletePrincipal(cmd.Context(), args[0], args[1]); err != nil {
			return err
		}
		fmt.Fprintf(cmd.OutOrStdout(), "Deleted principal %s\n", args[1])
		return nil
	},
}
