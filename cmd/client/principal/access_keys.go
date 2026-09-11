package principal

import (
	"github.com/fil-forge/hilt/cmd/client/lib"
	"github.com/spf13/cobra"
)

var listAccessKeysCmd = &cobra.Command{
	Use:   "access-keys <tenant-id> <user-id>",
	Short: "List the access keys bound to a principal",
	Args:  cobra.ExactArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		c, _, err := lib.InitManagementClient(cmd)
		if err != nil {
			return err
		}
		recs, err := c.ListPrincipalAccessKeys(cmd.Context(), args[0], args[1])
		if err != nil {
			return err
		}
		return lib.PrintJSON(cmd, recs)
	},
}
