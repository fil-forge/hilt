package accesskey

import (
	"github.com/fil-forge/hilt/cmd/client/lib"
	"github.com/spf13/cobra"
)

var listCmd = &cobra.Command{
	Use:   "list <tenant-id>",
	Short: "List a tenant's access keys",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		c, _, err := lib.InitManagementClient(cmd)
		if err != nil {
			return err
		}
		recs, err := c.ListAccessKeys(cmd.Context(), args[0])
		if err != nil {
			return err
		}
		return lib.PrintJSON(cmd, recs)
	},
}
