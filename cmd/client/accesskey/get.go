package accesskey

import (
	"github.com/fil-forge/hilt/cmd/client/lib"
	"github.com/spf13/cobra"
)

var getCmd = &cobra.Command{
	Use:   "get <tenant-id> <access-key-id>",
	Short: "Show one of a tenant's access keys",
	Args:  cobra.ExactArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		c, _, err := lib.InitManagementClient(cmd)
		if err != nil {
			return err
		}
		rec, err := c.GetAccessKey(cmd.Context(), args[0], args[1])
		if err != nil {
			return err
		}
		return lib.PrintJSON(cmd, rec)
	},
}
