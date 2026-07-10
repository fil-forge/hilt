package tenant

import (
	"github.com/fil-forge/hilt/cmd/client/lib"
	"github.com/spf13/cobra"
)

var getCmd = &cobra.Command{
	Use:   "get <tenant-id>",
	Short: "Show a tenant",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		c, _, err := lib.InitManagementClient(cmd)
		if err != nil {
			return err
		}
		rec, err := c.GetTenant(cmd.Context(), args[0])
		if err != nil {
			return err
		}
		return lib.PrintJSON(cmd, rec)
	},
}
