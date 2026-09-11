package principal

import (
	"github.com/fil-forge/hilt/cmd/client/lib"
	"github.com/spf13/cobra"
)

var getCmd = &cobra.Command{
	Use:   "get <tenant-id> <user-id>",
	Short: "Show one of a tenant's principals",
	Args:  cobra.ExactArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		c, _, err := lib.InitManagementClient(cmd)
		if err != nil {
			return err
		}
		rec, err := c.GetPrincipal(cmd.Context(), args[0], args[1])
		if err != nil {
			return err
		}
		return lib.PrintJSON(cmd, rec)
	},
}
