package principal

import (
	"github.com/fil-forge/hilt/cmd/client/lib"
	"github.com/spf13/cobra"
)

var createCmd = &cobra.Command{
	Use:   "create <tenant-id> <user-id>",
	Short: "Record a principal of a tenant",
	Long: "Record a principal of a tenant. A principal holds no key material and no " +
		"delegation: its access is computed from the bucket policies naming it. " +
		"The call is idempotent.",
	Args: cobra.ExactArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		c, _, err := lib.InitManagementClient(cmd)
		if err != nil {
			return err
		}
		rec, err := c.CreatePrincipal(cmd.Context(), args[0], args[1])
		if err != nil {
			return err
		}
		return lib.PrintJSON(cmd, rec)
	},
}
