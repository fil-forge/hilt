package policy

import (
	"github.com/fil-forge/hilt/cmd/client/lib"
	"github.com/spf13/cobra"
)

var listCmd = &cobra.Command{
	Use:   "list <tenant-id> <user-id>",
	Short: "List the policies naming a principal",
	Long: "List every policy of the tenant with a statement naming the principal " +
		"or the wildcard.",
	Args: cobra.ExactArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		c, _, err := lib.InitManagementClient(cmd)
		if err != nil {
			return err
		}
		recs, err := c.ListPrincipalPolicies(cmd.Context(), args[0], args[1])
		if err != nil {
			return err
		}
		return lib.PrintJSON(cmd, recs)
	},
}

var accessCmd = &cobra.Command{
	Use:   "access <tenant-id> <user-id>",
	Short: "Show a principal's effective actions per bucket",
	Long: "Show the actions the principal holds on each bucket, computed from the " +
		"tenant's stored policies. Buckets it has no action on are omitted.",
	Args: cobra.ExactArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		c, _, err := lib.InitManagementClient(cmd)
		if err != nil {
			return err
		}
		buckets, err := c.GetPrincipalAccess(cmd.Context(), args[0], args[1])
		if err != nil {
			return err
		}
		return lib.PrintJSON(cmd, buckets)
	},
}
