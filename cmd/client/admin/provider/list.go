package provider

import (
	"github.com/fil-forge/hilt/cmd/client/lib"
	"github.com/spf13/cobra"
)

var listCmd = &cobra.Command{
	Use:     "list",
	Aliases: []string{"ls"},
	Short:   "List the regional providers registered with Hilt",
	Long: "List every regional provider registered with Hilt: its DID, the region it " +
		"serves and the routing policy carrying its storage nodes. A provider with no " +
		"policy has no storage nodes set and its region's buckets use default routing.\n\n" +
		"This is an admin operation: it must be run with the Hilt service identity " +
		"config (identity.key_file / HILT_IDENTITY_KEY_FILE) so the signed invocation " +
		"is accepted by the server.",
	Args: cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		c, _, err := lib.InitAdminClient(cmd)
		if err != nil {
			return err
		}
		res, err := c.ListProviders(cmd.Context())
		if err != nil {
			return err
		}

		if len(res.Providers) == 0 {
			cmd.Println("No providers registered")
			return nil
		}

		table := lib.NewTable(cmd.OutOrStdout())
		table.Header("ID", "Region", "Policy")
		for _, p := range res.Providers {
			policy := "-"
			if p.Policy != nil {
				policy = p.Policy.String()
			}
			if err := table.Append(p.Provider.String(), p.Region, policy); err != nil {
				return err
			}
		}
		return table.Render()
	},
}
