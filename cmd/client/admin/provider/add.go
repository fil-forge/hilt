package provider

import (
	"fmt"

	"github.com/fil-forge/hilt/cmd/client/lib"
	"github.com/fil-forge/ucantone/did"
	"github.com/spf13/cobra"
)

var addCmd = &cobra.Command{
	Use:   "add <provider-did> <region>",
	Short: "Register a regional provider with Hilt",
	Long: "Register a regional provider (its DID and the region it serves).\n\n" +
		"This is an admin operation: it must be run with the Hilt service identity " +
		"config (identity.key_file / HILT_IDENTITY_KEY_FILE) so the signed invocation " +
		"is accepted by the server.",
	Args: cobra.ExactArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		providerID, err := did.Parse(args[0])
		if err != nil {
			return fmt.Errorf("parsing provider DID: %w", err)
		}
		region := args[1]

		c, _, err := lib.InitAdminClient(cmd)
		if err != nil {
			return err
		}
		if err := c.AddProvider(cmd.Context(), providerID, region); err != nil {
			return err
		}
		fmt.Fprintf(cmd.OutOrStdout(), "Registered provider %s for region %s\n", providerID, region)
		return nil
	},
}
