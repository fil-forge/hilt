package nodes

import (
	"fmt"

	"github.com/fil-forge/hilt/cmd/client/lib"
	"github.com/fil-forge/ucantone/did"
	"github.com/spf13/cobra"
)

var setCmd = &cobra.Command{
	Use:   "set <provider-did> <node-did>...",
	Short: "Replace the storage nodes a registered provider operates",
	Long: "Replace the storage nodes a registered provider operates. The nodes become " +
		"the complete candidate set of the provider's routing policy on the upload service.\n\n" +
		"This is an admin operation: it must be run with the Hilt service identity " +
		"config (identity.key_file / HILT_IDENTITY_KEY_FILE) so the signed invocation " +
		"is accepted by the server.",
	Args: cobra.MinimumNArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		providerID, err := did.Parse(args[0])
		if err != nil {
			return fmt.Errorf("parsing provider DID: %w", err)
		}
		nodes := make([]did.DID, 0, len(args)-1)
		for _, a := range args[1:] {
			n, err := did.Parse(a)
			if err != nil {
				return fmt.Errorf("parsing node DID %q: %w", a, err)
			}
			nodes = append(nodes, n)
		}

		c, _, err := lib.InitAdminClient(cmd)
		if err != nil {
			return err
		}
		if err := c.SetProviderNodes(cmd.Context(), providerID, nodes); err != nil {
			return err
		}
		fmt.Fprintf(cmd.OutOrStdout(), "Set %d node(s) for provider %s\n", len(nodes), providerID)
		return nil
	},
}
