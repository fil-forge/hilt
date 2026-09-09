package provider

import (
	"fmt"

	"github.com/fil-forge/hilt/cmd/client/lib"
	"github.com/fil-forge/ucantone/did"
	"github.com/spf13/cobra"
)

var addCmd = &cobra.Command{
	Use:   "add <provider-did> <region> [node-did...]",
	Short: "Register a regional provider with Hilt",
	Long: "Register a regional provider (its DID, the region it serves and, optionally, " +
		"the storage nodes it operates). With nodes, Hilt issues a routing policy for the " +
		"provider with the nodes as its candidates and every bucket created in the region " +
		"is routed to them. Without nodes the region's buckets use default routing until " +
		"`provider nodes set` is run.\n\n" +
		"This is an admin operation: it must be run with the Hilt service identity " +
		"config (identity.key_file / HILT_IDENTITY_KEY_FILE) so the signed invocation " +
		"is accepted by the server.",
	Args: cobra.MinimumNArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		providerID, err := did.Parse(args[0])
		if err != nil {
			return fmt.Errorf("parsing provider DID: %w", err)
		}
		region := args[1]
		nodes, err := parseNodes(args[2:])
		if err != nil {
			return err
		}

		c, _, err := lib.InitAdminClient(cmd)
		if err != nil {
			return err
		}
		if err := c.AddProvider(cmd.Context(), providerID, region, nodes); err != nil {
			return err
		}
		fmt.Fprintf(cmd.OutOrStdout(), "Registered provider %s for region %s with %d node(s)\n", providerID, region, len(nodes))
		return nil
	},
}

// parseNodes parses storage node DIDs from CLI arguments.
func parseNodes(args []string) ([]did.DID, error) {
	nodes := make([]did.DID, 0, len(args))
	for _, a := range args {
		n, err := did.Parse(a)
		if err != nil {
			return nil, fmt.Errorf("parsing node DID %q: %w", a, err)
		}
		nodes = append(nodes, n)
	}
	return nodes, nil
}
