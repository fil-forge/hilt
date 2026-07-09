// Package tenant provides the `hilt client tenant` command tree: partner
// operations on the Tenant REST API, authenticated with the partner key from
// config (auth.partner_key) or the HILT_PARTNER_KEY env var.
package tenant

import "github.com/spf13/cobra"

// Cmd is the `hilt client tenant` command group.
var Cmd = &cobra.Command{
	Use:   "tenant",
	Short: "Manage tenants via the Tenant REST API",
}

func init() {
	Cmd.AddCommand(provisionCmd)
	Cmd.AddCommand(getCmd)
	Cmd.AddCommand(setStatusCmd)
	Cmd.AddCommand(deleteCmd)
}
