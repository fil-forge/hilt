// Package principal provides the `hilt client principal` command tree: partner
// operations on a tenant's principals and their access keys via the Tenant REST
// API, authenticated with the partner key from config (auth.partner_key) or the
// HILT_PARTNER_KEY env var.
package principal

import "github.com/spf13/cobra"

// Cmd is the `hilt client principal` command group.
var Cmd = &cobra.Command{
	Use:   "principal",
	Short: "Manage a tenant's principals via the Tenant REST API",
}

func init() {
	Cmd.AddCommand(createCmd)
	Cmd.AddCommand(listCmd)
	Cmd.AddCommand(getCmd)
	Cmd.AddCommand(deleteCmd)
	Cmd.AddCommand(listAccessKeysCmd)
}
