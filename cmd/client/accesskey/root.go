// Package accesskey provides the `hilt client access-key` command tree: partner
// operations on a tenant's access keys via the Tenant REST API, authenticated
// with the partner key from config (auth.partner_key) or the HILT_PARTNER_KEY
// env var.
package accesskey

import "github.com/spf13/cobra"

// Cmd is the `hilt client access-key` command group.
var Cmd = &cobra.Command{
	Use:   "access-key",
	Short: "Manage a tenant's access keys via the Tenant REST API",
}

func init() {
	Cmd.AddCommand(createCmd)
	Cmd.AddCommand(listCmd)
	Cmd.AddCommand(getCmd)
	Cmd.AddCommand(deleteCmd)
}
