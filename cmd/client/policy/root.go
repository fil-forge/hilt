// Package policy provides the `hilt client policy` command tree: partner
// operations on a bucket's policy and the two principal reads computed from
// it, via the Tenant REST API, authenticated with the partner key from config
// (auth.partner_key) or the HILT_PARTNER_KEY env var.
package policy

import "github.com/spf13/cobra"

// Cmd is the `hilt client policy` command group.
var Cmd = &cobra.Command{
	Use:   "policy",
	Short: "Manage bucket policies via the Tenant REST API",
}

func init() {
	Cmd.AddCommand(getCmd)
	Cmd.AddCommand(createCmd)
	Cmd.AddCommand(replaceCmd)
	Cmd.AddCommand(deleteCmd)
	Cmd.AddCommand(listCmd)
	Cmd.AddCommand(accessCmd)
}
