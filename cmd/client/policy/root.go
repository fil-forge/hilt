// Package policy provides the `hilt client policy` command tree: the two
// principal reads computed from bucket policies, via the Tenant REST API, authenticated with the partner key from config
// (auth.partner_key) or the HILT_PARTNER_KEY env var.
package policy

import "github.com/spf13/cobra"

// Cmd is the `hilt client policy` command group.
var Cmd = &cobra.Command{
	Use:   "policy",
	Short: "Read bucket policies by principal via the Tenant REST API",
}

func init() {
	Cmd.AddCommand(listCmd)
	Cmd.AddCommand(accessCmd)
}
