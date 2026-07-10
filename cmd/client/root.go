// Package client provides the `hilt client` command tree: UCAN invocations and
// partner Tenant REST API calls against a running Hilt service.
package client

import (
	"github.com/fil-forge/hilt/cmd/client/accesskey"
	"github.com/fil-forge/hilt/cmd/client/admin"
	"github.com/fil-forge/hilt/cmd/client/tenant"
	"github.com/spf13/cobra"
)

// Cmd is the `hilt client` command group.
var Cmd = &cobra.Command{
	Use:   "client",
	Short: "Interact with a running Hilt service",
}

func init() {
	Cmd.PersistentFlags().String("url", "", "Hilt server URL (default: derived from the server host/port in config)")
	Cmd.AddCommand(admin.Cmd)
	Cmd.AddCommand(tenant.Cmd)
	Cmd.AddCommand(accesskey.Cmd)
}
