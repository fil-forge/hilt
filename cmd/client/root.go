// Package client provides the `hilt client` command tree: UCAN invocations against
// a running Hilt service.
package client

import (
	"github.com/fil-forge/hilt/cmd/client/admin"
	"github.com/spf13/cobra"
)

// Cmd is the `hilt client` command group.
var Cmd = &cobra.Command{
	Use:   "client",
	Short: "Interact with a running Hilt via UCAN invocations",
}

func init() {
	Cmd.PersistentFlags().String("url", "", "Hilt server URL (default: derived from the server host/port in config)")
	Cmd.AddCommand(admin.Cmd)
}
