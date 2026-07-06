// Package admin provides the `hilt client admin` command tree. Admin commands are
// authorized only when signed by the service identity itself, so they must be run
// with the Hilt service's identity config.
package admin

import (
	"github.com/fil-forge/hilt/cmd/client/admin/provider"
	"github.com/spf13/cobra"
)

// Cmd is the `hilt client admin` command group.
var Cmd = &cobra.Command{
	Use:   "admin",
	Short: "Administrate a running Hilt via UCAN invocations (requires the service identity)",
}

func init() {
	Cmd.AddCommand(provider.Cmd)
}
