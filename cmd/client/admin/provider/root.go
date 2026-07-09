// Package provider provides the `hilt client admin provider` command tree.
package provider

import "github.com/spf13/cobra"

// Cmd is the `hilt client admin provider` command group.
var Cmd = &cobra.Command{
	Use:   "provider",
	Short: "Manage regional providers",
}

func init() {
	Cmd.AddCommand(addCmd)
}
