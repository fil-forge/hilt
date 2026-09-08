// Package nodes provides the `hilt client admin provider nodes` command tree.
package nodes

import "github.com/spf13/cobra"

// Cmd is the `hilt client admin provider nodes` command group.
var Cmd = &cobra.Command{
	Use:   "nodes",
	Short: "Manage the storage nodes a regional provider operates",
}

func init() {
	Cmd.AddCommand(setCmd)
}
