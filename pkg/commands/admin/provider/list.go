//go:build !codegen

package provider

import (
	"github.com/fil-forge/libforge/commands"
	"github.com/fil-forge/ucantone/binding"
	"github.com/fil-forge/ucantone/ucan/command"
)

// ListArguments are the (empty) arguments of /admin/provider/list.
type ListArguments = commands.Unit

// List reports every regional provider registered with Hilt, with its region
// and routing policy, ordered by provider DID.
var List = binding.Bind[*ListArguments, *ListOK](command.MustParse("/admin/provider/list"))
