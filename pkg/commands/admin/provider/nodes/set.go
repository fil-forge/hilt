//go:build !codegen

// Package nodes defines the /admin/provider/nodes/* UCAN commands. These are
// admin commands: they are authorized only when the invocation issuer is the
// service's own identity (subject == service), so they carry no delegation
// proofs.
package nodes

import (
	"github.com/fil-forge/libforge/commands"
	"github.com/fil-forge/ucantone/binding"
	"github.com/fil-forge/ucantone/ucan/command"
)

// SetOK is the (empty) result of a successful /admin/provider/nodes/set.
type SetOK = commands.Unit

// Set replaces the storage nodes a registered provider operates: Hilt puts them
// as the candidates of the provider's routing policy on the upload service.
var Set = binding.Bind[*SetArguments, *SetOK](command.MustParse("/admin/provider/nodes/set"))
