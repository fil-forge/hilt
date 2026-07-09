//go:build !codegen

// Package provider defines the /admin/provider/* UCAN commands. These are admin
// commands: they are authorized only when the invocation issuer is the service's
// own identity (subject == service), so they carry no delegation proofs.
package provider

import (
	"github.com/fil-forge/libforge/commands"
	"github.com/fil-forge/ucantone/binding"
	"github.com/fil-forge/ucantone/ucan/command"
)

// AddOK is the (empty) result of a successful /admin/provider/add.
type AddOK = commands.Unit

// Add registers a regional provider (DID + region) with Hilt.
var Add = binding.Bind[*AddArguments, *AddOK](command.MustParse("/admin/provider/add"))
