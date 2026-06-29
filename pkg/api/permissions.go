package api

import (
	"github.com/fil-forge/libforge/commands/blob"
	"github.com/fil-forge/libforge/commands/content"
	"github.com/fil-forge/libforge/commands/index"
	"github.com/fil-forge/libforge/commands/upload"
	"github.com/fil-forge/ucantone/ucan"
)

// Forge command sets, sourced from the libforge bound command types so the
// command identifiers stay in sync with their definitions.
var (
	cmdsRetrieve = []ucan.Command{content.Retrieve.Command}
	cmdsAdd      = []ucan.Command{blob.Add.Command, index.Add.Command, upload.Add.Command}
	cmdsRemove   = []ucan.Command{blob.Remove.Command, upload.Remove.Command}
)

// s3PermissionCommands maps each supported S3 permission to the Forge commands
// that must be delegated from the tenant to the access key for it. Permissions
// with no Forge equivalent (bucket-level actions) map to nil — they are valid
// and stored on the access key, but issue no delegation and are enforced
// directly by Ingot/Hilt (see the RFC).
var s3PermissionCommands = map[string][]ucan.Command{
	"s3:GetObject":           cmdsRetrieve,
	"s3:GetObjectVersion":    cmdsRetrieve,
	"s3:GetObjectRetention":  cmdsRetrieve,
	"s3:GetObjectLegalHold":  cmdsRetrieve,
	"s3:ListBucket":          cmdsRetrieve,
	"s3:ListBucketVersions":  cmdsRetrieve,
	"s3:PutObject":           cmdsAdd,
	"s3:PutObjectRetention":  cmdsAdd,
	"s3:PutObjectLegalHold":  cmdsAdd,
	"s3:DeleteObject":        cmdsRemove,
	"s3:DeleteObjectVersion": cmdsRemove,
	"s3:CreateBucket":        nil,
	"s3:ListAllMyBuckets":    nil,
	"s3:DeleteBucket":        nil,
}

// validS3Permission reports whether p is a recognized S3 permission.
func validS3Permission(p string) bool {
	_, ok := s3PermissionCommands[p]
	return ok
}

// commandsForPermissions returns the deduplicated set of Forge commands to
// delegate for the given S3 permissions, preserving first-seen order.
func commandsForPermissions(permissions []string) []ucan.Command {
	seen := map[string]bool{}
	var cmds []ucan.Command
	for _, p := range permissions {
		for _, c := range s3PermissionCommands[p] {
			if k := c.String(); !seen[k] {
				seen[k] = true
				cmds = append(cmds, c)
			}
		}
	}
	return cmds
}
