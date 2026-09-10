// Package marker issues the marker delegation of a principal-bound access key.
//
// A principal-bound key is authorized from its tenant's bucket policies and
// holds no grant of its own. Its one delegation is the marker: issued by the
// tenant to the key, with the tenant as subject and the command
// /s3/key/marker. It grants nothing and is in no proof chain. It exists so the
// key has a CID the gateway holds and Hilt can revoke: revoking the marker
// through the revocation service makes the gateway drop what it cached for
// the key. ucantone gives each delegation a random nonce, so every marker has
// its own CID and a replacement is distinct from the one before it.
//
// The command is hand-written rather than a libforge bound command because
// nothing ever invokes it: the marker is only issued, stored, and revoked.
package marker

import (
	"time"

	"github.com/fil-forge/ucantone/did"
	"github.com/fil-forge/ucantone/ucan"
	"github.com/fil-forge/ucantone/ucan/command"
	"github.com/fil-forge/ucantone/ucan/delegation"
)

// Command is the marker delegation's command. It names no operation.
var Command = command.MustParse("/s3/key/marker")

// Issue issues key's marker: a delegation from issuer (the tenant) to key with
// tenant as subject and [Command] as command. It expires with the key when
// expiresAt is set and never otherwise.
func Issue(issuer ucan.Issuer, key, tenant did.DID, expiresAt *time.Time) (ucan.Delegation, error) {
	opt := delegation.WithNoExpiration()
	if expiresAt != nil {
		opt = delegation.WithExpiration(ucan.UnixTimestamp(expiresAt.Unix()))
	}
	m, err := delegation.Delegate(issuer, key, tenant, Command, opt)
	if err != nil {
		return nil, err
	}
	return m, nil
}
