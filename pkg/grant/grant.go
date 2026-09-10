// Package grant issues the stored delegations of an access key.
//
// A key's authority at the storage system is the set of tenant→key delegations
// it holds, one per subject and Forge command. A service key holds the set
// derived from the permissions and buckets it was created with. A
// principal-bound key holds, for each bucket its principal can reach, the set
// derived from the principal's effective actions on that bucket, and a policy
// change rewrites it (see Rotator).
package grant

import (
	"time"

	"github.com/fil-forge/hilt/pkg/s3perm"
	"github.com/fil-forge/ucantone/did"
	"github.com/fil-forge/ucantone/ucan"
	"github.com/fil-forge/ucantone/ucan/delegation"
)

// Issue returns issuer→key delegations, one per subject and Forge command the
// actions map to, expiring with the key when expiresAt is set and never
// otherwise (ucantone's default is 30 seconds). No subjects means one
// powerline delegation per command, with an undefined subject.
func Issue(issuer ucan.Issuer, key did.DID, subjects []did.DID, actions []string, expiresAt *time.Time) ([]ucan.Delegation, error) {
	opt := delegation.WithNoExpiration()
	if expiresAt != nil {
		opt = delegation.WithExpiration(ucan.UnixTimestamp(expiresAt.Unix()))
	}
	if len(subjects) == 0 {
		subjects = []did.DID{did.Undef}
	}
	var dels []ucan.Delegation
	for _, sub := range subjects {
		for _, cmd := range s3perm.CommandsFor(actions...) {
			d, err := delegation.Delegate(issuer, key, sub, cmd, opt)
			if err != nil {
				return nil, err
			}
			dels = append(dels, d)
		}
	}
	return dels, nil
}
