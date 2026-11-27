// Package grant issues the stored delegations of an access key.
//
// A key's authority at the storage system is the set of tenant→key delegations
// it holds, one per subject and Forge command. A service key holds the set
// derived from the permissions and buckets it was created with. A
// principal-bound key holds, for each bucket its principal can reach, the set
// derived from the principal's effective actions on that bucket, and a policy
// change rewrites it, in the task that writes the policy
// (pkg/tasks/tenantqueue). [ForKey] issues either kind's set, for a key being
// created and for one whose grants are issued again.
//
// Every grant expires, [Lifetime] after it is issued at the latest, and a key
// is issued the next set [RenewBefore] ahead of that. The set it replaces
// stays stored until it expires, so a change that withdraws the key's grants
// revokes both.
//
// The set is narrower while the key's tenant is not active: every issue
// reduces the key's actions to what the tenant's status keeps
// ([LimitToTenantStatus]), and a change of status withdraws the set and
// issues the one for the new status.
package grant

import (
	"time"

	"github.com/fil-forge/hilt/pkg/bucketpolicy"
	"github.com/fil-forge/hilt/pkg/s3perm"
	accesskeystore "github.com/fil-forge/hilt/pkg/store/accesskey"
	bucketpolicystore "github.com/fil-forge/hilt/pkg/store/bucketpolicy"
	"github.com/fil-forge/hilt/pkg/store/tenant"
	"github.com/fil-forge/ucantone/did"
	"github.com/fil-forge/ucantone/ucan"
	"github.com/fil-forge/ucantone/ucan/delegation"
)

// Lifetime is how long a grant lasts from the moment it is issued. A grant
// that is withdrawn is revoked, and the revocation service keeps a revocation
// until the delegation it names has expired, so this is also how long each
// revocation is kept.
const Lifetime = 7 * 24 * time.Hour

// RenewBefore is how long before a grant expires its key is issued the next
// one (queue-tenant.renew-grants). It must stay longer than the delegations
// an authorize issues beneath a grant, which last up to a day and the async
// overhang, so that none of them outlives the grant it was issued under; the
// rest is the time a renewal has to run in.
const RenewBefore = 3 * 24 * time.Hour

// Issue returns issuer→key delegations, one per subject and Forge command the
// actions map to. Each expires [Lifetime] from now, or with the key when
// expiresAt is sooner. No subjects means one powerline delegation per
// command, with an undefined subject.
func Issue(issuer ucan.Issuer, key did.DID, subjects []did.DID, actions []string, expiresAt *time.Time) ([]ucan.Delegation, error) {
	exp := time.Now().Add(Lifetime)
	if expiresAt != nil && expiresAt.Before(exp) {
		exp = *expiresAt
	}
	opt := delegation.WithExpiration(ucan.UnixTimestamp(exp.Unix()))
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

// ForKey returns the issuer→key delegations the access key holds while its
// tenant has the status, issued afresh by the tenant as issuer. A service
// key's come from its own permissions and buckets, and policies is not read.
// A principal-bound key's come from policies, the tenant's bucket policies
// that name its principal: over each bucket, the delegations for the
// principal's effective actions there, and none over a bucket whose policy
// leaves it no action. Either kind's actions are first reduced to what the
// status keeps ([LimitToTenantStatus]), so a write-locked tenant's key holds
// the delegations of its reads, listings and deletions alone, and a disabled
// tenant's holds none. Only the key's ID, Buckets, Permissions, Principal
// and ExpiresAt are read.
func ForKey(issuer ucan.Issuer, status tenant.Status, key accesskeystore.Record, policies []bucketpolicystore.Record) ([]ucan.Delegation, error) {
	if key.Principal == nil {
		actions := LimitToTenantStatus(status, key.Permissions)
		if len(actions) == 0 {
			return nil, nil
		}
		return Issue(issuer, key.ID, key.Buckets, actions, key.ExpiresAt)
	}
	var dels []ucan.Delegation
	for _, p := range policies {
		eff := LimitToTenantStatus(status, bucketpolicy.Effective(&p.Policy, *key.Principal))
		if len(eff) == 0 {
			continue
		}
		granted, err := Issue(issuer, key.ID, []did.DID{p.Bucket}, eff, key.ExpiresAt)
		if err != nil {
			return nil, err
		}
		dels = append(dels, granted...)
	}
	return dels, nil
}
