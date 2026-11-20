package tenant_test

import (
	"errors"
	"testing"

	"github.com/fil-forge/hilt/internal/testutil"
	tenantsvc "github.com/fil-forge/hilt/pkg/api/service/tenant"
	"github.com/fil-forge/hilt/pkg/grant"
	"github.com/fil-forge/hilt/pkg/s3perm"
	accesskey "github.com/fil-forge/hilt/pkg/store/accesskey"
	accesskeymemory "github.com/fil-forge/hilt/pkg/store/accesskey/memory"
	keypostgres "github.com/fil-forge/hilt/pkg/store/accesskey/postgres"
	bucketmemory "github.com/fil-forge/hilt/pkg/store/bucket/memory"
	policystore "github.com/fil-forge/hilt/pkg/store/bucketpolicy"
	policymemory "github.com/fil-forge/hilt/pkg/store/bucketpolicy/memory"
	delegationmemory "github.com/fil-forge/hilt/pkg/store/delegation/memory"
	delegationpostgres "github.com/fil-forge/hilt/pkg/store/delegation/postgres"
	principalmemory "github.com/fil-forge/hilt/pkg/store/principal/memory"
	"github.com/fil-forge/hilt/pkg/store/tenant"
	tenantmemory "github.com/fil-forge/hilt/pkg/store/tenant/memory"
	tenantpostgres "github.com/fil-forge/hilt/pkg/store/tenant/postgres"
	wrapmemory "github.com/fil-forge/hilt/pkg/store/wrapkey/memory"
	"github.com/fil-forge/hilt/pkg/vault"
	vaultmemory "github.com/fil-forge/hilt/pkg/vault/memory"
	s3bkt "github.com/fil-forge/libforge/commands/s3/bucket"
	"github.com/fil-forge/ucantone/did"
	"github.com/fil-forge/ucantone/multikey"
	"github.com/fil-forge/ucantone/multikey/secp256k1"
	"github.com/fil-forge/ucantone/ucan"
	"github.com/ipfs/go-cid"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

func TestStatusRestoresPrincipalPolicyAuthority(t *testing.T) {
	ctx := t.Context()
	tenants, keys, dels := tenantmemory.New(), accesskeymemory.New(), delegationmemory.New()
	principals, policies, secrets := principalmemory.New(), policymemory.New(), vaultmemory.New()
	signer, err := secp256k1.Generate()
	require.NoError(t, err)
	id, key, bucket := signer.KeyDID(), testutil.RandomDID(t), testutil.RandomDID(t)
	principal := "fixture-principal"
	require.NoError(t, tenants.Add(ctx, id, "principal-target", tenant.Active))
	require.NoError(t, principals.Add(ctx, id, principal))
	require.NoError(t, secrets.Write(ctx, vault.TenantKeyPath(id), signer.Bytes()))
	require.NoError(t, keys.Add(ctx, accesskey.Input{ID: key, Tenant: id, Name: "principal-key", Principal: &principal}))
	_, err = policies.Put(ctx, policystore.Input{Tenant: id, Bucket: bucket, Policy: s3bkt.PolicyDocument{
		Version: s3bkt.Version2012, Statements: []s3bkt.Statement{{
			Effect: s3bkt.Allow, Principal: s3bkt.Only(principal), Actions: s3bkt.NewStringSet("s3:GetObject", "s3:PutObject"),
			Resources: s3bkt.NewStringSet(s3bkt.ObjectsARN("fixture-bucket")),
		}},
	}}, nil)
	require.NoError(t, err)
	svc := tenantsvc.New(zap.NewNop(), tenants, bucketmemory.New(), keys, principals, policies, dels, secrets, wrapmemory.New(), nil, nil, &testutil.FakeSwarf{})
	for _, status := range []string{"write-locked", "disabled", "active"} {
		require.NoError(t, svc.SetStatus(ctx, "principal-target", status))
		page, err := dels.ListByAudience(ctx, key)
		require.NoError(t, err)
		var commands []ucan.Command
		for _, d := range page.Results {
			commands = append(commands, d.Command())
		}
		var expected []ucan.Command
		if status == "write-locked" {
			expected = s3perm.CommandsFor("s3:GetObject")
		}
		if status == "active" {
			expected = s3perm.CommandsFor("s3:GetObject", "s3:PutObject")
		}
		require.ElementsMatch(t, expected, commands)
	}
	// A tombstoned principal with stale key metadata cannot be restored.
	require.NoError(t, principals.Tombstone(ctx, id, principal, nil))
	require.NoError(t, svc.SetStatus(ctx, "principal-target", "active"))
	page, err := dels.ListByAudience(ctx, key)
	require.NoError(t, err)
	require.Empty(t, page.Results)
}

func TestStatusAuthorityPostgresAtomicity(t *testing.T) {
	pool := testutil.PostgresOrSkip(t)
	tenants, keys, dels := tenantpostgres.New(pool), keypostgres.New(pool), delegationpostgres.New(pool)
	for _, failPublish := range []bool{true, false} {
		t.Run(map[bool]string{true: "publish_failure_rolls_back", false: "success_commits_both"}[failPublish], func(t *testing.T) {
			ctx := t.Context()
			signer, err := secp256k1.Generate()
			require.NoError(t, err)
			id, key := signer.KeyDID(), testutil.RandomDID(t)
			external := id.String()
			require.NoError(t, tenants.Add(ctx, id, external, tenant.Active))
			require.NoError(t, keys.Add(ctx, accesskey.Input{ID: key, Tenant: id, Name: "atomic-key", Permissions: []string{"s3:PutObject"}}))
			secrets := vaultmemory.New()
			require.NoError(t, secrets.Write(ctx, vault.TenantKeyPath(id), signer.Bytes()))
			issued, err := grant.Issue(multikey.NewIssuer(id, signer), key, nil, []string{"s3:PutObject"}, nil)
			require.NoError(t, err)
			require.NoError(t, dels.PutBatch(ctx, issued))
			publisher := &testutil.FakeSwarf{}
			if failPublish {
				publisher.Err = errors.New("unavailable")
			}
			svc := tenantsvc.New(zap.NewNop(), tenants, bucketmemory.New(), keys, principalmemory.New(), policymemory.New(), dels, secrets, wrapmemory.New(), nil, nil, publisher)
			err = svc.SetStatus(ctx, external, "disabled")
			if failPublish {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
			rec, err := tenants.Get(ctx, id)
			require.NoError(t, err)
			page, err := dels.ListByAudience(ctx, key)
			require.NoError(t, err)
			if failPublish {
				require.Equal(t, tenant.Active, rec.Status)
				require.Len(t, page.Results, len(issued))
				var before, after []cid.Cid
				for _, original := range issued {
					before = append(before, original.Link())
				}
				for _, stored := range page.Results {
					after = append(after, stored.Link())
				}
				require.ElementsMatch(t, before, after)
			} else {
				require.Equal(t, tenant.Disabled, rec.Status)
				require.Empty(t, page.Results)
				require.Len(t, publisher.Revoked(), len(issued))
			}
		})
	}
}

func TestStatusReconcilesStoredAuthority(t *testing.T) {
	for _, failPublish := range []bool{false, true} {
		t.Run(map[bool]string{false: "restrict_restore_and_control", true: "publish_failure"}[failPublish], func(t *testing.T) {
			ctx := t.Context()
			tenants, keys, dels := tenantmemory.New(), accesskeymemory.New(), delegationmemory.New()
			secrets := vaultmemory.New()
			publisher := &testutil.FakeSwarf{}
			configured := []string{"s3:GetObject", "s3:PutObject", "s3:DeleteObject", "s3:PutBucketPolicy"}
			var tenantIDs, keyIDs []did.DID
			for _, external := range []string{"target", "control"} {
				signer, err := secp256k1.Generate()
				require.NoError(t, err)
				id, key := signer.KeyDID(), testutil.RandomDID(t)
				require.NoError(t, tenants.Add(ctx, id, external, tenant.Active))
				require.NoError(t, secrets.Write(ctx, vault.TenantKeyPath(id), signer.Bytes()))
				require.NoError(t, keys.Add(ctx, accesskey.Input{ID: key, Tenant: id, Name: "any-key", Permissions: configured}))
				issued, err := grant.Issue(multikey.NewIssuer(id, signer), key, nil, configured, nil)
				require.NoError(t, err)
				require.NoError(t, dels.PutBatch(ctx, issued))
				tenantIDs, keyIDs = append(tenantIDs, id), append(keyIDs, key)
			}
			list := func(key did.DID) []ucan.Delegation {
				page, err := dels.ListByAudience(ctx, key)
				require.NoError(t, err)
				require.Nil(t, page.Cursor)
				return page.Results
			}
			links := func(items []ucan.Delegation) []cid.Cid {
				var links []cid.Cid
				for _, item := range items {
					links = append(links, item.Link())
				}
				return links
			}
			before, control := list(keyIDs[0]), links(list(keyIDs[1]))
			svc := tenantsvc.New(zap.NewNop(), tenants, bucketmemory.New(), keys, principalmemory.New(), policymemory.New(), dels, secrets, wrapmemory.New(), nil, nil, publisher)
			if failPublish {
				publisher.Err = errors.New("unavailable")
				require.Error(t, svc.SetStatus(ctx, "target", "disabled"))
				rec, err := tenants.Get(ctx, tenantIDs[0])
				require.NoError(t, err)
				require.Equal(t, tenant.Active, rec.Status)
				require.ElementsMatch(t, links(before), links(list(keyIDs[0])))
				return
			}
			// A legacy writer may already have set the status without invalidating.
			require.NoError(t, tenants.SetStatus(ctx, tenantIDs[0], tenant.WriteLocked))
			require.NoError(t, svc.SetStatus(ctx, "target", "write-locked"))
			locked := list(keyIDs[0])
			var commands []ucan.Command
			for _, item := range locked {
				commands = append(commands, item.Command())
			}
			require.ElementsMatch(t, s3perm.CommandsFor("s3:GetObject", "s3:DeleteObject"), commands)
			require.ElementsMatch(t, links(before), publisher.Revoked())
			for _, link := range links(locked) {
				require.NotContains(t, links(before), link)
			}
			require.NoError(t, svc.SetStatus(ctx, "target", "disabled"))
			require.Empty(t, list(keyIDs[0]))
			require.NoError(t, svc.SetStatus(ctx, "target", "active"))
			restored := list(keyIDs[0])
			require.NotEmpty(t, restored)
			for _, link := range links(restored) {
				require.NotContains(t, publisher.Revoked(), link)
			}
			record, err := keys.Get(ctx, keyIDs[0])
			require.NoError(t, err)
			require.Equal(t, configured, record.Permissions)
			require.ElementsMatch(t, control, links(list(keyIDs[1])))
		})
	}
}
