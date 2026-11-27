package grant_test

import (
	"slices"
	"testing"
	"time"

	s3bkt "github.com/fil-forge/libforge/commands/s3/bucket"

	"github.com/fil-forge/hilt/pkg/grant"
	"github.com/fil-forge/hilt/pkg/s3perm"
	accesskeystore "github.com/fil-forge/hilt/pkg/store/accesskey"
	bucketpolicystore "github.com/fil-forge/hilt/pkg/store/bucketpolicy"
	tenantstore "github.com/fil-forge/hilt/pkg/store/tenant"
	"github.com/fil-forge/ucantone/did"
	"github.com/fil-forge/ucantone/multikey"
	"github.com/fil-forge/ucantone/multikey/ed25519"
	"github.com/fil-forge/ucantone/multikey/secp256k1"
	"github.com/fil-forge/ucantone/ucan"
	"github.com/stretchr/testify/require"
)

func TestIssue(t *testing.T) {
	tenantSigner, err := secp256k1.Generate()
	require.NoError(t, err)
	tenantID := tenantSigner.KeyDID()
	tenant := multikey.NewIssuer(tenantID, tenantSigner)
	keySigner, err := ed25519.Generate()
	require.NoError(t, err)
	keyID := keySigner.KeyDID()
	bucketA, bucketB := did.MustParse("did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"), did.MustParse("did:key:z6MkrJVnaZkeFzdQyMZu1cgjg7k1pZZ6pvBQ7XJPt4swbTQ2")

	t.Run("issues one delegation per subject and command", func(t *testing.T) {
		dels, err := grant.Issue(tenant, keyID, []did.DID{bucketA, bucketB}, []string{"s3:GetObject", "s3:DeleteObject"}, nil)
		require.NoError(t, err)
		cmds := s3perm.CommandsFor("s3:GetObject", "s3:DeleteObject")
		require.Len(t, dels, 2*len(cmds))
		var got [][2]string
		for _, d := range dels {
			require.Equal(t, tenantID, d.Issuer())
			require.Equal(t, keyID, d.Audience())
			require.NotNil(t, d.Expiration())
			require.WithinDuration(t, time.Now().Add(grant.Lifetime), time.Unix(int64(*d.Expiration()), 0), time.Minute)
			got = append(got, [2]string{d.Subject().String(), d.Command().String()})
		}
		var want [][2]string
		for _, sub := range []did.DID{bucketA, bucketB} {
			for _, cmd := range cmds {
				want = append(want, [2]string{sub.String(), cmd.String()})
			}
		}
		require.Equal(t, want, got)
	})

	t.Run("a key that expires after the lifetime is issued the lifetime", func(t *testing.T) {
		later := time.Now().Add(2 * grant.Lifetime)
		dels, err := grant.Issue(tenant, keyID, []did.DID{bucketA}, []string{"s3:GetObject"}, &later)
		require.NoError(t, err)
		require.NotEmpty(t, dels)
		for _, d := range dels {
			require.NotNil(t, d.Expiration())
			require.WithinDuration(t, time.Now().Add(grant.Lifetime), time.Unix(int64(*d.Expiration()), 0), time.Minute)
		}
	})

	t.Run("issues powerline delegations when there is no subject", func(t *testing.T) {
		dels, err := grant.Issue(tenant, keyID, nil, []string{"s3:GetObject"}, nil)
		require.NoError(t, err)
		require.Len(t, dels, len(s3perm.CommandsFor("s3:GetObject")))
		for _, d := range dels {
			require.False(t, d.Subject().Defined())
		}
	})

	t.Run("expires with the key", func(t *testing.T) {
		exp := time.Now().Add(time.Hour)
		dels, err := grant.Issue(tenant, keyID, []did.DID{bucketA}, []string{"s3:GetObject"}, &exp)
		require.NoError(t, err)
		require.NotEmpty(t, dels)
		for _, d := range dels {
			require.NotNil(t, d.Expiration())
			require.Equal(t, ucan.UnixTimestamp(exp.Unix()), *d.Expiration())
		}
	})

	t.Run("issues nothing for actions with no command", func(t *testing.T) {
		dels, err := grant.Issue(tenant, keyID, []did.DID{bucketA}, []string{"s3:ListAllMyBuckets"}, nil)
		require.NoError(t, err)
		require.Empty(t, dels)
	})
}

func TestForKey(t *testing.T) {
	tenantSigner, err := secp256k1.Generate()
	require.NoError(t, err)
	tenant := multikey.NewIssuer(tenantSigner.KeyDID(), tenantSigner)
	keySigner, err := ed25519.Generate()
	require.NoError(t, err)
	keyID := keySigner.KeyDID()
	bucketA, bucketB := did.MustParse("did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"), did.MustParse("did:key:z6MkrJVnaZkeFzdQyMZu1cgjg7k1pZZ6pvBQ7XJPt4swbTQ2")
	expires := time.Now().Add(time.Hour).Truncate(time.Second)

	// grants lists what each delegation grants, sorted.
	grants := func(dels []ucan.Delegation) []string {
		var out []string
		for _, d := range dels {
			require.Equal(t, tenant.DID(), d.Issuer())
			require.Equal(t, keyID, d.Audience())
			exp := "never"
			if e := d.Expiration(); e != nil {
				exp = time.Unix(int64(*e), 0).UTC().String()
			}
			out = append(out, d.Subject().String()+" "+d.Command().String()+" "+exp)
		}
		slices.Sort(out)
		return out
	}
	policy := func(bucket did.DID, principal s3bkt.Principal, actions ...string) bucketpolicystore.Record {
		return bucketpolicystore.Record{Bucket: bucket, Policy: s3bkt.PolicyDocument{Version: s3bkt.Version2012, Statements: []s3bkt.Statement{{
			Effect: s3bkt.Allow, Principal: principal, Actions: s3bkt.NewStringSet(actions...),
			Resources: s3bkt.NewStringSet(s3bkt.BucketARN("b"), s3bkt.ObjectsARN("b")),
		}}}}
	}

	t.Run("a service key holds what its permissions and buckets map to, whatever the policies say", func(t *testing.T) {
		key := accesskeystore.Record{ID: keyID, Buckets: []did.DID{bucketA}, Permissions: []string{"s3:GetObject", "s3:PutObject"}, ExpiresAt: &expires}
		got, err := grant.ForKey(tenant, tenantstore.Active, key, []bucketpolicystore.Record{policy(bucketB, s3bkt.Everyone(), "s3:DeleteObject")})
		require.NoError(t, err)
		want, err := grant.Issue(tenant, keyID, []did.DID{bucketA}, []string{"s3:GetObject", "s3:PutObject"}, &expires)
		require.NoError(t, err)
		require.NotEmpty(t, want)
		require.Equal(t, grants(want), grants(got))
	})

	t.Run("a service key with no buckets holds powerline delegations", func(t *testing.T) {
		got, err := grant.ForKey(tenant, tenantstore.Active, accesskeystore.Record{ID: keyID, Permissions: []string{"s3:GetObject"}}, nil)
		require.NoError(t, err)
		require.NotEmpty(t, got)
		for _, d := range got {
			require.False(t, d.Subject().Defined())
			require.NotNil(t, d.Expiration())
			require.WithinDuration(t, time.Now().Add(grant.Lifetime), time.Unix(int64(*d.Expiration()), 0), time.Minute)
		}
	})

	t.Run("a principal-bound key holds its principal's effective actions over each bucket", func(t *testing.T) {
		alice := "alice"
		key := accesskeystore.Record{ID: keyID, Principal: &alice, ExpiresAt: &expires}
		got, err := grant.ForKey(tenant, tenantstore.Active, key, []bucketpolicystore.Record{
			policy(bucketA, s3bkt.Only("alice"), "s3:GetObject"),
			policy(bucketB, s3bkt.Only("bob"), "s3:GetObject"),
		})
		require.NoError(t, err)
		want, err := grant.Issue(tenant, keyID, []did.DID{bucketA}, []string{"s3:GetObject"}, &expires)
		require.NoError(t, err)
		require.NotEmpty(t, want)
		require.Equal(t, grants(want), grants(got), "nothing over the bucket whose policy names another principal")
	})

	t.Run("a principal-bound key no policy names holds nothing", func(t *testing.T) {
		alice := "alice"
		got, err := grant.ForKey(tenant, tenantstore.Active, accesskeystore.Record{ID: keyID, Principal: &alice}, nil)
		require.NoError(t, err)
		require.Empty(t, got)
	})
}

func TestForKeyUnderATenantStatus(t *testing.T) {
	tenantSigner, err := secp256k1.Generate()
	require.NoError(t, err)
	tenant := multikey.NewIssuer(tenantSigner.KeyDID(), tenantSigner)
	keySigner, err := ed25519.Generate()
	require.NoError(t, err)
	keyID := keySigner.KeyDID()
	bucket := did.MustParse("did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK")
	alice := "alice"
	all := []string{"s3:GetObject", "s3:PutObject", "s3:DeleteObject", "s3:PutObjectTagging"}
	service := accesskeystore.Record{ID: keyID, Buckets: []did.DID{bucket}, Permissions: all}
	bound := accesskeystore.Record{ID: keyID, Principal: &alice}
	policies := []bucketpolicystore.Record{{Bucket: bucket, Policy: s3bkt.PolicyDocument{Version: s3bkt.Version2012, Statements: []s3bkt.Statement{{
		Effect: s3bkt.Allow, Principal: s3bkt.Only(alice), Actions: s3bkt.NewStringSet(all...),
		Resources: s3bkt.NewStringSet(s3bkt.ObjectsARN("b")),
	}}}}}
	// grants lists what each delegation grants, sorted.
	grants := func(dels []ucan.Delegation) []string {
		var out []string
		for _, d := range dels {
			out = append(out, d.Subject().String()+" "+d.Command().String())
		}
		slices.Sort(out)
		return out
	}
	issue := func(t *testing.T, actions ...string) []string {
		dels, err := grant.Issue(tenant, keyID, []did.DID{bucket}, actions, nil)
		require.NoError(t, err)
		require.NotEmpty(t, dels)
		return grants(dels)
	}

	for name, key := range map[string]accesskeystore.Record{"a service key": service, "a principal-bound key": bound} {
		t.Run(name+" of a write-locked tenant holds its reads and deletions alone", func(t *testing.T) {
			got, err := grant.ForKey(tenant, tenantstore.WriteLocked, key, policies)
			require.NoError(t, err)
			require.Equal(t, issue(t, "s3:GetObject", "s3:DeleteObject"), grants(got))
		})
		t.Run(name+" of an active tenant holds everything", func(t *testing.T) {
			got, err := grant.ForKey(tenant, tenantstore.Active, key, policies)
			require.NoError(t, err)
			require.Equal(t, issue(t, all...), grants(got))
		})
		t.Run(name+" of a disabled tenant holds nothing", func(t *testing.T) {
			got, err := grant.ForKey(tenant, tenantstore.Disabled, key, policies)
			require.NoError(t, err)
			require.Empty(t, got)
		})
	}

	t.Run("a write-locked tenant's key with nothing kept holds nothing, powerline included", func(t *testing.T) {
		got, err := grant.ForKey(tenant, tenantstore.WriteLocked, accesskeystore.Record{ID: keyID, Permissions: []string{"s3:PutObject"}}, nil)
		require.NoError(t, err)
		require.Empty(t, got)
	})
}

func TestLimitToTenantStatus(t *testing.T) {
	actions := []string{"s3:PutObject", "s3:GetObject", "s3:Frobnicate", "s3:DeleteObject", "s3:CreateBucket", "s3:ListAllMyBuckets"}
	given := slices.Clone(actions)

	active := grant.LimitToTenantStatus(tenantstore.Active, actions)
	require.Equal(t, actions, active)
	active[0] = "changed"
	require.Equal(t, given, actions, "the result is a new slice")

	require.Equal(t, []string{"s3:GetObject", "s3:DeleteObject", "s3:ListAllMyBuckets"},
		grant.LimitToTenantStatus(tenantstore.WriteLocked, actions), "what is kept, in the order given")
	require.Empty(t, grant.LimitToTenantStatus(tenantstore.Disabled, actions))
	require.Empty(t, grant.LimitToTenantStatus(tenantstore.Status("paused"), actions), "a status that is not one keeps nothing")
	require.Equal(t, given, actions, "the actions given are left alone")
}
