package grant_test

import (
	"testing"
	"time"

	"github.com/fil-forge/hilt/pkg/grant"
	"github.com/fil-forge/hilt/pkg/s3perm"
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
			require.Nil(t, d.Expiration())
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
