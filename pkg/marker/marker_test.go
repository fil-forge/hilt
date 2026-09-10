package marker_test

import (
	"testing"
	"time"

	"github.com/fil-forge/hilt/pkg/marker"
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

	t.Run("is issued by the tenant to the key, with the tenant as subject", func(t *testing.T) {
		m, err := marker.Issue(tenant, keyID, tenantID, nil)
		require.NoError(t, err)
		require.Equal(t, tenantID, m.Issuer())
		require.Equal(t, keyID, m.Audience())
		require.Equal(t, tenantID, m.Subject())
		require.Equal(t, marker.Command, m.Command())
		require.Equal(t, "/s3/key/marker", m.Command().String())
	})

	t.Run("never expires when the key does not", func(t *testing.T) {
		m, err := marker.Issue(tenant, keyID, tenantID, nil)
		require.NoError(t, err)
		require.Nil(t, m.Expiration())
	})

	t.Run("expires with the key", func(t *testing.T) {
		exp := time.Now().Add(time.Hour)
		m, err := marker.Issue(tenant, keyID, tenantID, &exp)
		require.NoError(t, err)
		require.NotNil(t, m.Expiration())
		require.Equal(t, ucan.UnixTimestamp(exp.Unix()), *m.Expiration())
	})

	t.Run("each marker has its own CID", func(t *testing.T) {
		a, err := marker.Issue(tenant, keyID, tenantID, nil)
		require.NoError(t, err)
		b, err := marker.Issue(tenant, keyID, tenantID, nil)
		require.NoError(t, err)
		require.NotEmpty(t, a.Nonce())
		require.NotEqual(t, a.Link(), b.Link())
	})
}
