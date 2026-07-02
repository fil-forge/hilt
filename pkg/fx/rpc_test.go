package fx_test

import (
	"testing"

	"github.com/fil-forge/hilt/pkg/config"
	appfx "github.com/fil-forge/hilt/pkg/fx"
	"github.com/fil-forge/hilt/pkg/rpc"
	"github.com/fil-forge/ucantone/server"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

func TestNewIdentityEphemeral(t *testing.T) {
	id, err := appfx.NewIdentity(config.IdentityConfig{}, zap.NewNop())
	require.NoError(t, err)
	require.True(t, id.DID().Defined())
	require.Equal(t, "key", id.DID().Method()) // ephemeral key ⇒ did:key
}

func TestNewIdentityMissingKeyFile(t *testing.T) {
	_, err := appfx.NewIdentity(config.IdentityConfig{KeyFile: "/nonexistent/hilt.pem"}, zap.NewNop())
	require.Error(t, err)
}

func TestNewUCANServer(t *testing.T) {
	id, err := appfx.NewIdentity(config.IdentityConfig{}, zap.NewNop())
	require.NoError(t, err)

	srv := appfx.NewUCANServer(appfx.UCANServerParams{
		Identity: id,
		Routes: []server.Route{
			rpc.NewAuthorizeRequestHandler(zap.NewNop()),
			rpc.NewCreateBucketHandler(zap.NewNop()),
			rpc.NewDeleteBucketHandler(zap.NewNop()),
			rpc.NewBucketInfoHandler(zap.NewNop()),
			rpc.NewListBucketsHandler(zap.NewNop()),
		},
	})
	require.NotNil(t, srv)
}
