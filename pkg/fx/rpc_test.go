package fx_test

import (
	"testing"

	"github.com/fil-forge/hilt/pkg/config"
	appfx "github.com/fil-forge/hilt/pkg/fx"
	"github.com/fil-forge/hilt/pkg/rpc"
	"github.com/fil-forge/hilt/pkg/rpc/service/auth"
	accesskeymemory "github.com/fil-forge/hilt/pkg/store/accesskey/memory"
	bucketmemory "github.com/fil-forge/hilt/pkg/store/bucket/memory"
	delegationmemory "github.com/fil-forge/hilt/pkg/store/delegation/memory"
	providermemory "github.com/fil-forge/hilt/pkg/store/provider/memory"
	tenantmemory "github.com/fil-forge/hilt/pkg/store/tenant/memory"
	vaultmemory "github.com/fil-forge/hilt/pkg/vault/memory"
	"github.com/fil-forge/libforge/testutil"
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

	az := auth.NewAuthorizer(zap.NewNop(), accesskeymemory.New(), tenantmemory.New(), providermemory.New(), bucketmemory.New(), vaultmemory.New())
	upload, err := appfx.NewUploadClient(
		id,
		config.UploadConfig{ServiceID: testutil.RandomDID(t).String(), ServiceURL: "http://sprue.test"},
		zap.NewNop(),
	)
	require.NoError(t, err)
	srv := appfx.NewUCANServer(appfx.UCANServerParams{
		Identity: id,
		Routes: []server.Route{
			rpc.NewAuthorizeRequestHandler(zap.NewNop(), az),
			rpc.NewCreateBucketHandler(zap.NewNop(), az, bucketmemory.New(), delegationmemory.New(), upload),
			rpc.NewDeleteBucketHandler(zap.NewNop(), az, bucketmemory.New(), delegationmemory.New(), upload),
			rpc.NewBucketInfoHandler(zap.NewNop(), bucketmemory.New(), accesskeymemory.New(), delegationmemory.New()),
			rpc.NewListBucketsHandler(zap.NewNop(), az, bucketmemory.New()),
		},
	})
	require.NotNil(t, srv)
}
