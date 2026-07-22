package rpc_test

import (
	"net/url"
	"testing"

	"github.com/fil-forge/hilt/pkg/client/upload"
	"github.com/fil-forge/hilt/pkg/rpc"
	"github.com/fil-forge/hilt/pkg/rpc/service/auth"
	bucketsvc "github.com/fil-forge/hilt/pkg/rpc/service/bucket"
	accesskeymemory "github.com/fil-forge/hilt/pkg/store/accesskey/memory"
	bucketmemory "github.com/fil-forge/hilt/pkg/store/bucket/memory"
	delegationmemory "github.com/fil-forge/hilt/pkg/store/delegation/memory"
	providermemory "github.com/fil-forge/hilt/pkg/store/provider/memory"
	tenantmemory "github.com/fil-forge/hilt/pkg/store/tenant/memory"
	vaultmemory "github.com/fil-forge/hilt/pkg/vault/memory"
	"github.com/fil-forge/libforge/identity"
	"github.com/fil-forge/libforge/testutil"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

// TestHandlerCommands checks each handler constructor wires up the right command
// and a non-nil handler.
func TestHandlerCommands(t *testing.T) {
	az := auth.NewAuthorizer(zap.NewNop(), accesskeymemory.New(), tenantmemory.New(), providermemory.New(), bucketmemory.New(), vaultmemory.New())

	up, err := upload.NewClient(testutil.RandomDID(t), url.URL{Scheme: "http", Host: "sprue.test"}, testutil.RandomIssuer(t), upload.WithBaseProofs(delegationmemory.New()))
	require.NoError(t, err)
	buckets := bucketsvc.New(zap.NewNop(), az, bucketmemory.New(), delegationmemory.New(), accesskeymemory.New(), up)

	t.Run("list", func(t *testing.T) {
		route := rpc.NewListBucketsHandler(zap.NewNop(), buckets)
		require.Equal(t, "/s3/bucket/list", route.Command.String())
		require.NotNil(t, route.Handler)
	})

	t.Run("authorize", func(t *testing.T) {
		route := rpc.NewAuthorizeRequestHandler(zap.NewNop(), az)
		require.Equal(t, "/s3/request/authorize", route.Command.String())
		require.NotNil(t, route.Handler)
	})

	t.Run("create", func(t *testing.T) {
		route := rpc.NewCreateBucketHandler(zap.NewNop(), buckets)
		require.Equal(t, "/s3/bucket/create", route.Command.String())
		require.NotNil(t, route.Handler)
	})

	t.Run("delete", func(t *testing.T) {
		route := rpc.NewDeleteBucketHandler(zap.NewNop(), buckets)
		require.Equal(t, "/s3/bucket/delete", route.Command.String())
		require.NotNil(t, route.Handler)
	})

	t.Run("info", func(t *testing.T) {
		route := rpc.NewBucketInfoHandler(zap.NewNop(), buckets)
		require.Equal(t, "/s3/bucket/info", route.Command.String())
		require.NotNil(t, route.Handler)
	})

	t.Run("provider add", func(t *testing.T) {
		id, err := identity.New("", "")
		require.NoError(t, err)
		route := rpc.NewAddProviderHandler(zap.NewNop(), id, providermemory.New())
		require.Equal(t, "/admin/provider/add", route.Command.String())
		require.NotNil(t, route.Handler)
	})
}
