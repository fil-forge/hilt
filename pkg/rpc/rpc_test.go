package rpc_test

import (
	"testing"

	"github.com/fil-forge/hilt/pkg/rpc"
	"github.com/fil-forge/hilt/pkg/rpc/service/auth"
	accesskeymemory "github.com/fil-forge/hilt/pkg/store/accesskey/memory"
	bucketmemory "github.com/fil-forge/hilt/pkg/store/bucket/memory"
	providermemory "github.com/fil-forge/hilt/pkg/store/provider/memory"
	tenantmemory "github.com/fil-forge/hilt/pkg/store/tenant/memory"
	vaultmemory "github.com/fil-forge/hilt/pkg/vault/memory"
	"github.com/fil-forge/ucantone/server"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

func TestHandlerCommands(t *testing.T) {
	cases := []struct {
		name    string
		route   func(*zap.Logger) server.Route
		command string
	}{
		{"create", rpc.NewCreateBucketHandler, "/s3/bucket/create"},
		{"delete", rpc.NewDeleteBucketHandler, "/s3/bucket/delete"},
		{"info", rpc.NewBucketInfoHandler, "/s3/bucket/info"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			route := tc.route(zap.NewNop())
			require.Equal(t, tc.command, route.Command.String())
			require.NotNil(t, route.Handler)
		})
	}

	az := auth.NewAuthorizer(zap.NewNop(), accesskeymemory.New(), tenantmemory.New(), providermemory.New(), vaultmemory.New())

	t.Run("list", func(t *testing.T) {
		route := rpc.NewListBucketsHandler(zap.NewNop(), az, bucketmemory.New())
		require.Equal(t, "/s3/bucket/list", route.Command.String())
		require.NotNil(t, route.Handler)
	})

	t.Run("authorize", func(t *testing.T) {
		route := rpc.NewAuthorizeRequestHandler(zap.NewNop(), az, bucketmemory.New())
		require.Equal(t, "/s3/request/authorize", route.Command.String())
		require.NotNil(t, route.Handler)
	})
}
