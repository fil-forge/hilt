package rpc_test

import (
	"testing"

	"github.com/fil-forge/hilt/pkg/rpc"
	accesskeymemory "github.com/fil-forge/hilt/pkg/store/accesskey/memory"
	bucketmemory "github.com/fil-forge/hilt/pkg/store/bucket/memory"
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
		{"authorize", rpc.NewAuthorizeRequestHandler, "/s3/request/authorize"},
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

	t.Run("list", func(t *testing.T) {
		route := rpc.NewListBucketsHandler(zap.NewNop(), accesskeymemory.New(), tenantmemory.New(), bucketmemory.New(), vaultmemory.New())
		require.Equal(t, "/s3/bucket/list", route.Command.String())
		require.NotNil(t, route.Handler)
	})
}
