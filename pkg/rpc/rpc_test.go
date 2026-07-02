package rpc_test

import (
	"testing"

	"github.com/fil-forge/hilt/pkg/rpc"
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
		{"list", rpc.NewListBucketsHandler, "/s3/bucket/list"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			route := tc.route(zap.NewNop())
			require.Equal(t, tc.command, route.Command.String())
			require.NotNil(t, route.Handler)
		})
	}
}
