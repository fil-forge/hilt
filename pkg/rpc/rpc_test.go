package rpc_test

import (
	"net/url"
	"testing"

	"github.com/fil-forge/hilt/internal/testutil"
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
	swarfclient "github.com/fil-forge/swarf/pkg/client"
	"github.com/fil-forge/ucantone/server"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

// newRoutes builds every route the RPC server serves, backed by in-memory stores
// and clients pointed at hosts no test reaches. It is the one place the handler
// set is enumerated: a new handler belongs here (and in pkg/fx's RPCModule).
func newRoutes(t *testing.T, id identity.Identity) []server.Route {
	t.Helper()
	az := auth.NewAuthorizer(zap.NewNop(), accesskeymemory.New(), tenantmemory.New(), providermemory.New(), bucketmemory.New(), vaultmemory.New())

	up, err := upload.NewClient(testutil.RandomDID(t), url.URL{Scheme: "http", Host: "sprue.test"}, testutil.RandomIssuer(t), upload.WithBaseProofs(delegationmemory.New()))
	require.NoError(t, err)
	revocations, err := swarfclient.New(testutil.RandomDID(t), url.URL{Scheme: "http", Host: "swarf.test"})
	require.NoError(t, err)
	buckets := bucketsvc.New(zap.NewNop(), az, bucketmemory.New(), delegationmemory.New(), accesskeymemory.New(), up, revocations)

	return []server.Route{
		rpc.NewAuthorizeRequestHandler(zap.NewNop(), az),
		rpc.NewCreateBucketHandler(zap.NewNop(), buckets),
		rpc.NewDeleteBucketHandler(zap.NewNop(), buckets),
		rpc.NewBucketInfoHandler(zap.NewNop(), buckets),
		rpc.NewListBucketsHandler(zap.NewNop(), buckets),
		rpc.NewAddProviderHandler(zap.NewNop(), id, providermemory.New(), delegationmemory.New(), up),
		rpc.NewSetProviderNodesHandler(zap.NewNop(), id, providermemory.New(), delegationmemory.New(), up),
		rpc.NewListProvidersHandler(zap.NewNop(), id, providermemory.New()),
	}
}

// TestHandlerCommands checks each handler constructor wires up the right command
// and a non-nil handler.
func TestHandlerCommands(t *testing.T) {
	id, err := identity.New("", "")
	require.NoError(t, err)

	var commands []string
	for _, route := range newRoutes(t, id) {
		require.NotNil(t, route.Handler, route.Command.String())
		commands = append(commands, route.Command.String())
	}

	require.ElementsMatch(t, []string{
		"/s3/request/authorize",
		"/s3/bucket/create",
		"/s3/bucket/delete",
		"/s3/bucket/info",
		"/s3/bucket/list",
		"/admin/provider/add",
		"/admin/provider/nodes/set",
		"/admin/provider/list",
	}, commands)
}
