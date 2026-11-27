package rpc_test

import (
	"net/url"
	"testing"

	"github.com/fil-forge/hilt/internal/testutil"
	"github.com/fil-forge/hilt/pkg/client/upload"
	"github.com/fil-forge/hilt/pkg/rpc"
	"github.com/fil-forge/hilt/pkg/rpc/service/auth"
	bucketsvc "github.com/fil-forge/hilt/pkg/rpc/service/bucket"
	accesskeypostgres "github.com/fil-forge/hilt/pkg/store/accesskey/postgres"
	bucketpostgres "github.com/fil-forge/hilt/pkg/store/bucket/postgres"
	bucketpolicypostgres "github.com/fil-forge/hilt/pkg/store/bucketpolicy/postgres"
	delegationpostgres "github.com/fil-forge/hilt/pkg/store/delegation/postgres"
	"github.com/fil-forge/hilt/pkg/store/pglock"
	principalpostgres "github.com/fil-forge/hilt/pkg/store/principal/postgres"
	providerpostgres "github.com/fil-forge/hilt/pkg/store/provider/postgres"
	tenantpostgres "github.com/fil-forge/hilt/pkg/store/tenant/postgres"
	usagepostgres "github.com/fil-forge/hilt/pkg/store/usage/postgres"
	vaultmemory "github.com/fil-forge/hilt/pkg/vault/memory"
	"github.com/fil-forge/libforge/identity"
	"github.com/fil-forge/ucantone/server"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

// newRoutes builds every route the RPC server serves, backed by a test database
// and clients pointed at hosts no test reaches. It is the one place the handler
// set is enumerated: a new handler belongs here (and in pkg/fx's RPCModule).
func newRoutes(t *testing.T, id identity.Identity) []server.Route {
	t.Helper()
	pool := testutil.PostgresOrSkip(t)
	az := auth.NewAuthorizer(zap.NewNop(), accesskeypostgres.New(pool), tenantpostgres.New(pool), providerpostgres.New(pool), bucketpostgres.New(pool), principalpostgres.New(pool), bucketpolicypostgres.New(pool), vaultmemory.New(),
		auth.WithSnapshots(pglock.NewSnapshots(pool)))

	up, err := upload.NewClient(testutil.RandomDID(t), url.URL{Scheme: "http", Host: "sprue.test"}, testutil.RandomIssuer(t), upload.WithBaseProofs(delegationpostgres.New(pool)))
	require.NoError(t, err)
	buckets := bucketsvc.New(zap.NewNop(), az, bucketpostgres.New(pool), delegationpostgres.New(pool), accesskeypostgres.New(pool), tenantpostgres.New(pool), bucketpolicypostgres.New(pool), providerpostgres.New(pool), up, nil, nil)

	return []server.Route{
		rpc.NewAuthorizeRequestHandler(zap.NewNop(), az, delegationpostgres.New(pool)),
		rpc.NewCreateBucketHandler(zap.NewNop(), buckets),
		rpc.NewDeleteBucketHandler(zap.NewNop(), buckets),
		rpc.NewBucketInfoHandler(zap.NewNop(), buckets),
		rpc.NewListBucketsHandler(zap.NewNop(), buckets),
		rpc.NewPolicyHandler(zap.NewNop(), buckets),
		rpc.NewReportUsageHandler(zap.NewNop(), bucketpostgres.New(pool), usagepostgres.New(pool)),
		rpc.NewAddProviderHandler(zap.NewNop(), id, providerpostgres.New(pool), delegationpostgres.New(pool), up),
		rpc.NewSetProviderNodesHandler(zap.NewNop(), id, providerpostgres.New(pool), delegationpostgres.New(pool), up),
		rpc.NewListProvidersHandler(zap.NewNop(), id, providerpostgres.New(pool)),
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
		"/s3/bucket/policy",
		"/s3/usage/report",
		"/admin/provider/add",
		"/admin/provider/nodes/set",
		"/admin/provider/list",
	}, commands)
}
