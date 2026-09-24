package fx_test

import (
	"testing"

	"github.com/fil-forge/hilt/internal/testutil"
	"github.com/fil-forge/hilt/pkg/config"
	appfx "github.com/fil-forge/hilt/pkg/fx"
	storememory "github.com/fil-forge/hilt/pkg/fx/store/memory"
	vaultmemory "github.com/fil-forge/hilt/pkg/fx/vault/memory"
	"github.com/fil-forge/libforge/identity"
	"github.com/fil-forge/ucantone/did"
	"github.com/fil-forge/ucantone/execution/batch"
	"github.com/fil-forge/ucantone/server"
	"github.com/fil-forge/ucantone/server/middleware"
	"github.com/fil-forge/ucantone/ucan"
	"github.com/fil-forge/ucantone/ucan/delegation"
	"github.com/fil-forge/ucantone/ucan/invocation"
	"github.com/ipfs/go-cid"
	"github.com/stretchr/testify/require"
	"go.uber.org/fx"
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

// newRPCApp builds the RPC module over in-memory backends and returns the two
// route groups and the server built from them, so a test sees the wiring the
// app actually gets (RPCModule decides which group a handler joins). fx.New
// executes Invoke functions immediately, so the values are populated without
// starting the app; nothing here registers a lifecycle hook.
func newRPCApp(t *testing.T) (routes []server.Route, admin []server.Route, srv *server.HTTPServer, id identity.Identity) {
	t.Helper()
	cfg := &config.Config{
		Storage:    config.StorageConfig{Type: config.StorageTypeMemory},
		Vault:      config.VaultConfig{Type: config.VaultTypeMemory},
		Upload:     config.UploadConfig{ServiceID: testutil.RandomDID(t).String(), ServiceURL: "http://sprue.test"},
		Revocation: config.RevocationConfig{ServiceID: testutil.RandomDID(t).String(), ServiceURL: "http://swarf.test"},
	}
	app := fx.New(
		fx.Supply(cfg),
		appfx.ConfigModule,
		appfx.LoggerModule,
		appfx.IdentityModule,
		appfx.RevocationModule,
		appfx.RPCModule,
		storememory.Module,
		vaultmemory.Module,
		fx.NopLogger,
		// The handlers log their rejections; keep the test output quiet.
		fx.Decorate(func(*zap.Logger) *zap.Logger { return zap.NewNop() }),
		fx.Invoke(fx.Annotate(
			func(r []server.Route, a []server.Route, s *server.HTTPServer, i identity.Identity) {
				routes, admin, srv, id = r, a, s, i
			},
			fx.ParamTags(`group:"ucanRoutes"`, `group:"ucanAdminRoutes"`),
		)),
	)
	require.NoError(t, app.Err())
	require.NotNil(t, srv)
	// Both groups are asserted non-empty here because the tests below range over
	// them: an empty group would make those tests pass without asserting a thing.
	require.NotEmpty(t, routes)
	require.NotEmpty(t, admin)
	return routes, admin, srv, id
}

// TestRPCModuleRouteGroups checks which group each handler joins: the admin
// commands, which the service invokes on itself, are the ones served unguarded,
// and every other command is guarded.
func TestRPCModuleRouteGroups(t *testing.T) {
	routes, admin, _, _ := newRPCApp(t)

	require.ElementsMatch(t, []string{
		"/s3/request/authorize",
		"/s3/bucket/create",
		"/s3/bucket/delete",
		"/s3/bucket/info",
		"/s3/bucket/list",
	}, commandsOf(routes))

	require.ElementsMatch(t, []string{
		"/admin/provider/add",
		"/admin/provider/nodes/set",
		"/admin/provider/list",
	}, commandsOf(admin))
}

// TestUCANServerRejectsSelfSigned drives a self-signed invocation — the shape
// that needs no proofs and claims unattenuated authority — through the server
// the app serves. Every command Hilt serves for others rejects it, and so does
// an admin command, which admits only the service's own key.
func TestUCANServerRejectsSelfSigned(t *testing.T) {
	routes, admin, srv, id := newRPCApp(t)
	stranger := testutil.RandomIssuer(t)

	for _, route := range routes {
		t.Run(route.Command.String(), func(t *testing.T) {
			err := executeOn(t, srv, id.DID(), route.Command, stranger, stranger.DID())
			require.ErrorIs(t, err, middleware.ErrSelfSignedInvocation)
		})
	}

	for _, route := range admin {
		t.Run(route.Command.String(), func(t *testing.T) {
			err := executeOn(t, srv, id.DID(), route.Command, stranger, stranger.DID())
			require.ErrorIs(t, err, middleware.ErrUnauthorized)
		})
	}
}

// TestUCANServerRejectsAdminOverAnotherSubject covers the admin routes' subject
// check. An admin command may act only on the service's own authority, so an
// invocation subjected elsewhere is rejected even when the service issues it and
// holds a delegation from that subject — the case the issuer check alone lets
// through.
func TestUCANServerRejectsAdminOverAnotherSubject(t *testing.T) {
	_, admin, srv, id := newRPCApp(t)
	stranger := testutil.RandomIssuer(t)

	for _, route := range admin {
		t.Run(route.Command.String(), func(t *testing.T) {
			// The stranger delegates the command over itself to the service, so the
			// invocation carries a chain the validator accepts and the subject check
			// is what rejects it.
			prf, err := delegation.Delegate(stranger, id.DID(), stranger.DID(), route.Command)
			require.NoError(t, err)

			err = executeOn(t, srv, id.DID(), route.Command, id, stranger.DID(), prf)
			require.ErrorIs(t, err, middleware.ErrInvalidSubject)
		})
	}
}

// TestUCANServerAdmitsTheServiceOnAdminRoutes is the other half: an admin
// command is self-signed by definition, so it must reach its handler when the
// service itself issues it.
func TestUCANServerAdmitsTheServiceOnAdminRoutes(t *testing.T) {
	_, admin, srv, id := newRPCApp(t)

	for _, route := range admin {
		t.Run(route.Command.String(), func(t *testing.T) {
			err := executeOn(t, srv, id.DID(), route.Command, id, id.DID())
			require.NotErrorIs(t, err, middleware.ErrSelfSignedInvocation)
			require.NotErrorIs(t, err, middleware.ErrInvalidSubject)
			require.NotErrorIs(t, err, middleware.ErrUnauthorized)
		})
	}
}

func commandsOf(routes []server.Route) []string {
	cmds := make([]string, 0, len(routes))
	for _, r := range routes {
		cmds = append(cmds, r.Command.String())
	}
	return cmds
}

// executeOn runs one invocation of cmd through the server as a request would
// arrive, returning the failure its receipt carries (nil on success). The
// invocation carries no arguments, so a command that runs rejects it on its own
// terms — which is how these tests tell a rejection by the route's middleware
// from a command that ran.
func executeOn(t *testing.T, srv *server.HTTPServer, service did.DID, cmd ucan.Command, issuer ucan.Issuer, subject did.DID, proofs ...ucan.Delegation) error {
	t.Helper()
	links := make([]cid.Cid, 0, len(proofs))
	for _, p := range proofs {
		links = append(links, p.Link())
	}
	inv, err := invocation.Invoke(issuer, subject, cmd, nil,
		invocation.WithAudience(service), invocation.WithProofs(links...))
	require.NoError(t, err)

	resp, err := srv.ExecuteBatch(batch.NewRequest(t.Context(), []ucan.Invocation{inv}, batch.WithDelegations(proofs...)))
	require.NoError(t, err)
	rcpt, ok := resp.Receipt(inv.Task().Link())
	require.True(t, ok, "the server issued no receipt for the invocation")
	return testutil.ReceiptFailure(t, rcpt)
}
