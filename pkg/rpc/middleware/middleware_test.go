package middleware_test

import (
	"testing"

	"github.com/fil-forge/hilt/internal/testutil"
	hiltmiddleware "github.com/fil-forge/hilt/pkg/rpc/middleware"
	bucketsvc "github.com/fil-forge/hilt/pkg/rpc/service/bucket"
	s3bkt "github.com/fil-forge/libforge/commands/s3/bucket"
	"github.com/fil-forge/ucantone/execution"
	"github.com/fil-forge/ucantone/server"
	"github.com/fil-forge/ucantone/server/middleware"
	"github.com/fil-forge/ucantone/ucan"
	"github.com/fil-forge/ucantone/ucan/invocation"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"
)

// route wraps a command in the logging middleware plus the checks, the way the
// server serves the commands Hilt holds for others.
func route(t *testing.T, logger *zap.Logger, service ucan.Issuer, ran *bool) server.Route {
	t.Helper()
	routes := middleware.Apply([]server.Route{server.NewRoute(s3bkt.List.Command,
		func(req execution.Request, res execution.Response) error {
			*ran = true
			return nil
		},
	)},
		hiltmiddleware.LogRejections(logger),
		middleware.NotSelfSigned(),
		middleware.OnlySubject(service.DID()),
	)
	require.Len(t, routes, 1)
	return routes[0]
}

func TestLogRejections(t *testing.T) {
	service := testutil.RandomIssuer(t)
	agent := testutil.RandomIssuer(t)

	t.Run("logs the rejection with the issuer and subject refused", func(t *testing.T) {
		core, logs := observer.New(zapcore.WarnLevel)
		var ran bool
		err := testutil.ExecuteRoute(t, route(t, zap.New(core), service, &ran), service, agent, agent.DID())
		require.ErrorIs(t, err, middleware.ErrSelfSignedInvocation)
		require.False(t, ran)

		entries := logs.FilterMessage("rejecting invocation").All()
		require.Len(t, entries, 1)
		fields := entries[0].ContextMap()
		require.Equal(t, middleware.SelfSignedInvocationErrorName, fields["reason"])
		require.Equal(t, agent.DID().String(), fields["issuer"])
		require.Equal(t, agent.DID().String(), fields["subject"])
	})

	t.Run("logs nothing when the command runs", func(t *testing.T) {
		core, logs := observer.New(zapcore.WarnLevel)
		var ran bool
		err := testutil.ExecuteRoute(t, route(t, zap.New(core), service, &ran), service, agent, service.DID())
		require.NoError(t, err)
		require.True(t, ran)
		require.Zero(t, logs.Len())
	})

	t.Run("leaves a command's own failure to the command", func(t *testing.T) {
		core, logs := observer.New(zapcore.WarnLevel)
		routes := middleware.Apply([]server.Route{server.NewRoute(s3bkt.List.Command,
			func(req execution.Request, res execution.Response) error {
				return res.SetFailure(bucketsvc.ErrUnknownBucket)
			},
		)}, hiltmiddleware.LogRejections(zap.New(core)))

		err := testutil.ExecuteRoute(t, routes[0], service, agent, service.DID())
		require.ErrorIs(t, err, bucketsvc.ErrUnknownBucket)
		require.Zero(t, logs.Len(), "handlers log their own errors")
	})

	t.Run("logs each rejected invocation of a batch", func(t *testing.T) {
		core, logs := observer.New(zapcore.WarnLevel)
		var ran bool
		r := route(t, zap.New(core), service, &ran)

		var items []execution.Batch
		for _, subject := range []ucan.Principal{agent, service, agent} {
			inv, err := invocation.Invoke(agent, subject.DID(), r.Command, nil, invocation.WithAudience(service.DID()))
			require.NoError(t, err)
			res, err := execution.NewResponse(inv.Task().Link(), execution.WithIssuer(service))
			require.NoError(t, err)
			items = append(items, execution.Batch{Request: execution.NewRequest(t.Context(), inv), Response: res})
		}
		require.NoError(t, r.Handler(items))
		require.True(t, ran, "the invocation the checks accept still runs")
		require.Len(t, logs.FilterMessage("rejecting invocation").All(), 2)
	})
}
