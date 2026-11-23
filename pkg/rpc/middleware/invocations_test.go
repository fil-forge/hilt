package middleware_test

import (
	"errors"
	"testing"

	"github.com/fil-forge/hilt/internal/testutil"
	"github.com/fil-forge/hilt/pkg/reqlog"
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

// invoke runs handler behind LogInvocations over one invocation of the List
// command, issued by agent over service, in a context carrying request id
// "req-1". It returns the invocation and the fields of every
// "invocation handled" line, with "took" checked and dropped.
func invoke(t *testing.T, handler execution.BatchHandlerFunc) (ucan.Invocation, []map[string]any) {
	t.Helper()
	service := testutil.RandomIssuer(t)
	agent := testutil.RandomIssuer(t)
	core, logs := observer.New(zapcore.InfoLevel)
	routes := middleware.Apply([]server.Route{server.NewBatchRoute(s3bkt.List.Command, handler)},
		hiltmiddleware.LogInvocations(zap.New(core)))

	inv, err := invocation.Invoke(agent, service.DID(), s3bkt.List.Command, nil, invocation.WithAudience(service.DID()))
	require.NoError(t, err)
	res, err := execution.NewResponse(inv.Task().Link(), execution.WithIssuer(service))
	require.NoError(t, err)
	req := execution.NewRequest(reqlog.WithRequestID(t.Context(), "req-1"), inv)
	func() {
		defer func() { _ = recover() }()
		_ = routes[0].Handler([]execution.Batch{{Request: req, Response: res}})
	}()

	var lines []map[string]any
	for _, entry := range logs.FilterMessage("invocation handled").All() {
		fields := entry.ContextMap()
		require.Contains(t, fields, "took")
		delete(fields, "took")
		lines = append(lines, fields)
	}
	return inv, lines
}

// line is the "invocation handled" line LogInvocations writes for inv, with
// the outcome fields given.
func line(inv ucan.Invocation, outcome map[string]any) map[string]any {
	fields := map[string]any{
		"command":    s3bkt.List.Command.String(),
		"request_id": "req-1",
		"invocation": inv.Link().String(),
		"issuer":     inv.Issuer().String(),
		"subject":    inv.Subject().String(),
	}
	for k, v := range outcome {
		fields[k] = v
	}
	return fields
}

func TestLogInvocations(t *testing.T) {
	cases := []struct {
		name    string
		handler execution.BatchHandlerFunc
		outcome map[string]any
	}{
		{
			name: "a success",
			handler: func(items []execution.Batch) error {
				return items[0].Response.SetSuccess(&s3bkt.ListOK{})
			},
			outcome: map[string]any{"ok": true},
		},
		{
			name: "a failure receipt",
			handler: func(items []execution.Batch) error {
				return items[0].Response.SetFailure(bucketsvc.ErrUnknownBucket)
			},
			outcome: map[string]any{"ok": false, "failure": bucketsvc.UnknownBucketErrorName, "error": bucketsvc.ErrUnknownBucket.Error()},
		},
		{
			name:    "an error returned by the handler",
			handler: func([]execution.Batch) error { return errors.New("broken") },
			outcome: map[string]any{"ok": false, "error": "broken"},
		},
		{
			name:    "a panic",
			handler: func([]execution.Batch) error { panic("handler exploded") },
			outcome: map[string]any{"ok": false, "error": "handler panicked"},
		},
		{
			name:    "no receipt",
			handler: func([]execution.Batch) error { return nil },
			outcome: map[string]any{"ok": false, "error": "handler set no receipt"},
		},
	}
	for _, c := range cases {
		t.Run("logs "+c.name, func(t *testing.T) {
			inv, lines := invoke(t, c.handler)
			require.Equal(t, []map[string]any{line(inv, c.outcome)}, lines)
		})
	}

	t.Run("hands the handler a context carrying the request and invocation ids", func(t *testing.T) {
		var got []zapcore.Field
		inv, _ := invoke(t, func(items []execution.Batch) error {
			got = reqlog.Fields(items[0].Request.Context())
			return items[0].Response.SetSuccess(&s3bkt.ListOK{})
		})
		require.Equal(t, []zapcore.Field{zap.String("request_id", "req-1"), zap.Stringer("invocation", inv.Link())}, got)
	})
}
