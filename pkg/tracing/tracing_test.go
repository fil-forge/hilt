package tracing

import (
	"bytes"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/fil-forge/ucantone/execution"
	"github.com/fil-forge/ucantone/ipld/codec/dagcbor"
	"github.com/fil-forge/ucantone/ipld/datamodel"
	"github.com/fil-forge/ucantone/server"
	"github.com/fil-forge/ucantone/testutil"
	"github.com/fil-forge/ucantone/ucan"
	"github.com/fil-forge/ucantone/ucan/container"
	"github.com/fil-forge/ucantone/ucan/invocation"
	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/propagation"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
	"go.opentelemetry.io/otel/trace"
)

func installRecorder(t *testing.T) *tracetest.SpanRecorder {
	t.Helper()
	rec := tracetest.NewSpanRecorder()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(rec))
	prevTP, prevProp := otel.GetTracerProvider(), otel.GetTextMapPropagator()
	otel.SetTracerProvider(tp)
	otel.SetTextMapPropagator(propagation.TraceContext{})
	t.Cleanup(func() {
		otel.SetTracerProvider(prevTP)
		otel.SetTextMapPropagator(prevProp)
	})
	return rec
}

// newServer returns an echo server with hilt's tracing middleware, serving
// a UCAN server with the span namer and each handler wrapped as hilt
// registers them.
func newServer(t *testing.T, service ucan.Issuer, routes map[ucan.Command]execution.HandlerFunc) *echo.Echo {
	t.Helper()
	srv := server.NewHTTP(service, server.WithEventListener(SpanNamer{}))
	for cmd, fn := range routes {
		srv.Handle(cmd, Handler(cmd, fn))
	}
	e := echo.New()
	e.Use(Middleware())
	e.POST("/", func(c echo.Context) error {
		srv.ServeHTTP(c.Response(), c.Request())
		return nil
	})
	e.GET("/health", func(c echo.Context) error { return c.NoContent(http.StatusOK) })
	e.GET("/things/:id", func(c echo.Context) error { return c.NoContent(http.StatusOK) })
	return e
}

func invocationRequest(t *testing.T, invs ...ucan.Invocation) *http.Request {
	t.Helper()
	var body bytes.Buffer
	require.NoError(t, container.New(container.WithInvocations(invs...)).MarshalCBOR(&body))
	req := httptest.NewRequest(http.MethodPost, "/", &body)
	req.Header.Set("Content-Type", dagcbor.ContentType)
	return req
}

func spansNamed(spans []sdktrace.ReadOnlySpan, name string) []sdktrace.ReadOnlySpan {
	var out []sdktrace.ReadOnlySpan
	for _, s := range spans {
		if s.Name() == name {
			out = append(out, s)
		}
	}
	return out
}

func boolAttr(s sdktrace.ReadOnlySpan, key attribute.Key) (bool, bool) {
	for _, kv := range s.Attributes() {
		if kv.Key == key {
			return kv.Value.AsBool(), true
		}
	}
	return false, false
}

func TestRequestSpanNamedForCommandsWithSpanPerInvocation(t *testing.T) {
	rec := installRecorder(t)
	service := testutil.RandomIssuer(t)
	alice := testutil.RandomIssuer(t)
	e := newServer(t, service, map[ucan.Command]execution.HandlerFunc{
		testutil.ConsoleLogCommand: func(req execution.Request, res execution.Response) error {
			// The handler's context carries its invocation span.
			_, child := Tracer().Start(req.Context(), "child")
			child.End()
			return res.SetSuccess(datamodel.Map{})
		},
		testutil.TestEchoCommand: func(req execution.Request, res execution.Response) error {
			return res.SetFailure(errors.New("echo refused"))
		},
	})

	var invs []ucan.Invocation
	for _, cmd := range []ucan.Command{testutil.ConsoleLogCommand, testutil.ConsoleLogCommand, testutil.TestEchoCommand} {
		inv, err := invocation.Invoke(alice, alice.DID(), cmd, datamodel.Map{"message": "hi"}, invocation.WithAudience(service.DID()))
		require.NoError(t, err)
		invs = append(invs, inv)
	}
	req := invocationRequest(t, invs...)
	req.Header.Set("traceparent", "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01")
	rr := httptest.NewRecorder()
	e.ServeHTTP(rr, req)
	require.Equal(t, http.StatusOK, rr.Code)

	spans := rec.Ended()
	servers := spansNamed(spans, testutil.ConsoleLogCommand.String()+", "+testutil.TestEchoCommand.String())
	require.Len(t, servers, 1)
	srv := servers[0]
	require.Equal(t, trace.SpanKindServer, srv.SpanKind())
	require.Equal(t, "4bf92f3577b34da6a3ce929d0e0e4736", srv.SpanContext().TraceID().String())
	require.Equal(t, "00f067aa0ba902b7", srv.Parent().SpanID().String())

	logs := spansNamed(spans, testutil.ConsoleLogCommand.String())
	require.Len(t, logs, 2)
	for _, s := range logs {
		require.Equal(t, srv.SpanContext().SpanID(), s.Parent().SpanID())
		ok, found := boolAttr(s, "ucan.receipt.ok")
		require.True(t, found)
		require.True(t, ok)
	}
	children := spansNamed(spans, "child")
	require.Len(t, children, 2)
	for _, c := range children {
		require.Contains(t, []trace.SpanID{logs[0].SpanContext().SpanID(), logs[1].SpanContext().SpanID()}, c.Parent().SpanID())
	}

	echoes := spansNamed(spans, testutil.TestEchoCommand.String())
	require.Len(t, echoes, 1)
	ok, found := boolAttr(echoes[0], "ucan.receipt.ok")
	require.True(t, found)
	require.False(t, ok)
	require.Equal(t, codes.Unset, echoes[0].Status().Code)
}

func TestHandlerErrorFailsSpan(t *testing.T) {
	rec := installRecorder(t)
	service := testutil.RandomIssuer(t)
	alice := testutil.RandomIssuer(t)
	e := newServer(t, service, map[ucan.Command]execution.HandlerFunc{
		testutil.ConsoleLogCommand: func(execution.Request, execution.Response) error {
			return errors.New("broken")
		},
	})

	inv, err := invocation.Invoke(alice, alice.DID(), testutil.ConsoleLogCommand, datamodel.Map{}, invocation.WithAudience(service.DID()))
	require.NoError(t, err)
	e.ServeHTTP(httptest.NewRecorder(), invocationRequest(t, inv))

	spans := spansNamed(rec.Ended(), testutil.ConsoleLogCommand.String())
	require.NotEmpty(t, spans)
	var handler sdktrace.ReadOnlySpan
	for _, s := range spans {
		if s.SpanKind() == trace.SpanKindInternal {
			handler = s
		}
	}
	require.NotNil(t, handler)
	require.Equal(t, codes.Error, handler.Status().Code)
	require.Equal(t, "broken", handler.Status().Description)
}

func TestHealthNotTraced(t *testing.T) {
	rec := installRecorder(t)
	e := newServer(t, testutil.RandomIssuer(t), nil)

	rr := httptest.NewRecorder()
	e.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/health", nil))
	require.Equal(t, http.StatusOK, rr.Code)
	require.Empty(t, rec.Ended())
}

func TestRESTSpanNamedForRoute(t *testing.T) {
	rec := installRecorder(t)
	e := newServer(t, testutil.RandomIssuer(t), nil)

	e.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/things/abc123", nil))
	spans := rec.Ended()
	require.Len(t, spans, 1)
	require.Equal(t, "GET /things/:id", spans[0].Name())
}
