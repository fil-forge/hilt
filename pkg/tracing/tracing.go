// Package tracing is hilt's OpenTelemetry instrumentation: the per-request
// server span, the per-invocation handler spans and the instrumented HTTP
// transport every outbound call goes through. Spans go to the global tracer
// provider, so the host decides where they are exported: `hilt serve`
// installs one with Setup; tests and other hosts install their own or leave
// OpenTelemetry's no-op default.
package tracing

import (
	"bytes"
	"context"
	"net/http"
	"slices"
	"strings"

	edm "github.com/fil-forge/ucantone/errors/datamodel"
	"github.com/fil-forge/ucantone/execution"
	"github.com/fil-forge/ucantone/server"
	"github.com/fil-forge/ucantone/ucan"
	"github.com/labstack/echo/v4"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
)

// Name is the instrumentation scope of hilt's own spans.
const Name = "github.com/fil-forge/hilt"

// Tracer returns hilt's tracer from the global provider.
func Tracer() trace.Tracer {
	return otel.Tracer(Name)
}

// NewHTTPClient returns an HTTP client that records each request as a client
// span and propagates the trace context to the callee.
func NewHTTPClient() *http.Client {
	return &http.Client{Transport: Transport(http.DefaultTransport)}
}

// Transport wraps base so each request is a client span carrying the trace
// context, for clients that bring their own transport.
func Transport(base http.RoundTripper) http.RoundTripper {
	return otelhttp.NewTransport(base)
}

// Middleware starts the server span for each request, continuing a trace
// context the caller sent. The span is named for the method and the matched
// route ("GET /tenants/:id"), so IDs in the path do not each get a name of
// their own; SpanNamer then renames a UCAN request for the commands it
// carries. Health checks are not traced: an orchestrator polls them every few
// seconds.
func Middleware() echo.MiddlewareFunc {
	start := echo.WrapMiddleware(otelhttp.NewMiddleware("hilt",
		otelhttp.WithSpanNameFormatter(func(_ string, r *http.Request) string {
			return r.Method
		}),
		otelhttp.WithFilter(func(r *http.Request) bool {
			return r.URL.Path != "/health"
		}),
	))
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return start(func(c echo.Context) error {
			if route := c.Path(); route != "" {
				trace.SpanFromContext(c.Request().Context()).SetName(c.Request().Method + " " + route)
			}
			return next(c)
		})
	}
}

// SpanNamer is a UCAN server event listener that names the request's server
// span for the commands it invokes ("/space/blob/add" rather than "POST /"). A
// batch of several commands is named for each distinct one, sorted, so the
// same mix of commands always gets the same name.
type SpanNamer struct{}

var _ server.EventListener = SpanNamer{}

func (SpanNamer) OnRequestDecode(ctx context.Context, ct ucan.Container) error {
	var cmds []string
	for _, inv := range ct.Invocations() {
		cmd := inv.Command().String()
		if !slices.Contains(cmds, cmd) {
			cmds = append(cmds, cmd)
		}
	}
	if len(cmds) > 0 {
		slices.Sort(cmds)
		trace.SpanFromContext(ctx).SetName(strings.Join(cmds, ", "))
	}
	return nil
}

func (SpanNamer) OnResponseEncode(context.Context, ucan.Container) error { return nil }

// Handler wraps a UCAN handler in a span per invocation, named for its
// command, so the invocations of a batch each get their own span under the
// request's, and work a handler does for one invocation nests under that
// invocation's span. The spans start once the batch's invocations have been
// validated, so the gap before them is validation, and they end when the
// handler returns for the whole batch. A failure receipt is an outcome the
// caller receives, recorded as ucan.receipt.ok=false; an error returned by the
// handler, or the receipt ucantone issues for a per-invocation handler's error
// or panic, also marks the span as failed.
func Handler(cmd ucan.Command, fn execution.BatchHandlerFunc) execution.BatchHandlerFunc {
	tracer := Tracer()
	name := cmd.String()
	return func(items []execution.Batch) error {
		traced := make([]execution.Batch, len(items))
		spans := make([]trace.Span, len(items))
		for i, item := range items {
			ctx, span := tracer.Start(item.Request.Context(), name,
				trace.WithAttributes(attribute.String("ucan.task", item.Request.Invocation().Task().Link().String())),
			)
			spans[i] = span
			traced[i] = execution.Batch{Request: tracedRequest{Request: item.Request, ctx: ctx}, Response: item.Response}
		}

		err := fn(traced)
		for i, span := range spans {
			if err != nil {
				span.RecordError(err)
				span.SetStatus(codes.Error, err.Error())
			} else if rcpt := items[i].Response.Receipt(); rcpt != nil {
				span.SetAttributes(attribute.Bool("ucan.receipt.ok", rcpt.Out().IsOK()))
				if failure, ok := handlerFailure(rcpt); ok {
					span.SetStatus(codes.Error, failure.Message)
				}
			}
			span.End()
		}
		return err
	}
}

// tracedRequest hands a handler its invocation span's context.
type tracedRequest struct {
	execution.Request
	ctx context.Context
}

func (r tracedRequest) Context() context.Context { return r.ctx }

// handlerFailures are the failures ucantone issues when a handler returns an
// error or panics, rather than setting a result: unexpected, so they fail the
// span the way a returned error does.
var handlerFailures = map[string]struct{}{
	execution.HandlerExecutionErrorName: {},
	execution.ExecutionFailureErrorName: {},
}

// handlerFailure reports the failure a receipt carries when it is one of
// [handlerFailures].
func handlerFailure(rcpt ucan.Receipt) (edm.ErrorModel, bool) {
	out := rcpt.Out()
	if !out.IsErr() {
		return edm.ErrorModel{}, false
	}
	_, errBytes := out.Unpack()
	var model edm.ErrorModel
	if err := model.UnmarshalCBOR(bytes.NewReader(errBytes)); err != nil {
		return edm.ErrorModel{}, false
	}
	if _, ok := handlerFailures[model.ErrorName]; !ok {
		return edm.ErrorModel{}, false
	}
	return model, true
}
