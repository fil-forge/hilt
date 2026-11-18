// Package reqlog carries the ids that join Hilt's log lines for one request:
// the HTTP request id, which the request line logs, and the CID of the UCAN
// invocation being executed, which the invocation line logs. A service that
// logs work done for a request adds [Fields] to its line, so an operator can
// find the request and the invocation the work belongs to.
package reqlog

import (
	"context"

	"github.com/ipfs/go-cid"
	"go.uber.org/zap"
)

type requestIDKey struct{}

type invocationKey struct{}

// WithRequestID returns ctx carrying the HTTP request id.
func WithRequestID(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, requestIDKey{}, id)
}

// WithInvocation returns ctx carrying the CID of the UCAN invocation being
// executed.
func WithInvocation(ctx context.Context, inv cid.Cid) context.Context {
	return context.WithValue(ctx, invocationKey{}, inv)
}

// RequestID returns the HTTP request id ctx carries, if any.
func RequestID(ctx context.Context) (string, bool) {
	id, ok := ctx.Value(requestIDKey{}).(string)
	return id, ok && id != ""
}

// Fields returns the request id ("request_id") and the invocation CID
// ("invocation") ctx carries, each only when present.
func Fields(ctx context.Context) []zap.Field {
	var fields []zap.Field
	if id, ok := RequestID(ctx); ok {
		fields = append(fields, zap.String("request_id", id))
	}
	if inv, ok := ctx.Value(invocationKey{}).(cid.Cid); ok && inv.Defined() {
		fields = append(fields, zap.Stringer("invocation", inv))
	}
	return fields
}
