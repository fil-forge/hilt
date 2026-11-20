package middleware

import (
	"context"
	"time"

	"github.com/fil-forge/hilt/pkg/reqlog"
	"github.com/fil-forge/ucantone/execution"
	"github.com/fil-forge/ucantone/server"
	"github.com/fil-forge/ucantone/server/middleware"
	"go.uber.org/zap"
)

// LogInvocations logs one "invocation handled" line per invocation the route
// executes: its command, issuer, subject and CID, the HTTP request id it
// arrived with, whether its receipt is a success, the failure's name and
// message when it is not, and how long the route took. One HTTP request can
// carry several invocations, which the route handles as one batch, so "took"
// is the batch's duration. The invocation's CID goes in the context the
// handler receives ([reqlog.WithInvocation]), so the lines a handler logs with
// [reqlog.Fields] join this one.
//
// The outcome is decided the way tracing.Handler decides it: a failure on the
// receipt stands, then a panic, a returned error, and a missing receipt each
// count as failures. It belongs outermost, so it times and reports whatever
// the checks inside it decide.
func LogInvocations(logger *zap.Logger) middleware.Middleware {
	return func(route server.Route) server.Route {
		log := logger.With(zap.Stringer("command", route.Command))
		next := route.Handler
		route.Handler = func(items []execution.Batch) error {
			start := time.Now()
			tagged := make([]execution.Batch, len(items))
			for i, item := range items {
				ctx := reqlog.WithInvocation(item.Request.Context(), item.Request.Invocation().Link())
				tagged[i] = execution.Batch{Request: taggedRequest{Request: item.Request, ctx: ctx}, Response: item.Response}
			}

			var err error
			returned := false
			defer func() {
				took := time.Since(start)
				for i, item := range tagged {
					inv := item.Request.Invocation()
					fields := append(reqlog.Fields(item.Request.Context()),
						zap.Stringer("issuer", inv.Issuer()),
						zap.Stringer("subject", inv.Subject()),
						zap.Duration("took", took),
					)
					fields = append(fields, outcome(items[i].Response, returned, err)...)
					log.Info("invocation handled", fields...)
				}
			}()
			err = next(tagged)
			returned = true
			return err
		}
		return route
	}
}

// outcome reports whether the invocation succeeded ("ok") and, when it did
// not, why ("failure", and "error" for the failure's message).
func outcome(res execution.Response, returned bool, err error) []zap.Field {
	if model, ok := failure(res); ok {
		return []zap.Field{zap.Bool("ok", false), zap.String("failure", model.Name()), zap.String("error", model.Message)}
	}
	switch {
	case !returned:
		return []zap.Field{zap.Bool("ok", false), zap.String("error", "handler panicked")}
	case err != nil:
		return []zap.Field{zap.Bool("ok", false), zap.Error(err)}
	case res.Receipt() == nil:
		return []zap.Field{zap.Bool("ok", false), zap.String("error", "handler set no receipt")}
	}
	return []zap.Field{zap.Bool("ok", true)}
}

// taggedRequest hands a handler a context carrying its invocation's CID.
type taggedRequest struct {
	execution.Request
	ctx context.Context
}

func (r taggedRequest) Context() context.Context { return r.ctx }
