// Package middleware holds the Hilt side of the UCAN route middleware: the
// authorization checks themselves live in ucantone's server/middleware, which
// is silent, and [LogRejections] records what they reject. [LogInvocations]
// logs every invocation a route executes, with its outcome. pkg/fx's
// NewUCANServer applies them: the commands Hilt serves for others behind
// NotSelfSigned and OnlySubject, the ones Hilt invokes on itself behind
// OnlyIssuer.
package middleware

import (
	"bytes"

	edm "github.com/fil-forge/ucantone/errors/datamodel"
	"github.com/fil-forge/ucantone/execution"
	"github.com/fil-forge/ucantone/server"
	"github.com/fil-forge/ucantone/server/middleware"
	"go.uber.org/zap"
)

// rejections are the failures the authorization middleware records, by name.
// Anything else in a receipt came from the command itself, which logs its own
// errors.
var rejections = map[string]struct{}{
	middleware.SelfSignedInvocationErrorName: {},
	middleware.InvalidSubjectErrorName:       {},
	middleware.UnauthorizedErrorName:         {},
}

// LogRejections logs an invocation the authorization middleware turned away,
// with the issuer and subject that were refused. It belongs outside the
// checks, so it sees whatever they record on the response.
func LogRejections(logger *zap.Logger) middleware.Middleware {
	return func(route server.Route) server.Route {
		log := logger.With(zap.Stringer("command", route.Command))
		next := route.Handler
		route.Handler = func(items []execution.Batch) error {
			// The checks inside record their rejections before the command
			// runs, so they are logged even when the command then fails.
			err := next(items)
			for _, item := range items {
				name, ok := failureName(item.Response)
				if !ok {
					continue
				}
				if _, rejected := rejections[name]; !rejected {
					continue
				}
				inv := item.Request.Invocation()
				log.Warn("rejecting invocation",
					zap.String("reason", name),
					zap.Stringer("issuer", inv.Issuer()),
					zap.Stringer("subject", inv.Subject()),
				)
			}
			return err
		}
		return route
	}
}

// failureName reports the name of the failure the response carries, if it
// carries one.
func failureName(res execution.Response) (string, bool) {
	model, ok := failure(res)
	return model.Name(), ok
}

// failure reports the failure the response carries, if it carries one.
func failure(res execution.Response) (edm.ErrorModel, bool) {
	rcpt := res.Receipt()
	if rcpt == nil {
		return edm.ErrorModel{}, false
	}
	out := rcpt.Out()
	if !out.IsErr() {
		return edm.ErrorModel{}, false
	}
	_, errBytes := out.Unpack()
	var model edm.ErrorModel
	if err := model.UnmarshalCBOR(bytes.NewReader(errBytes)); err != nil {
		return edm.ErrorModel{}, false
	}
	return model, true
}
