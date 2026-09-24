// Package middleware holds the Hilt side of the UCAN route middleware: the
// authorization checks themselves live in ucantone's server/middleware, which
// is silent, and [LogRejections] records what they reject. pkg/fx's
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
// with the issuer and subject that were refused. It belongs outermost, so it
// sees whatever the checks inside it record on the response.
func LogRejections(logger *zap.Logger) middleware.Middleware {
	return func(route server.Route) server.Route {
		log := logger.With(zap.Stringer("command", route.Command))
		next := route.Handler
		route.Handler = func(req execution.Request, res execution.Response) error {
			if err := next(req, res); err != nil {
				return err
			}
			name, ok := failureName(res)
			if !ok {
				return nil
			}
			if _, rejected := rejections[name]; !rejected {
				return nil
			}
			inv := req.Invocation()
			log.Warn("rejecting invocation",
				zap.String("reason", name),
				zap.Stringer("issuer", inv.Issuer()),
				zap.Stringer("subject", inv.Subject()),
			)
			return nil
		}
		return route
	}
}

// failureName reports the name of the failure the response carries, if it
// carries one.
func failureName(res execution.Response) (string, bool) {
	rcpt := res.Receipt()
	if rcpt == nil {
		return "", false
	}
	out := rcpt.Out()
	if !out.IsErr() {
		return "", false
	}
	_, errBytes := out.Unpack()
	var model edm.ErrorModel
	if err := model.UnmarshalCBOR(bytes.NewReader(errBytes)); err != nil {
		return "", false
	}
	return model.Name(), true
}
