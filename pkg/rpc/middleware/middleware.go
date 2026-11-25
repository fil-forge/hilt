// Package middleware holds the Hilt side of the UCAN route middleware: the
// authorization checks themselves live in ucantone's server/middleware, which
// is silent, and [LogRejections] records what they reject. pkg/fx's
// NewUCANServer applies them: the commands Hilt serves for others behind
// NotSelfSigned and OnlySubject, the ones Hilt invokes on itself behind
// OnlyIssuer. The commands a provider invokes on its own authority sit behind
// [OnlySelfSignedByProvider], which is Hilt's own because it reads Hilt's
// provider registry.
package middleware

import (
	"bytes"
	"context"
	"errors"
	"fmt"

	"github.com/fil-forge/hilt/pkg/store"
	"github.com/fil-forge/ucantone/did"
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

// ProviderLookup reports whether a DID is a registered provider. It returns
// [store.ErrRecordNotFound] when it is not.
type ProviderLookup func(ctx context.Context, id did.DID) error

// OnlySelfSignedByProvider accepts an invocation only when its issuer is its
// own subject and a registered provider. It guards the commands a provider
// invokes on its own authority, with the service as audience: a report of
// what the provider itself did, which needs no authority from anyone else.
//
// A self-signed invocation carries no proofs, so anyone holding any key can
// produce one. What makes these safe is the registry: the service acts only
// for the providers it has registered, and the command is one whose effect is
// confined to what the issuer may say about itself.
//
// An invocation whose issuer and subject differ is refused as
// [middleware.ErrInvalidSubject], and one from anyone but a registered provider
// as [middleware.ErrUnauthorized].
func OnlySelfSignedByProvider(registered ProviderLookup) middleware.Middleware {
	return func(route server.Route) server.Route {
		next := route.Handler
		if next == nil {
			return route
		}
		route.Handler = func(items []execution.Batch) error {
			accepted := make([]execution.Batch, 0, len(items))
			for _, item := range items {
				inv := item.Request.Invocation()
				var rejection error
				switch err := registered(item.Request.Context(), inv.Issuer()); {
				case inv.Issuer() != inv.Subject():
					rejection = middleware.ErrInvalidSubject
				case errors.Is(err, store.ErrRecordNotFound):
					rejection = middleware.ErrUnauthorized
				case err != nil:
					return fmt.Errorf("looking up provider %s: %w", inv.Issuer(), err)
				}
				if rejection != nil {
					if err := item.Response.SetFailure(rejection); err != nil {
						return err
					}
					continue
				}
				accepted = append(accepted, item)
			}
			if len(accepted) == 0 {
				return nil
			}
			return next(accepted)
		}
		return route
	}
}
