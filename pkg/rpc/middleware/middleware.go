// Package middleware holds the authorization checks the UCAN RPC routes are
// served behind. Each wraps a [server.Route]'s handler, so it runs after the
// ucantone dispatcher has validated the invocation and before the command sees
// it, and records its rejection as the receipt's failure. pkg/fx's
// NewUCANServer applies them: the commands Hilt serves for others behind
// [NotSelfSigned] and [OnlySubject], the ones Hilt invokes on itself behind
// [OnlyIssuer].
package middleware

import (
	"github.com/fil-forge/ucantone/did"
	ucanerrors "github.com/fil-forge/ucantone/errors"
	"github.com/fil-forge/ucantone/execution"
	"github.com/fil-forge/ucantone/server"
	"go.uber.org/zap"
)

// Error names for the rejections, exported so callers can match on the stable
// Name() of a serialized failure.
const (
	SelfSignedInvocationErrorName = "SelfSignedInvocation"
	InvalidSubjectErrorName       = "InvalidSubject"
	UnauthorizedErrorName         = "Unauthorized"
)

var (
	// ErrSelfSignedInvocation is returned when an invocation's issuer is its own
	// subject. Such an invocation carries its own authority and needs no proofs,
	// so only a command the service invokes on itself may be issued that way.
	ErrSelfSignedInvocation = ucanerrors.New(SelfSignedInvocationErrorName, "an invocation may not be issued by its own subject")
	// ErrInvalidSubject is returned when an invocation's subject is not the one
	// the command is served for. Authority over it is that subject's to delegate.
	ErrInvalidSubject = ucanerrors.New(InvalidSubjectErrorName, "the subject of this invocation must be the service")
	// ErrUnauthorized is returned when an invocation's issuer is not the one
	// entitled to the command.
	ErrUnauthorized = ucanerrors.New(UnauthorizedErrorName, "only the service identity may perform this operation")
)

// Middleware wraps a command handler with a check made before the command runs.
// It is given a logger scoped to the command it wraps.
type Middleware func(log *zap.Logger, next execution.HandlerFunc) execution.HandlerFunc

// Apply returns the routes with each middleware wrapped around their handlers,
// the first one outermost.
func Apply(logger *zap.Logger, routes []server.Route, middleware ...Middleware) []server.Route {
	applied := make([]server.Route, 0, len(routes))
	for _, r := range routes {
		log := logger.With(zap.Stringer("command", r.Command))
		for i := len(middleware) - 1; i >= 0; i-- {
			r.Handler = middleware[i](log, r.Handler)
		}
		applied = append(applied, r)
	}
	return applied
}

// NotSelfSigned rejects an invocation issued by its own subject. Such an
// invocation proves nothing: the UCAN rules give it the subject's full authority
// with no delegation proofs, so anyone holding any key can produce one. A
// command guarded by it requires authority that came from somewhere else.
func NotSelfSigned() Middleware {
	return func(log *zap.Logger, next execution.HandlerFunc) execution.HandlerFunc {
		return func(req execution.Request, res execution.Response) error {
			inv := req.Invocation()
			if inv.Issuer() == inv.Subject() {
				log.Warn("rejecting self-signed invocation", zap.Stringer("issuer", inv.Issuer()))
				return res.SetFailure(ErrSelfSignedInvocation)
			}
			return next(req, res)
		}
	}
}

// OnlySubject rejects an invocation subjected to anyone but subject, so the
// authority the caller presents has to trace back to the service rather than to
// a key the caller owns.
func OnlySubject(subject did.DID) Middleware {
	return func(log *zap.Logger, next execution.HandlerFunc) execution.HandlerFunc {
		return func(req execution.Request, res execution.Response) error {
			inv := req.Invocation()
			if inv.Subject() != subject {
				log.Warn("rejecting invocation subjected elsewhere",
					zap.Stringer("issuer", inv.Issuer()), zap.Stringer("subject", inv.Subject()))
				return res.SetFailure(ErrInvalidSubject)
			}
			return next(req, res)
		}
	}
}

// OnlyIssuer rejects an invocation issued by anyone but issuer. It guards the
// commands the service invokes on itself, which are self-signed by definition
// and so cannot be guarded by [NotSelfSigned]: what makes them safe is that only
// the service's own key can produce them.
func OnlyIssuer(issuer did.DID) Middleware {
	return func(log *zap.Logger, next execution.HandlerFunc) execution.HandlerFunc {
		return func(req execution.Request, res execution.Response) error {
			inv := req.Invocation()
			if inv.Issuer() != issuer {
				log.Warn("rejecting invocation from an unauthorized issuer", zap.Stringer("issuer", inv.Issuer()))
				return res.SetFailure(ErrUnauthorized)
			}
			return next(req, res)
		}
	}
}
