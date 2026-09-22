package middleware_test

import (
	"testing"

	"github.com/fil-forge/hilt/internal/testutil"
	"github.com/fil-forge/hilt/pkg/rpc/middleware"
	s3bkt "github.com/fil-forge/libforge/commands/s3/bucket"
	"github.com/fil-forge/ucantone/did"
	"github.com/fil-forge/ucantone/execution"
	"github.com/fil-forge/ucantone/server"
	"github.com/fil-forge/ucantone/ucan"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

// wrap applies the middleware to a stand-in command that records whether it ran.
func wrap(t *testing.T, called *bool, mw ...middleware.Middleware) server.Route {
	t.Helper()
	routes := middleware.Apply(zap.NewNop(), []server.Route{{
		Command: s3bkt.List.Command,
		Handler: func(req execution.Request, res execution.Response) error {
			*called = true
			return nil
		},
	}}, mw...)
	require.Len(t, routes, 1)
	return routes[0]
}

func TestNotSelfSigned(t *testing.T) {
	service := testutil.RandomIssuer(t)
	provider := testutil.RandomIssuer(t)
	stranger := testutil.RandomIssuer(t)

	tests := []struct {
		name    string
		issuer  ucan.Issuer
		subject did.DID
		wantErr error
	}{
		{
			name:    "rejects an invocation issued by its own subject",
			issuer:  stranger,
			subject: stranger.DID(),
			wantErr: middleware.ErrSelfSignedInvocation,
		},
		{
			name:    "rejects one self-signed by the service itself",
			issuer:  service,
			subject: service.DID(),
			wantErr: middleware.ErrSelfSignedInvocation,
		},
		{
			name:    "runs the command when the issuer is not the subject",
			issuer:  provider,
			subject: service.DID(),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var called bool
			route := wrap(t, &called, middleware.NotSelfSigned())
			err := testutil.ExecuteRoute(t, route, service, tt.issuer, tt.subject)
			requireOutcome(t, err, called, tt.wantErr)
		})
	}
}

func TestOnlySubject(t *testing.T) {
	service := testutil.RandomIssuer(t)
	provider := testutil.RandomIssuer(t)
	stranger := testutil.RandomIssuer(t)

	tests := []struct {
		name    string
		issuer  ucan.Issuer
		subject did.DID
		wantErr error
	}{
		{
			name:    "rejects an invocation subjected to someone else",
			issuer:  provider,
			subject: stranger.DID(),
			wantErr: middleware.ErrInvalidSubject,
		},
		{
			name:    "rejects one subjected to the issuer's own DID",
			issuer:  stranger,
			subject: stranger.DID(),
			wantErr: middleware.ErrInvalidSubject,
		},
		{
			name:    "runs the command when the subject is the service",
			issuer:  provider,
			subject: service.DID(),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var called bool
			route := wrap(t, &called, middleware.OnlySubject(service.DID()))
			err := testutil.ExecuteRoute(t, route, service, tt.issuer, tt.subject)
			requireOutcome(t, err, called, tt.wantErr)
		})
	}
}

func TestOnlyIssuer(t *testing.T) {
	service := testutil.RandomIssuer(t)
	stranger := testutil.RandomIssuer(t)

	tests := []struct {
		name    string
		issuer  ucan.Issuer
		subject did.DID
		wantErr error
	}{
		{
			name:    "rejects an invocation from another issuer",
			issuer:  stranger,
			subject: service.DID(),
			wantErr: middleware.ErrUnauthorized,
		},
		{
			name:    "runs the command for the service's own self-signed invocation",
			issuer:  service,
			subject: service.DID(),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var called bool
			route := wrap(t, &called, middleware.OnlyIssuer(service.DID()))
			err := testutil.ExecuteRoute(t, route, service, tt.issuer, tt.subject)
			requireOutcome(t, err, called, tt.wantErr)
		})
	}
}

// TestApplyOrder checks that the first middleware is the outermost: a
// self-signed invocation over another DID is reported as self-signed, the
// rejection the caller most needs to see.
func TestApplyOrder(t *testing.T) {
	service := testutil.RandomIssuer(t)
	stranger := testutil.RandomIssuer(t)

	var called bool
	route := wrap(t, &called, middleware.NotSelfSigned(), middleware.OnlySubject(service.DID()))
	err := testutil.ExecuteRoute(t, route, service, stranger, stranger.DID())
	requireOutcome(t, err, called, middleware.ErrSelfSignedInvocation)
}

func requireOutcome(t *testing.T, err error, called bool, wantErr error) {
	t.Helper()
	if wantErr == nil {
		require.NoError(t, err)
		require.True(t, called, "the command should have run")
		return
	}
	require.ErrorIs(t, err, wantErr)
	require.False(t, called, "the command should not have run")
}
