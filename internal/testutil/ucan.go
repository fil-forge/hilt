package testutil

import (
	"bytes"
	"testing"

	"github.com/fil-forge/ucantone/did"
	edm "github.com/fil-forge/ucantone/errors/datamodel"
	"github.com/fil-forge/ucantone/execution"
	"github.com/fil-forge/ucantone/server"
	"github.com/fil-forge/ucantone/ucan"
	"github.com/fil-forge/ucantone/ucan/invocation"
	"github.com/stretchr/testify/require"
)

// ExecuteRoute runs a route's handler over an invocation of the route's own
// command, issued by issuer over subject and addressed to the service. It
// returns the failure the receipt carries, or the error the handler returned;
// nil when the handler succeeded and set no failure.
//
// The invocation carries no arguments, so a command that runs rejects it on its
// own terms — which is how a caller tells a rejection by the route's middleware
// from a command that ran.
func ExecuteRoute(t *testing.T, route server.Route, service ucan.Issuer, issuer ucan.Issuer, subject did.DID) error {
	t.Helper()
	inv, err := invocation.Invoke(issuer, subject, route.Command, nil, invocation.WithAudience(service.DID()))
	require.NoError(t, err)

	req := execution.NewRequest(t.Context(), inv)
	res, err := execution.NewResponse(inv.Task().Link(), execution.WithIssuer(service))
	require.NoError(t, err)
	if err := route.Handler(req, res); err != nil {
		return err
	}

	return ReceiptFailure(t, res.Receipt())
}

// ReceiptFailure returns the failure a receipt carries, decoded as the standard
// error model so it can be matched against a named sentinel; nil when the
// receipt reports success, or when there is no receipt because the handler set
// no result.
func ReceiptFailure(t *testing.T, rcpt ucan.Receipt) error {
	t.Helper()
	if rcpt == nil {
		return nil
	}
	out := rcpt.Out()
	if !out.IsErr() {
		return nil
	}
	_, errBytes := out.Unpack()
	var model edm.ErrorModel
	require.NoError(t, model.UnmarshalCBOR(bytes.NewReader(errBytes)))
	return model
}
