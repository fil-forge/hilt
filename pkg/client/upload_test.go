package client_test

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"testing"

	"github.com/fil-forge/hilt/internal/testutil"
	"github.com/fil-forge/hilt/pkg/client"
	blobcmds "github.com/fil-forge/libforge/commands/blob"
	customercmds "github.com/fil-forge/libforge/commands/customer"
	providercmds "github.com/fil-forge/libforge/commands/provider"
	ucanlib "github.com/fil-forge/libforge/ucan"
	"github.com/fil-forge/ucantone/binding"
	"github.com/fil-forge/ucantone/did"
	"github.com/fil-forge/ucantone/server"
	"github.com/fil-forge/ucantone/ucan"
	"github.com/fil-forge/ucantone/ucan/container"
	"github.com/ipfs/go-cid"
	"github.com/stretchr/testify/require"
)

// newClient builds an UploadClient whose transport is the given in-process
// server, exercising NewUploadClient itself.
func newClient(t *testing.T, service ucan.Issuer, srv *server.HTTPServer, issuer ucan.Issuer, proofs ucanlib.ProofStore) *client.UploadClient {
	t.Helper()
	u, err := url.Parse("http://upload.test")
	require.NoError(t, err)
	c, err := client.NewUploadClient(service.DID(), *u, issuer, proofs,
		client.WithHTTPClient(&http.Client{Transport: srv}))
	require.NoError(t, err)
	return c
}

// errProofStore is a ProofStore whose ProofChain always fails.
type errProofStore struct{ err error }

func (e errProofStore) ProofChain(ctx context.Context, aud did.DID, cmd ucan.Command, sub did.DID) ([]ucan.Delegation, []cid.Cid, error) {
	return nil, nil, e.err
}

// errRoundTripper is an http.RoundTripper that always fails, forcing Execute to
// return an error.
type errRoundTripper struct{}

func (errRoundTripper) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, errors.New("transport boom")
}

func TestRegisterCustomer(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		service := testutil.RandomIssuer(t)
		alice := testutil.RandomIssuer(t)
		customerDID := testutil.RandomDID(t)
		product := testutil.RandomDID(t)
		details := map[string]string{"name": "Acme"}

		// service delegates /customer/add to alice (root: subject == issuer).
		dlg, err := customercmds.Add.Delegate(service, alice.DID(), service.DID())
		require.NoError(t, err)
		proofs := ucanlib.NewContainerProofStore(container.New(container.WithDelegations(dlg)))

		var gotArgs *customercmds.AddArguments
		var gotAud did.DID
		srv := server.NewHTTP(service)
		srv.Handle(customercmds.Add.Command, customercmds.Add.Handler(
			func(req *binding.Request[*customercmds.AddArguments], res *binding.Response[*customercmds.AddOK]) error {
				gotArgs = req.Task().Arguments()
				gotAud = req.Invocation().Audience()
				return res.SetSuccess(&customercmds.AddOK{})
			}))

		c := newClient(t, service, srv, alice, proofs)
		err = c.RegisterCustomer(t.Context(), customerDID, product, details)
		require.NoError(t, err)

		require.Equal(t, customerDID, gotArgs.Customer)
		require.Equal(t, product, gotArgs.Product)
		require.Equal(t, details, gotArgs.Details)
		require.Equal(t, service.DID(), gotAud)
	})

	t.Run("proof chain error", func(t *testing.T) {
		service := testutil.RandomIssuer(t)
		alice := testutil.RandomIssuer(t)
		srv := server.NewHTTP(service)

		c := newClient(t, service, srv, alice, errProofStore{err: errors.New("boom")})
		err := c.RegisterCustomer(t.Context(), testutil.RandomDID(t), testutil.RandomDID(t), nil)
		require.Error(t, err)
		require.Contains(t, err.Error(), "getting proof chain")
	})

	t.Run("execution error", func(t *testing.T) {
		service := testutil.RandomIssuer(t)
		alice := testutil.RandomIssuer(t)

		dlg, err := customercmds.Add.Delegate(service, alice.DID(), service.DID())
		require.NoError(t, err)
		proofs := ucanlib.NewContainerProofStore(container.New(container.WithDelegations(dlg)))

		u, err := url.Parse("http://upload.test")
		require.NoError(t, err)
		c, err := client.NewUploadClient(service.DID(), *u, alice, proofs,
			client.WithHTTPClient(&http.Client{Transport: errRoundTripper{}}))
		require.NoError(t, err)

		err = c.RegisterCustomer(t.Context(), testutil.RandomDID(t), testutil.RandomDID(t), nil)
		require.Error(t, err)
	})
}

func TestProvisionSpace(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		service := testutil.RandomIssuer(t)
		account := testutil.RandomIssuer(t)
		space := testutil.RandomDID(t)

		var gotArgs *providercmds.AddArguments
		var gotAud did.DID
		srv := server.NewHTTP(service)
		srv.Handle(providercmds.Add.Command, providercmds.Add.Handler(
			func(req *binding.Request[*providercmds.AddArguments], res *binding.Response[*providercmds.AddOK]) error {
				gotArgs = req.Task().Arguments()
				gotAud = req.Invocation().Audience()
				return res.SetSuccess(&providercmds.AddOK{ID: "sub-123"})
			}))

		// ProvisionSpace is self-issued and does not consult the proof store.
		c := newClient(t, service, srv, account, nil)
		id, err := c.ProvisionSpace(t.Context(), account, space)
		require.NoError(t, err)
		require.Equal(t, "sub-123", id)

		require.Equal(t, service.DID(), gotArgs.Provider)
		require.Equal(t, space, gotArgs.Consumer)
		require.Equal(t, service.DID(), gotAud)
	})

	t.Run("failure receipt", func(t *testing.T) {
		service := testutil.RandomIssuer(t)
		account := testutil.RandomIssuer(t)
		space := testutil.RandomDID(t)

		srv := server.NewHTTP(service)
		srv.Handle(providercmds.Add.Command, providercmds.Add.Handler(
			func(req *binding.Request[*providercmds.AddArguments], res *binding.Response[*providercmds.AddOK]) error {
				return res.SetFailure(errors.New("nope"))
			}))

		c := newClient(t, service, srv, account, nil)
		id, err := c.ProvisionSpace(t.Context(), account, space)
		require.Error(t, err)
		require.Empty(t, id)
	})
}

func TestSpaceEmpty(t *testing.T) {
	// listServer builds an in-process server whose /blob/list handler returns
	// the given results, capturing the invocation for assertions.
	newListServer := func(t *testing.T, service ucan.Issuer, results []blobcmds.ListBlobItem) (*server.HTTPServer, func() (*blobcmds.ListArguments, did.DID, did.DID)) {
		t.Helper()
		var gotArgs *blobcmds.ListArguments
		var gotSub, gotAud did.DID
		srv := server.NewHTTP(service)
		srv.Handle(blobcmds.List.Command, blobcmds.List.Handler(
			func(req *binding.Request[*blobcmds.ListArguments], res *binding.Response[*blobcmds.ListOK]) error {
				gotArgs = req.Task().Arguments()
				gotSub = req.Invocation().Subject()
				gotAud = req.Invocation().Audience()
				return res.SetSuccess(&blobcmds.ListOK{Results: results})
			}))
		return srv, func() (*blobcmds.ListArguments, did.DID, did.DID) { return gotArgs, gotSub, gotAud }
	}

	t.Run("empty", func(t *testing.T) {
		service := testutil.RandomIssuer(t)
		alice := testutil.RandomIssuer(t)
		space := testutil.RandomIssuer(t)

		// space delegates /blob/list to alice (root: subject == issuer == space).
		// The proof chain is looked up scoped to the space.
		dlg, err := blobcmds.List.Delegate(space, alice.DID(), space.DID())
		require.NoError(t, err)
		proofs := ucanlib.NewContainerProofStore(container.New(container.WithDelegations(dlg)))

		srv, captured := newListServer(t, service, nil)

		c := newClient(t, service, srv, alice, proofs)
		empty, err := c.SpaceEmpty(t.Context(), space.DID(), client.WithIssuer(alice), client.WithProofs(proofs))
		require.NoError(t, err)
		require.True(t, empty)

		gotArgs, gotSub, gotAud := captured()
		require.NotNil(t, gotArgs.Size)
		require.Equal(t, uint64(1), *gotArgs.Size)
		require.Equal(t, space.DID(), gotSub)
		require.Equal(t, service.DID(), gotAud)
	})

	t.Run("not empty", func(t *testing.T) {
		service := testutil.RandomIssuer(t)
		alice := testutil.RandomIssuer(t)
		space := testutil.RandomIssuer(t)

		dlg, err := blobcmds.List.Delegate(space, alice.DID(), space.DID())
		require.NoError(t, err)
		proofs := ucanlib.NewContainerProofStore(container.New(container.WithDelegations(dlg)))

		srv, _ := newListServer(t, service, []blobcmds.ListBlobItem{{}})

		c := newClient(t, service, srv, alice, nil)
		empty, err := c.SpaceEmpty(t.Context(), space.DID(), client.WithIssuer(alice), client.WithProofs(proofs))
		require.NoError(t, err)
		require.False(t, empty)
	})

	t.Run("proof chain error", func(t *testing.T) {
		service := testutil.RandomIssuer(t)
		alice := testutil.RandomIssuer(t)
		srv := server.NewHTTP(service)

		c := newClient(t, service, srv, alice, nil)
		_, err := c.SpaceEmpty(t.Context(), testutil.RandomDID(t), client.WithIssuer(alice), client.WithProofs(errProofStore{err: errors.New("boom")}))
		require.Error(t, err)
		require.Contains(t, err.Error(), "getting proof chain")
	})

	t.Run("execution error", func(t *testing.T) {
		service := testutil.RandomIssuer(t)
		alice := testutil.RandomIssuer(t)
		space := testutil.RandomIssuer(t)

		dlg, err := blobcmds.List.Delegate(space, alice.DID(), space.DID())
		require.NoError(t, err)
		proofs := ucanlib.NewContainerProofStore(container.New(container.WithDelegations(dlg)))

		u, err := url.Parse("http://upload.test")
		require.NoError(t, err)
		c, err := client.NewUploadClient(service.DID(), *u, alice, nil,
			client.WithHTTPClient(&http.Client{Transport: errRoundTripper{}}))
		require.NoError(t, err)

		_, err = c.SpaceEmpty(t.Context(), space.DID(), client.WithIssuer(alice), client.WithProofs(proofs))
		require.Error(t, err)
	})

	t.Run("failure receipt", func(t *testing.T) {
		service := testutil.RandomIssuer(t)
		alice := testutil.RandomIssuer(t)
		space := testutil.RandomIssuer(t)

		dlg, err := blobcmds.List.Delegate(space, alice.DID(), space.DID())
		require.NoError(t, err)
		proofs := ucanlib.NewContainerProofStore(container.New(container.WithDelegations(dlg)))

		srv := server.NewHTTP(service)
		srv.Handle(blobcmds.List.Command, blobcmds.List.Handler(
			func(req *binding.Request[*blobcmds.ListArguments], res *binding.Response[*blobcmds.ListOK]) error {
				return res.SetFailure(errors.New("nope"))
			}))

		c := newClient(t, service, srv, alice, nil)
		_, err = c.SpaceEmpty(t.Context(), space.DID(), client.WithIssuer(alice), client.WithProofs(proofs))
		require.Error(t, err)
	})
}
