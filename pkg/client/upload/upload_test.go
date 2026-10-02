package upload_test

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"testing"
	"time"

	upload "github.com/fil-forge/hilt/pkg/client/upload"
	blobcmds "github.com/fil-forge/libforge/commands/blob"
	customercmds "github.com/fil-forge/libforge/commands/customer"
	metricscmds "github.com/fil-forge/libforge/commands/metrics"
	providercmds "github.com/fil-forge/libforge/commands/provider"
	routingcmds "github.com/fil-forge/libforge/commands/routing"
	"github.com/fil-forge/libforge/testutil"
	ucanlib "github.com/fil-forge/libforge/ucan"
	"github.com/fil-forge/ucantone/binding"
	"github.com/fil-forge/ucantone/did"
	ucanerrors "github.com/fil-forge/ucantone/errors"
	"github.com/fil-forge/ucantone/server"
	"github.com/fil-forge/ucantone/ucan"
	"github.com/fil-forge/ucantone/ucan/command"
	"github.com/fil-forge/ucantone/ucan/container"
	"github.com/fil-forge/ucantone/ucan/delegation"
	"github.com/ipfs/go-cid"
	"github.com/stretchr/testify/require"
)

// newClient builds an UploadClient whose transport is the given in-process
// server, exercising NewUploadClient itself.
func newClient(t *testing.T, service ucan.Issuer, srv *server.HTTPServer, issuer ucan.Issuer, proofs ucanlib.ProofStore) *upload.Client {
	t.Helper()
	u, err := url.Parse("http://upload.test")
	require.NoError(t, err)
	c, err := upload.NewClient(service.DID(), *u, issuer,
		upload.WithBaseProofs(proofs),
		upload.WithHTTPClient(&http.Client{Transport: srv}))
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
		customerID := testutil.RandomDID(t)
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
		err = c.RegisterCustomer(t.Context(), customerID, product, details)
		require.NoError(t, err)

		require.Equal(t, customerID, gotArgs.Customer)
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
		c, err := upload.NewClient(service.DID(), *u, alice,
			upload.WithBaseProofs(proofs),
			upload.WithHTTPClient(&http.Client{Transport: errRoundTripper{}}))
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
		empty, err := c.SpaceEmpty(t.Context(), space.DID(), upload.WithIssuer(alice), upload.WithProofs(proofs))
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
		empty, err := c.SpaceEmpty(t.Context(), space.DID(), upload.WithIssuer(alice), upload.WithProofs(proofs))
		require.NoError(t, err)
		require.False(t, empty)
	})

	t.Run("proof chain error", func(t *testing.T) {
		service := testutil.RandomIssuer(t)
		alice := testutil.RandomIssuer(t)
		srv := server.NewHTTP(service)

		c := newClient(t, service, srv, alice, nil)
		_, err := c.SpaceEmpty(t.Context(), testutil.RandomDID(t), upload.WithIssuer(alice), upload.WithProofs(errProofStore{err: errors.New("boom")}))
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
		c, err := upload.NewClient(service.DID(), *u, alice,
			upload.WithHTTPClient(&http.Client{Transport: errRoundTripper{}}))
		require.NoError(t, err)

		_, err = c.SpaceEmpty(t.Context(), space.DID(), upload.WithIssuer(alice), upload.WithProofs(proofs))
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
		_, err = c.SpaceEmpty(t.Context(), space.DID(), upload.WithIssuer(alice), upload.WithProofs(proofs))
		require.Error(t, err)
	})
}

func TestPutRoutingPolicy(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		service := testutil.RandomIssuer(t)
		hilt := testutil.RandomIssuer(t)
		policy := testutil.RandomIssuer(t)
		nodes := []did.DID{testutil.RandomDID(t), testutil.RandomDID(t)}

		// policy delegates / to hilt (root: subject == issuer == policy).
		root, err := delegation.Delegate(policy, hilt.DID(), policy.DID(), command.Top(), delegation.WithNoExpiration())
		require.NoError(t, err)
		proofs := ucanlib.NewContainerProofStore(container.New(container.WithDelegations(root)))

		var gotArgs *routingcmds.PutArguments
		var gotSub, gotAud, gotIss did.DID
		srv := server.NewHTTP(service)
		srv.Handle(routingcmds.Put.Command, routingcmds.Put.Handler(
			func(req *binding.Request[*routingcmds.PutArguments], res *binding.Response[*routingcmds.PutOK]) error {
				gotArgs = req.Task().Arguments()
				gotSub = req.Invocation().Subject()
				gotAud = req.Invocation().Audience()
				gotIss = req.Invocation().Issuer()
				return res.SetSuccess(&routingcmds.PutOK{})
			}))

		c := newClient(t, service, srv, hilt, nil)
		require.NoError(t, c.PutRoutingPolicy(t.Context(), policy.DID(), nodes, upload.WithProofs(proofs)))

		require.Equal(t, policy.DID(), gotSub)
		require.Equal(t, service.DID(), gotAud)
		require.Equal(t, hilt.DID(), gotIss)
		require.Len(t, gotArgs.Candidates.Entries, len(nodes))
		for _, n := range nodes {
			require.Contains(t, gotArgs.Candidates.Entries, n)
		}
	})

	t.Run("proof chain error", func(t *testing.T) {
		service := testutil.RandomIssuer(t)
		hilt := testutil.RandomIssuer(t)
		srv := server.NewHTTP(service)

		c := newClient(t, service, srv, hilt, nil)
		err := c.PutRoutingPolicy(t.Context(), testutil.RandomDID(t), []did.DID{testutil.RandomDID(t)}, upload.WithProofs(errProofStore{err: errors.New("boom")}))
		require.Error(t, err)
		require.Contains(t, err.Error(), "getting proof chain")
	})

	t.Run("failure receipt", func(t *testing.T) {
		service := testutil.RandomIssuer(t)
		hilt := testutil.RandomIssuer(t)
		policy := testutil.RandomIssuer(t)

		root, err := delegation.Delegate(policy, hilt.DID(), policy.DID(), command.Top(), delegation.WithNoExpiration())
		require.NoError(t, err)
		proofs := ucanlib.NewContainerProofStore(container.New(container.WithDelegations(root)))

		srv := server.NewHTTP(service)
		srv.Handle(routingcmds.Put.Command, routingcmds.Put.Handler(
			func(req *binding.Request[*routingcmds.PutArguments], res *binding.Response[*routingcmds.PutOK]) error {
				return res.SetFailure(ucanerrors.New(routingcmds.InvalidCandidatesErrorName, "unregistered node"))
			}))

		c := newClient(t, service, srv, hilt, nil)
		err = c.PutRoutingPolicy(t.Context(), policy.DID(), []did.DID{testutil.RandomDID(t)}, upload.WithProofs(proofs))
		require.Error(t, err)
		var named ucanerrors.Named
		require.ErrorAs(t, err, &named)
		require.Equal(t, routingcmds.InvalidCandidatesErrorName, named.Name())
	})
}

func TestUseRoutingPolicy(t *testing.T) {
	newUseServer := func(t *testing.T, service ucan.Issuer) (*server.HTTPServer, func() (*routingcmds.UseArguments, did.DID, did.DID)) {
		t.Helper()
		var gotArgs *routingcmds.UseArguments
		var gotSub, gotIss did.DID
		srv := server.NewHTTP(service)
		srv.Handle(routingcmds.Use.Command, routingcmds.Use.Handler(
			func(req *binding.Request[*routingcmds.UseArguments], res *binding.Response[*routingcmds.UseOK]) error {
				gotArgs = req.Task().Arguments()
				gotSub = req.Invocation().Subject()
				gotIss = req.Invocation().Issuer()
				return res.SetSuccess(&routingcmds.UseOK{})
			}))
		return srv, func() (*routingcmds.UseArguments, did.DID, did.DID) { return gotArgs, gotSub, gotIss }
	}

	t.Run("sets the policy as the tenant", func(t *testing.T) {
		service := testutil.RandomIssuer(t)
		hilt := testutil.RandomIssuer(t)
		tenant := testutil.RandomIssuer(t)
		space := testutil.RandomIssuer(t)
		policy := testutil.RandomDID(t)

		// space delegates / to the tenant (root: subject == issuer == space).
		root, err := delegation.Delegate(space, tenant.DID(), space.DID(), command.Top(), delegation.WithNoExpiration())
		require.NoError(t, err)
		proofs := ucanlib.NewContainerProofStore(container.New(container.WithDelegations(root)))

		srv, captured := newUseServer(t, service)
		c := newClient(t, service, srv, hilt, nil)
		require.NoError(t, c.UseRoutingPolicy(t.Context(), space.DID(), &policy, upload.WithIssuer(tenant), upload.WithProofs(proofs)))

		gotArgs, gotSub, gotIss := captured()
		require.NotNil(t, gotArgs.Policy)
		require.Equal(t, policy, *gotArgs.Policy)
		require.Equal(t, space.DID(), gotSub)
		require.Equal(t, tenant.DID(), gotIss)
	})

	t.Run("clears the policy", func(t *testing.T) {
		service := testutil.RandomIssuer(t)
		space := testutil.RandomIssuer(t)

		srv, captured := newUseServer(t, service)
		// The space itself issues the invocation: no proofs needed.
		c := newClient(t, service, srv, space, nil)
		require.NoError(t, c.UseRoutingPolicy(t.Context(), space.DID(), nil))

		gotArgs, _, _ := captured()
		require.Nil(t, gotArgs.Policy)
	})

	t.Run("proof chain error", func(t *testing.T) {
		service := testutil.RandomIssuer(t)
		hilt := testutil.RandomIssuer(t)
		srv := server.NewHTTP(service)

		c := newClient(t, service, srv, hilt, nil)
		err := c.UseRoutingPolicy(t.Context(), testutil.RandomDID(t), nil, upload.WithProofs(errProofStore{err: errors.New("boom")}))
		require.Error(t, err)
		require.Contains(t, err.Error(), "getting proof chain")
	})
}

func TestSampleUsage(t *testing.T) {
	// newSampleServer builds an in-process server whose /metrics/sample handler
	// returns the given series, capturing the invocation for assertions.
	newSampleServer := func(t *testing.T, service ucan.Issuer, items []metricscmds.SampleItem) (*server.HTTPServer, func() (*metricscmds.SampleArguments, did.DID, did.DID)) {
		t.Helper()
		var gotArgs *metricscmds.SampleArguments
		var gotSub, gotAud did.DID
		srv := server.NewHTTP(service)
		srv.Handle(metricscmds.Sample.Command, metricscmds.Sample.Handler(
			func(req *binding.Request[*metricscmds.SampleArguments], res *binding.Response[*metricscmds.SampleOK]) error {
				gotArgs = req.Task().Arguments()
				gotSub = req.Invocation().Subject()
				gotAud = req.Invocation().Audience()
				return res.SetSuccess(&metricscmds.SampleOK{
					From: gotArgs.From, To: gotArgs.To, Window: gotArgs.Window, Samples: items,
				})
			}))
		return srv, func() (*metricscmds.SampleArguments, did.DID, did.DID) { return gotArgs, gotSub, gotAud }
	}

	// sampleProofs delegates /metrics/sample over the space to alice, the root
	// the client's proof chain is looked up against.
	sampleProofs := func(t *testing.T, space, alice ucan.Issuer) ucanlib.ProofStore {
		t.Helper()
		dlg, err := metricscmds.Sample.Delegate(space, alice.DID(), space.DID())
		require.NoError(t, err)
		return ucanlib.NewContainerProofStore(container.New(container.WithDelegations(dlg)))
	}

	t.Run("sends the range as whole seconds and returns the series", func(t *testing.T) {
		service := testutil.RandomIssuer(t)
		alice := testutil.RandomIssuer(t)
		space := testutil.RandomIssuer(t)
		proofs := sampleProofs(t, space, alice)

		srv, captured := newSampleServer(t, service, []metricscmds.SampleItem{
			{Timestamp: 1767225600, BytesStored: 1024, BytesIngested: 512, UploadCount: 3},
			{Timestamp: 1767229200, BytesStored: 2048, BytesIngested: 1024, UploadCount: 5},
		})

		from := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
		to := from.Add(2 * time.Hour)

		c := newClient(t, service, srv, alice, nil)
		ok, err := c.SampleUsage(t.Context(), space.DID(), from, to, time.Hour,
			upload.WithIssuer(alice), upload.WithProofs(proofs))
		require.NoError(t, err)

		gotArgs, gotSub, gotAud := captured()
		require.Equal(t, from.Unix(), gotArgs.From)
		require.Equal(t, to.Unix(), gotArgs.To)
		require.Equal(t, int64(3600), gotArgs.Window, "the window travels as seconds")
		require.Equal(t, space.DID(), gotSub, "the space is the subject, not an argument")
		require.Equal(t, service.DID(), gotAud)

		require.Len(t, ok.Samples, 2)
		require.Equal(t, int64(1767225600), ok.Samples[0].Timestamp)
		require.Equal(t, uint64(1024), ok.Samples[0].BytesStored)
		require.Equal(t, uint64(512), ok.Samples[0].BytesIngested)
		require.Equal(t, uint64(3), ok.Samples[0].UploadCount)
		require.Equal(t, uint64(5), ok.Samples[1].UploadCount)
	})

	t.Run("rounds a sub-second window down to whole seconds", func(t *testing.T) {
		service := testutil.RandomIssuer(t)
		alice := testutil.RandomIssuer(t)
		space := testutil.RandomIssuer(t)
		proofs := sampleProofs(t, space, alice)

		srv, captured := newSampleServer(t, service, nil)
		from := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

		c := newClient(t, service, srv, alice, nil)
		_, err := c.SampleUsage(t.Context(), space.DID(), from, from.Add(time.Hour), 1500*time.Millisecond,
			upload.WithIssuer(alice), upload.WithProofs(proofs))
		require.NoError(t, err)

		gotArgs, _, _ := captured()
		require.Equal(t, int64(1), gotArgs.Window)
	})

	t.Run("proof chain error", func(t *testing.T) {
		service := testutil.RandomIssuer(t)
		alice := testutil.RandomIssuer(t)
		srv := server.NewHTTP(service)

		c := newClient(t, service, srv, alice, nil)
		_, err := c.SampleUsage(t.Context(), testutil.RandomDID(t), time.Now(), time.Now().Add(time.Hour), time.Hour,
			upload.WithIssuer(alice), upload.WithProofs(errProofStore{err: errors.New("boom")}))
		require.Error(t, err)
		require.Contains(t, err.Error(), "getting proof chain")
	})

	t.Run("execution error", func(t *testing.T) {
		service := testutil.RandomIssuer(t)
		alice := testutil.RandomIssuer(t)
		space := testutil.RandomIssuer(t)
		proofs := sampleProofs(t, space, alice)

		u, err := url.Parse("http://upload.test")
		require.NoError(t, err)
		c, err := upload.NewClient(service.DID(), *u, alice,
			upload.WithHTTPClient(&http.Client{Transport: errRoundTripper{}}))
		require.NoError(t, err)

		_, err = c.SampleUsage(t.Context(), space.DID(), time.Now(), time.Now().Add(time.Hour), time.Hour,
			upload.WithIssuer(alice), upload.WithProofs(proofs))
		require.Error(t, err)
	})

	// A named failure is how the upload service says the request itself is
	// unusable. The name has to survive the round trip, because the REST handler
	// chooses a status from it rather than from the message.
	t.Run("failure receipt keeps its name", func(t *testing.T) {
		service := testutil.RandomIssuer(t)
		alice := testutil.RandomIssuer(t)
		space := testutil.RandomIssuer(t)
		proofs := sampleProofs(t, space, alice)

		srv := server.NewHTTP(service)
		srv.Handle(metricscmds.Sample.Command, metricscmds.Sample.Handler(
			func(req *binding.Request[*metricscmds.SampleArguments], res *binding.Response[*metricscmds.SampleOK]) error {
				return res.SetFailure(ucanerrors.New(metricscmds.UsageUnstableErrorName, "try again"))
			}))

		c := newClient(t, service, srv, alice, nil)
		_, err := c.SampleUsage(t.Context(), space.DID(), time.Now(), time.Now().Add(time.Hour), time.Hour,
			upload.WithIssuer(alice), upload.WithProofs(proofs))
		require.Error(t, err)

		var named ucanerrors.Named
		require.ErrorAs(t, err, &named)
		require.Equal(t, metricscmds.UsageUnstableErrorName, named.Name())
	})
}
