package integration

import (
	"net/http/httptest"
	"sync"

	blobcmds "github.com/fil-forge/libforge/commands/blob"
	customercmds "github.com/fil-forge/libforge/commands/customer"
	providercmds "github.com/fil-forge/libforge/commands/provider"
	"github.com/fil-forge/ucantone/binding"
	"github.com/fil-forge/ucantone/did"
	"github.com/fil-forge/ucantone/server"
	"github.com/fil-forge/ucantone/ucan"
	"github.com/fil-forge/ucantone/ucan/promise"
	"github.com/fil-forge/ucantone/validator"
	"github.com/ipfs/go-cid"
)

// mockSprue is a stand-in for the Sprue upload service. It is a real ucantone UCAN
// server (so it returns properly signed receipts) handling the commands Hilt and the
// gateway invoke on the happy path: /customer/add (tenant provisioning),
// /provider/add (bucket space provisioning), and /blob/add (object upload, from the
// mock Ingot). It is configured with a DID resolver that can resolve the tenant's
// did:plc (via the mock PLC directory), needed to verify the /provider/add
// invocation (issued by the tenant) and the /blob/add proof chain (rooted at the
// bucket, through the tenant).
type mockSprue struct {
	server *httptest.Server

	mu           sync.Mutex
	customerAdds int
	providerAdds int
	blobAdds     int
}

// newMockSprue starts the mock Sprue UCAN server. issuer is Sprue's identity (it
// signs receipts as this DID, which must match Hilt's upload.service_id); resolver
// resolves invocation issuers (did:key and the tenant's did:plc).
func newMockSprue(issuer ucan.Issuer, resolver did.Resolver) *mockSprue {
	m := &mockSprue{}
	srv := server.NewHTTP(issuer, server.WithValidationOptions(validator.WithDIDResolver(resolver)))

	srv.Handle(customercmds.Add.Command, customercmds.Add.Handler(
		func(req *binding.Request[*customercmds.AddArguments], res *binding.Response[*customercmds.AddOK]) error {
			m.mu.Lock()
			m.customerAdds++
			m.mu.Unlock()
			return res.SetSuccess(&customercmds.AddOK{})
		}))

	srv.Handle(providercmds.Add.Command, providercmds.Add.Handler(
		func(req *binding.Request[*providercmds.AddArguments], res *binding.Response[*providercmds.AddOK]) error {
			m.mu.Lock()
			m.providerAdds++
			m.mu.Unlock()
			return res.SetSuccess(&providercmds.AddOK{ID: "sub-1"})
		}))

	srv.Handle(blobcmds.Add.Command, blobcmds.Add.Handler(
		func(req *binding.Request[*blobcmds.AddArguments], res *binding.Response[*blobcmds.AddOK]) error {
			m.mu.Lock()
			m.blobAdds++
			m.mu.Unlock()
			// Return a success result. The Site promise references a /blob/accept
			// task; a CID derived from the blob digest is a valid placeholder for
			// this happy-path test (the full accept/put protocol is out of scope).
			task := cid.NewCidV1(cid.Raw, req.Task().Arguments().Blob.Digest)
			return res.SetSuccess(&blobcmds.AddOK{Site: promise.AwaitOK{Task: task}})
		}))

	m.server = httptest.NewServer(srv)
	return m
}

// URL is the endpoint to configure as Hilt's upload.service_url.
func (m *mockSprue) URL() string { return m.server.URL }

// Close shuts the server down.
func (m *mockSprue) Close() { m.server.Close() }

// counts returns how many times each command was handled.
func (m *mockSprue) counts() (customerAdds, providerAdds, blobAdds int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.customerAdds, m.providerAdds, m.blobAdds
}
