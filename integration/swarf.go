package integration

import (
	"errors"
	"fmt"
	"net/http/httptest"
	"sync"

	ucancmds "github.com/fil-forge/libforge/commands/ucan"
	"github.com/fil-forge/ucantone/binding"
	"github.com/fil-forge/ucantone/did"
	"github.com/fil-forge/ucantone/server"
	"github.com/fil-forge/ucantone/ucan"
	"github.com/fil-forge/ucantone/validator"
	"github.com/ipfs/go-cid"
)

// mockSwarf is a stand-in for the Swarf revocation service. It is a real ucantone
// UCAN server handling /ucan/revoke, and it applies the same path-witness checks
// the real service does (see the revocation spec) so a malformed witness fails the
// test rather than being silently accepted. Like the mock Sprue it needs a DID
// resolver that can resolve the tenant's did:plc, since the tenant issues both the
// revocation invocation and the delegation being revoked.
type mockSwarf struct {
	server *httptest.Server

	mu      sync.Mutex
	revoked []cid.Cid
}

// newMockSwarf starts the mock Swarf UCAN server. issuer is Swarf's identity (it
// signs receipts as this DID, which must match Hilt's revocation.service_id);
// resolver resolves the revocation issuer and the witness delegation issuers.
func newMockSwarf(issuer ucan.Issuer, resolver did.Resolver) *mockSwarf {
	m := &mockSwarf{}
	srv := server.NewHTTP(issuer, server.WithValidationOptions(validator.WithDIDResolver(resolver)))

	srv.Handle(ucancmds.Revoke.Command, ucancmds.Revoke.Handler(
		func(req *binding.Request[*ucancmds.RevokeArguments], res *binding.Response[*ucancmds.RevokeOK]) error {
			args := req.Task().Arguments()
			witnesses := map[cid.Cid]ucan.Delegation{}
			for _, dlg := range req.Metadata().Delegations() {
				witnesses[dlg.Link()] = dlg
			}
			path := make([]ucan.Delegation, len(args.Path))
			for i, link := range args.Path {
				dlg, ok := witnesses[link]
				if !ok {
					return fmt.Errorf("delegation %s at path index %d is not in the request container", link, i)
				}
				path[i] = dlg
			}
			if len(path) == 0 || path[len(path)-1].Link() != args.Revoke {
				return errors.New("revocation path must end with the revoked delegation")
			}
			if err := validateWitnessPath(req, path, resolver); err != nil {
				return err
			}
			var isIssuer bool
			for _, dlg := range path {
				if dlg.Issuer() == req.Invocation().Issuer() {
					isIssuer = true
					break
				}
			}
			if !isIssuer {
				return errors.New("revocation issuer is not an issuer in the delegation path")
			}

			m.mu.Lock()
			m.revoked = append(m.revoked, args.Revoke)
			m.mu.Unlock()
			return res.SetSuccess(&ucancmds.RevokeOK{})
		}))

	m.server = httptest.NewServer(srv)
	return m
}

// validateWitnessPath checks the path is a valid delegation chain: rooted in a
// self-issued delegation, each delegation issued to the previous audience, every
// delegation sharing the root's subject (or subject-less), and each one valid.
func validateWitnessPath(req *binding.Request[*ucancmds.RevokeArguments], path []ucan.Delegation, resolver did.Resolver) error {
	rootSubject := path[0].Subject()
	if rootSubject != path[0].Issuer() {
		return errors.New("root delegation subject must equal its issuer")
	}
	for i, dlg := range path {
		if err := validator.ValidateToken(req.Context(), dlg, validator.WithDIDResolver(resolver)); err != nil {
			return fmt.Errorf("validating delegation at path index %d: %w", i, err)
		}
		if i == 0 {
			continue
		}
		if dlg.Subject() != rootSubject && dlg.Subject() != did.Undef {
			return fmt.Errorf("delegation at path index %d has a different subject", i)
		}
		if dlg.Issuer() != path[i-1].Audience() {
			return fmt.Errorf("delegation at path index %d issuer does not match the previous audience", i)
		}
	}
	return nil
}

// URL is the endpoint to configure as Hilt's revocation.service_url.
func (m *mockSwarf) URL() string { return m.server.URL }

// Close shuts the server down.
func (m *mockSwarf) Close() { m.server.Close() }

// revocations returns the delegations revoked so far.
func (m *mockSwarf) revocations() []cid.Cid {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]cid.Cid(nil), m.revoked...)
}
