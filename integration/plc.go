package integration

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"

	"github.com/fil-forge/ucantone/did"
	"github.com/fil-forge/ucantone/did/key"
	"github.com/fil-forge/ucantone/did/plc"
)

// mockPLC is a stand-in for the did:plc directory. When Hilt provisions a tenant it
// POSTs the signed genesis operation to POST /<did:plc>; the mock records the
// tenant's verification key (a did:key carried in the operation) and answers 200.
// GET /<did:plc> then serves the corresponding DID document, which is how the real
// Swarf (whose did:plc resolver is an HTTP client for this directory) verifies the
// revocations the tenant signs.
//
// It also acts as an in-process did.Resolver for those captured identities, which
// the mock Sprue needs to verify invocations the tenant issues (e.g. /provider/add
// during bucket provisioning). The real Hilt only ever validates did:key issuers, so
// it does not need either — only the services it calls do.
type mockPLC struct {
	server *httptest.Server

	mu   sync.Mutex
	keys map[string]did.DID // did:plc string -> verification did:key
}

// newMockPLC starts the mock PLC directory HTTP server.
func newMockPLC() *mockPLC {
	m := &mockPLC{keys: map[string]did.DID{}}
	m.server = httptest.NewServer(http.HandlerFunc(m.handle))
	return m
}

// URL is the directory endpoint to configure as Hilt's plc.directory.
func (m *mockPLC) URL() string { return m.server.URL }

// Close shuts the server down.
func (m *mockPLC) Close() { m.server.Close() }

func (m *mockPLC) handle(w http.ResponseWriter, r *http.Request) {
	// Path is "/<did:plc:...>".
	tenantDID := strings.TrimPrefix(r.URL.Path, "/")

	switch r.Method {
	case http.MethodPost:
		m.publish(w, r, tenantDID)
	case http.MethodGet:
		m.document(w, r, tenantDID)
	default:
		http.Error(w, "only GET and POST are supported", http.StatusMethodNotAllowed)
	}
}

// publish records the verification key from a genesis operation.
func (m *mockPLC) publish(w http.ResponseWriter, r *http.Request, tenantDID string) {
	var op plc.SignedOperation
	if err := op.UnmarshalDagJSON(r.Body); err != nil {
		http.Error(w, fmt.Sprintf("decoding genesis operation: %v", err), http.StatusBadRequest)
		return
	}
	// The tenant service publishes a single verification method keyed "hilt", whose
	// value is the tenant's signing key as a did:key.
	keyDID, ok := op.VerificationMethods["hilt"]
	if !ok {
		http.Error(w, "genesis operation has no \"hilt\" verification method", http.StatusBadRequest)
		return
	}

	m.mu.Lock()
	m.keys[tenantDID] = keyDID
	m.mu.Unlock()

	w.WriteHeader(http.StatusOK)
}

// document serves the DID document for a recorded did:plc, as the real directory's
// resolution endpoint does.
func (m *mockPLC) document(w http.ResponseWriter, r *http.Request, tenantDID string) {
	d, err := did.Parse(tenantDID)
	if err != nil {
		http.Error(w, fmt.Sprintf("parsing DID: %v", err), http.StatusBadRequest)
		return
	}
	doc, err := m.Resolve(r.Context(), d)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "application/did+json")
	if err := json.NewEncoder(w).Encode(doc); err != nil {
		http.Error(w, fmt.Sprintf("encoding DID document: %v", err), http.StatusInternalServerError)
	}
}

// Resolve resolves a captured did:plc to a DID document by delegating to the did:key
// resolver for the verification key recorded from its genesis operation. The
// document's verification methods carry the key material, which is all the UCAN
// validator needs to verify the tenant's signature.
func (m *mockPLC) Resolve(ctx context.Context, d did.DID) (did.Document, error) {
	m.mu.Lock()
	keyDID, ok := m.keys[d.String()]
	m.mu.Unlock()
	if !ok {
		return did.Document{}, fmt.Errorf("unknown did:plc %s", d)
	}
	return key.Resolver.Resolve(ctx, keyDID)
}

// resolver is a DID resolver covering did:key (directly) and the did:plc identities
// this mock has recorded.
func (m *mockPLC) resolver() did.Resolver {
	return did.ResolverMap{
		key.Method: key.Resolver,
		"plc":      did.ResolverFunc(m.Resolve),
	}
}
