package integration

import (
	"context"
	"crypto/md5"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"

	"github.com/fil-forge/hilt/pkg/client"
	"github.com/fil-forge/hilt/pkg/sigv4"
	blobcmds "github.com/fil-forge/libforge/commands/blob"
	s3 "github.com/fil-forge/libforge/commands/s3"
	s3req "github.com/fil-forge/libforge/commands/s3/request"
	ucanlib "github.com/fil-forge/libforge/ucan"
	"github.com/fil-forge/ucantone/did"
	"github.com/fil-forge/ucantone/execution"
	"github.com/fil-forge/ucantone/ucan"
	"github.com/fil-forge/ucantone/ucan/container"
	"github.com/fil-forge/ucantone/ucan/invocation"
	"github.com/multiformats/go-multihash"
)

// mockIngot is a stand-in for the Ingot S3 gateway. It exposes an S3 HTTP endpoint
// (which the real AWS SDK targets) and, for each request, calls Hilt's UCAN RPC:
//   - CreateBucket (PUT /<bucket>)      -> Hilt /s3/bucket/create
//   - PutObject    (PUT /<bucket>/<key>) -> Hilt /s3/request/authorize (verify the
//     signature) + /s3/bucket/info (fetch proofs), then it stores the object by
//     invoking /blob/add on Sprue with a bucket-rooted proof chain.
//
// It signs its Hilt invocations as the provider identity registered with Hilt (that
// identity + its Hilt->Ingot proofs live in hilt); it signs its Sprue /blob/add
// invocation as the same provider identity (ingotIssuer), with the bucket as subject.
type mockIngot struct {
	hilt        *client.Client
	ingotIssuer ucan.Issuer
	sprueID     did.DID
	sprueExec   execution.Executor
	server      *httptest.Server

	mu      sync.Mutex
	objects map[string][]byte // "<bucket>/<key>" -> bytes
}

// newMockIngot starts the mock Ingot S3 endpoint. hilt calls Hilt (issuer = the
// provider identity); ingotIssuer/sprueID/sprueExec are used to invoke /blob/add on
// Sprue.
func newMockIngot(hilt *client.Client, ingotIssuer ucan.Issuer, sprueID did.DID, sprueExec execution.Executor) *mockIngot {
	m := &mockIngot{
		hilt:        hilt,
		ingotIssuer: ingotIssuer,
		sprueID:     sprueID,
		sprueExec:   sprueExec,
		objects:     map[string][]byte{},
	}
	m.server = httptest.NewServer(http.HandlerFunc(m.handle))
	return m
}

// URL is the S3 endpoint to point the AWS SDK at.
func (m *mockIngot) URL() string { return m.server.URL }

// Close shuts the server down.
func (m *mockIngot) Close() { m.server.Close() }

// object returns a stored object's bytes.
func (m *mockIngot) object(bucket, key string) ([]byte, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	b, ok := m.objects[bucket+"/"+key]
	return b, ok
}

func (m *mockIngot) handle(w http.ResponseWriter, r *http.Request) {
	bucket, objectKey := parsePathStyle(r.URL.Path)
	switch {
	case r.Method == http.MethodPut && bucket != "" && objectKey == "":
		m.createBucket(w, r)
	case r.Method == http.MethodPut && bucket != "" && objectKey != "":
		m.putObject(w, r, bucket, objectKey)
	default:
		http.Error(w, "unsupported S3 operation", http.StatusNotImplemented)
	}
}

// createBucket forwards a CreateBucket to Hilt's /s3/bucket/create.
func (m *mockIngot) createBucket(w http.ResponseWriter, r *http.Request) {
	if _, _, err := m.hilt.CreateBucket(r.Context(), s3RequestFrom(r)); err != nil {
		http.Error(w, fmt.Sprintf("create bucket rejected: %v", err), http.StatusForbidden)
		return
	}
	w.WriteHeader(http.StatusOK)
}

// putObject authorizes the request with Hilt, verifies the caller's SigV4 signature
// against the key Hilt returns, hands the object to Sprue via /blob/add, then stores
// it.
func (m *mockIngot) putObject(w http.ResponseWriter, r *http.Request, bucket, objectKey string) {
	req := s3RequestFrom(r)
	ok, authCtr, err := m.hilt.AuthorizeRequest(r.Context(), req)
	if err != nil {
		http.Error(w, fmt.Sprintf("authorize rejected: %v", err), http.StatusForbidden)
		return
	}
	if err := verifySignature(req, ok); err != nil {
		http.Error(w, fmt.Sprintf("signature verification failed: %v", err), http.StatusForbidden)
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "reading body", http.StatusBadRequest)
		return
	}
	if err := m.storeBlob(r.Context(), bucket, ok, authCtr, body); err != nil {
		http.Error(w, fmt.Sprintf("storing object: %v", err), http.StatusBadGateway)
		return
	}

	m.mu.Lock()
	m.objects[bucket+"/"+objectKey] = body
	m.mu.Unlock()

	w.Header().Set("ETag", fmt.Sprintf("%q", fmt.Sprintf("%x", md5.Sum(body))))
	w.WriteHeader(http.StatusOK)
}

// storeBlob invokes /blob/add on Sprue for the object. It assembles the proof chain
// the invocation needs from two Hilt responses: the accessKey->Ingot re-delegation
// (subject = bucket) that /s3/request/authorize already returned, plus the
// bucket->tenant->accessKey chain fetched from /s3/bucket/info. The invocation is
// issued by Ingot with the bucket as subject.
func (m *mockIngot) storeBlob(ctx context.Context, bucket string, auth *s3req.AuthorizeOK, authCtr ucan.Container, body []byte) error {
	bucketDID := auth.Bucket
	accessKeyDID, err := singleAccessKey(auth)
	if err != nil {
		return err
	}

	_, infoCtr, err := m.hilt.BucketInfo(ctx, bucket, accessKeyDID)
	if err != nil {
		return fmt.Errorf("fetching bucket info: %w", err)
	}

	// Merge the delegation blocks from both responses into one proof store; its
	// ProofChain assembles the ordered bucket->...->Ingot chain for /blob/add.
	merged := container.New(container.WithDelegations(
		append(authCtr.Delegations(), infoCtr.Delegations()...)...))
	proofs, links, err := ucanlib.NewContainerProofStore(merged).
		ProofChain(ctx, m.ingotIssuer.DID(), blobcmds.Add.Command, bucketDID)
	if err != nil {
		return fmt.Errorf("building /blob/add proof chain: %w", err)
	}
	if len(proofs) == 0 {
		return fmt.Errorf("no proof chain to invoke /blob/add on %s", bucketDID)
	}

	digest, err := multihash.Sum(body, multihash.SHA2_256, -1)
	if err != nil {
		return fmt.Errorf("hashing body: %w", err)
	}
	inv, err := blobcmds.Add.Invoke(m.ingotIssuer, bucketDID,
		&blobcmds.AddArguments{Blob: blobcmds.Blob{Digest: digest, Size: uint64(len(body))}},
		invocation.WithAudience(m.sprueID),
		invocation.WithProofs(links...),
	)
	if err != nil {
		return fmt.Errorf("building /blob/add invocation: %w", err)
	}
	res, err := m.sprueExec.Execute(execution.NewRequest(ctx, inv, execution.WithDelegations(proofs...)))
	if err != nil {
		return fmt.Errorf("executing /blob/add: %w", err)
	}
	if _, err := blobcmds.Add.Unpack(res.Receipt()); err != nil {
		return fmt.Errorf("/blob/add rejected: %w", err)
	}
	return nil
}

// verifySignature re-parses the request and verifies its SigV4 signature using the
// verification key Hilt derived for the access key (exactly what the gateway does).
func verifySignature(req s3.Request, ok *s3req.AuthorizeOK) error {
	sr, err := sigv4.Parse(sigv4.Request{Method: req.Method, Headers: req.Headers, URL: req.URL})
	if err != nil {
		return fmt.Errorf("parsing signature: %w", err)
	}
	for _, keys := range ok.Keys.Entries {
		if len(keys) == 0 {
			continue
		}
		if err := sigv4.VerifyWithKey(sr, keys[0].Data); err == nil {
			return nil
		}
	}
	return fmt.Errorf("no verification key matched the request signature")
}

// singleAccessKey returns the sole access-key DID from an authorize result.
func singleAccessKey(ok *s3req.AuthorizeOK) (did.DID, error) {
	for akDID := range ok.Keys.Entries {
		return akDID, nil
	}
	return did.DID{}, fmt.Errorf("authorize result carried no access key")
}

// s3RequestFrom rebuilds the signed S3 request from the incoming HTTP request: the
// method, every header (including Host, which SigV4 signs but Go keeps off
// r.Header), and the full URL the client signed against the Ingot endpoint.
func s3RequestFrom(r *http.Request) s3.Request {
	headers := map[string]string{"Host": r.Host}
	for name, values := range r.Header {
		if len(values) > 0 {
			headers[name] = values[0]
		}
	}
	return s3.Request{
		Method:  r.Method,
		Headers: headers,
		URL:     "http://" + r.Host + r.URL.RequestURI(),
	}
}

// parsePathStyle splits a path-style S3 URL path ("/<bucket>/<key...>") into its
// bucket and (possibly empty) object key.
func parsePathStyle(path string) (bucket, key string) {
	trimmed := strings.TrimPrefix(path, "/")
	bucket, key, _ = strings.Cut(trimmed, "/")
	return bucket, key
}
