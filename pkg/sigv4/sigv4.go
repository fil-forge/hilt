// Package sigv4 verifies AWS S3 request signatures for the two schemes the
// Forge S3 gateway uses: AWS4-HMAC-SHA256 (SigV4) and AWS4-ECDSA-P256-SHA256
// (SigV4a). It is built on the Go standard library only.
//
// Access keys are ed25519 keys; the client's secretAccessKey is the multibase
// base64url encoding of the multiformat-tagged private key. SigV4 feeds that
// string into the standard HMAC signing-key chain; SigV4a derives an ECDSA
// P-256 key from the access key id + secret using AWS's deterministic KDF.
package sigv4

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"
)

// Scheme identifies an AWS signature algorithm.
type Scheme string

const (
	SchemeV4  Scheme = "AWS4-HMAC-SHA256"
	SchemeV4a Scheme = "AWS4-ECDSA-P256-SHA256"
)

const (
	amzAlgorithm    = "X-Amz-Algorithm"
	amzCredential   = "X-Amz-Credential"
	amzSignedHdrs   = "X-Amz-SignedHeaders"
	amzSignature    = "X-Amz-Signature"
	amzDate         = "X-Amz-Date"
	amzContentSHA   = "X-Amz-Content-Sha256"
	amzRegionSet    = "X-Amz-Region-Set"
	terminator      = "aws4_request"
	unsignedPayload = "UNSIGNED-PAYLOAD"
)

// Request is the subset of an HTTP request that sigv4 needs to verify (or
// produce) a signature. Callers adapt their own request representation to it.
type Request struct {
	Method  string
	Headers map[string]string
	URL     string
}

// toHeader builds a canonicalized http.Header from a plain header map, so
// internal lookups get case-insensitive .Get semantics.
func toHeader(m map[string]string) http.Header {
	h := make(http.Header, len(m))
	for k, v := range m {
		h.Set(k, v)
	}
	return h
}

// SignedRequest is the parsed authentication state of an S3 request: the public
// identity fields plus the components needed to recompute the signature.
type SignedRequest struct {
	Scheme      Scheme
	AccessKeyID string // bare did:key identifier
	Region      string // credential-scope region (V4) or X-Amz-Region-Set (V4a)

	method        string
	canonicalURI  string
	query         url.Values // signed query params (X-Amz-Signature removed)
	headers       http.Header
	host          string
	signedHeaders []string // lowercased, sorted
	payloadHash   string
	amzDate       string
	scope         string // "<date>/[<region>/]<service>/aws4_request"
	signature     string // the signature carried on the request
}

// Parse extracts the signature fields from an S3 request — from the
// Authorization header or, for presigned URLs, the X-Amz-* query parameters. It
// does not verify the signature; call [SignedRequest.Verify] for that.
func Parse(req Request) (*SignedRequest, error) {
	u, err := url.Parse(req.URL)
	if err != nil {
		return nil, fmt.Errorf("parsing request URL: %w", err)
	}
	query := u.Query()
	headers := toHeader(req.Headers)

	var (
		algorithm     string
		credential    string
		signedHeaders string
		signature     string
		date          string
		regionSet     string
		payloadHash   string
	)

	if query.Get(amzAlgorithm) != "" {
		// Presigned URL: auth fields live in the query string.
		algorithm = query.Get(amzAlgorithm)
		credential = query.Get(amzCredential)
		signedHeaders = query.Get(amzSignedHdrs)
		signature = query.Get(amzSignature)
		date = query.Get(amzDate)
		regionSet = query.Get(amzRegionSet)
		payloadHash = query.Get(amzContentSHA)
		if payloadHash == "" {
			payloadHash = unsignedPayload
		}
	} else if auth := headers.Get("Authorization"); strings.HasPrefix(auth, "AWS4-") {
		algorithm, credential, signedHeaders, signature = parseAuthorization(auth)
		date = headers.Get(amzDate)
		regionSet = headers.Get(amzRegionSet)
		payloadHash = headers.Get(amzContentSHA)
		if payloadHash == "" {
			payloadHash = hashSHA256(nil)
		}
	} else {
		return nil, errors.New("request is not signed")
	}

	scheme := Scheme(algorithm)
	if scheme != SchemeV4 && scheme != SchemeV4a {
		return nil, fmt.Errorf("unsupported signature algorithm %q", algorithm)
	}
	if credential == "" || signedHeaders == "" || signature == "" || date == "" {
		return nil, errors.New("incomplete signature parameters")
	}

	// Credential = "<accessKeyId>/<scope>". V4 scope carries the region; V4a does
	// not (region comes from X-Amz-Region-Set).
	credParts := strings.Split(credential, "/")
	wantParts := 5
	if scheme == SchemeV4a {
		wantParts = 4
	}
	if len(credParts) != wantParts || credParts[len(credParts)-1] != terminator {
		return nil, fmt.Errorf("malformed credential %q", credential)
	}
	accessKeyID := credParts[0]
	scope := strings.Join(credParts[1:], "/")

	region := regionSet
	if scheme == SchemeV4 {
		region = credParts[2]
	}

	canonicalURI := u.EscapedPath()
	if canonicalURI == "" {
		canonicalURI = "/"
	}

	signed := query
	signed.Del(amzSignature)

	host := headers.Get("Host")
	if host == "" {
		host = u.Host
	}

	return &SignedRequest{
		Scheme:        scheme,
		AccessKeyID:   accessKeyID,
		Region:        region,
		method:        req.Method,
		canonicalURI:  canonicalURI,
		query:         signed,
		headers:       headers,
		host:          host,
		signedHeaders: splitSignedHeaders(signedHeaders),
		payloadHash:   payloadHash,
		amzDate:       date,
		scope:         scope,
		signature:     signature,
	}, nil
}

// Verify recomputes the request signature from secretAccessKey (the client's
// multibase base64url secret) and compares it to the one on the request. It
// returns nil when the signature is valid.
func Verify(req *SignedRequest, secretAccessKey string) error {
	switch req.Scheme {
	case SchemeV4:
		return verifyV4(req, secretAccessKey)
	case SchemeV4a:
		return verifyV4a(req, secretAccessKey)
	default:
		return fmt.Errorf("unsupported signature algorithm %q", req.Scheme)
	}
}

// scopeService returns the service element of the credential scope (e.g. "s3").
func (s *SignedRequest) scopeService() string {
	parts := strings.Split(s.scope, "/")
	// scope is "<date>/[<region>/]<service>/aws4_request"; service is second-last.
	if len(parts) < 2 {
		return ""
	}
	return parts[len(parts)-2]
}

// scopeDate returns the yyyymmdd date element of the credential scope.
func (s *SignedRequest) scopeDate() string {
	parts := strings.Split(s.scope, "/")
	if len(parts) == 0 {
		return ""
	}
	return parts[0]
}

func splitSignedHeaders(s string) []string {
	hdrs := strings.Split(strings.ToLower(s), ";")
	sort.Strings(hdrs)
	return hdrs
}

// parseAuthorization splits a SigV4/SigV4a Authorization header value:
// "<ALGO> Credential=<cred>, SignedHeaders=<hdrs>, Signature=<sig>".
func parseAuthorization(auth string) (algorithm, credential, signedHeaders, signature string) {
	algorithm, rest, ok := strings.Cut(auth, " ")
	if !ok {
		return "", "", "", ""
	}
	for part := range strings.SplitSeq(rest, ",") {
		part = strings.TrimSpace(part)
		k, v, ok := strings.Cut(part, "=")
		if !ok {
			continue
		}
		switch k {
		case "Credential":
			credential = v
		case "SignedHeaders":
			signedHeaders = v
		case "Signature":
			signature = v
		}
	}
	return algorithm, credential, signedHeaders, signature
}
