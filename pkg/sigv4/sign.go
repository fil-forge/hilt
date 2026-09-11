package sigv4

import (
	"fmt"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"
)

const (
	amzDateFormat = "20060102T150405Z"
	dateFormat    = "20060102"
	service       = "s3"
)

// PresignOption adjusts Presign.
type PresignOption func(*presignConfig)

type presignConfig struct {
	signedHeaders []string
}

// WithSignedHeaders covers the named request headers with the signature, in
// addition to host. Their values are read from req.Headers when signing, so the
// same values must be sent with the request.
func WithSignedHeaders(names ...string) PresignOption {
	return func(c *presignConfig) {
		for _, n := range names {
			c.signedHeaders = append(c.signedHeaders, strings.ToLower(n))
		}
	}
}

// Presign returns a copy of req signed as a presigned URL (auth in the query
// string) for the given scheme, valid for expires from signedAt. It mirrors
// Verify's canonicalization and is primarily used by tests and any client-side
// signing; Hilt itself only verifies. host is signed, plus any headers named by
// WithSignedHeaders.
func Presign(req Request, accessKeyID, secretAccessKey, region string, scheme Scheme, signedAt time.Time, expires time.Duration, opts ...PresignOption) (Request, error) {
	u, err := url.Parse(req.URL)
	if err != nil {
		return Request{}, fmt.Errorf("parsing request URL: %w", err)
	}
	cfg := presignConfig{signedHeaders: []string{"host"}}
	for _, opt := range opts {
		opt(&cfg)
	}
	slices.Sort(cfg.signedHeaders)
	cfg.signedHeaders = slices.Compact(cfg.signedHeaders)

	date := signedAt.UTC().Format(amzDateFormat)
	stamp := signedAt.UTC().Format(dateFormat)

	scope := stamp + "/" + region + "/" + service + "/" + terminator
	if scheme == SchemeV4a {
		scope = stamp + "/" + service + "/" + terminator
	}

	q := u.Query()
	q.Set(amzAlgorithm, string(scheme))
	q.Set(amzCredential, accessKeyID+"/"+scope)
	q.Set(amzDate, date)
	q.Set(amzExpires, strconv.Itoa(int(expires.Seconds())))
	q.Set(amzSignedHdrs, strings.Join(cfg.signedHeaders, ";"))
	if scheme == SchemeV4a {
		q.Set(amzRegionSet, region)
	}

	canonicalURI := u.EscapedPath()
	if canonicalURI == "" {
		canonicalURI = "/"
	}
	headers, err := toHeader(req.Headers)
	if err != nil {
		return Request{}, err
	}

	sr := &SignedRequest{
		Scheme:        scheme,
		AccessKeyID:   accessKeyID,
		Regions:       []string{region},
		method:        req.Method,
		canonicalURI:  canonicalURI,
		query:         q, // X-Amz-Signature not yet set
		headers:       headers,
		host:          u.Host,
		signedHeaders: cfg.signedHeaders,
		payloadHash:   unsignedPayload,
		amzDate:       date,
		scope:         scope,
	}

	var signature string
	switch scheme {
	case SchemeV4:
		signature = sr.signV4(secretAccessKey)
	case SchemeV4a:
		signature, err = sr.signV4a(secretAccessKey)
		if err != nil {
			return Request{}, err
		}
	default:
		return Request{}, fmt.Errorf("unsupported signature algorithm %q", scheme)
	}

	q.Set(amzSignature, signature)
	u.RawQuery = q.Encode()

	signed := req
	signed.URL = u.String()
	return signed, nil
}
