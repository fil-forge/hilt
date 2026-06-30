package sigv4

import (
	"fmt"
	"net/url"
	"time"
)

const (
	amzDateFormat = "20060102T150405Z"
	dateFormat    = "20060102"
	service       = "s3"
)

// Presign returns a copy of req signed as a presigned URL (auth in the query
// string) for the given scheme. It mirrors Verify's canonicalization and is
// primarily used by tests and any client-side signing; Hilt itself only
// verifies. host is the only signed header.
func Presign(req Request, accessKeyID, secretAccessKey, region string, scheme Scheme, signedAt time.Time) (Request, error) {
	u, err := url.Parse(req.URL)
	if err != nil {
		return Request{}, fmt.Errorf("parsing request URL: %w", err)
	}

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
	q.Set(amzSignedHdrs, "host")
	if scheme == SchemeV4a {
		q.Set(amzRegionSet, region)
	}

	canonicalURI := u.EscapedPath()
	if canonicalURI == "" {
		canonicalURI = "/"
	}

	sr := &SignedRequest{
		Scheme:        scheme,
		AccessKeyID:   accessKeyID,
		Region:        region,
		method:        req.Method,
		canonicalURI:  canonicalURI,
		query:         q, // X-Amz-Signature not yet set
		headers:       toHeader(req.Headers),
		host:          u.Host,
		signedHeaders: []string{"host"},
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
