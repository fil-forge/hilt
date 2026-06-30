package sigv4

import (
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"strings"
)

// canonicalRequest builds the AWS canonical request string per the SigV4 spec.
func (s *SignedRequest) canonicalRequest() string {
	var b strings.Builder
	b.WriteString(s.method)
	b.WriteByte('\n')
	b.WriteString(s.canonicalURI)
	b.WriteByte('\n')
	b.WriteString(s.canonicalQueryString())
	b.WriteByte('\n')
	b.WriteString(s.canonicalHeaders())
	b.WriteByte('\n')
	b.WriteString(strings.Join(s.signedHeaders, ";"))
	b.WriteByte('\n')
	b.WriteString(s.payloadHash)
	return b.String()
}

// stringToSign builds the AWS string-to-sign for the given algorithm.
func (s *SignedRequest) stringToSign() string {
	return string(s.Scheme) + "\n" +
		s.amzDate + "\n" +
		s.scope + "\n" +
		hashSHA256([]byte(s.canonicalRequest()))
}

// canonicalQueryString encodes and sorts the signed query parameters.
func (s *SignedRequest) canonicalQueryString() string {
	pairs := make([]string, 0, len(s.query))
	for key, values := range s.query {
		ek := awsURIEncode(key, true)
		for _, v := range values {
			pairs = append(pairs, ek+"="+awsURIEncode(v, true))
		}
	}
	sort.Strings(pairs)
	return strings.Join(pairs, "&")
}

// canonicalHeaders builds the canonical header block for the signed headers.
func (s *SignedRequest) canonicalHeaders() string {
	var b strings.Builder
	for _, name := range s.signedHeaders {
		var value string
		if name == "host" {
			value = s.host
		} else {
			value = s.headers.Get(name)
		}
		b.WriteString(name)
		b.WriteByte(':')
		b.WriteString(trimHeaderValue(value))
		b.WriteByte('\n')
	}
	return b.String()
}

// trimHeaderValue trims surrounding whitespace and collapses internal runs of
// whitespace to a single space, per the SigV4 canonical header rules.
func trimHeaderValue(v string) string {
	return strings.Join(strings.Fields(v), " ")
}

// awsURIEncode percent-encodes per the AWS SigV4 rules: unreserved characters
// are left as-is, everything else is %XX (uppercase hex). When encodeSlash is
// false, '/' is left literal (used for the canonical URI path).
func awsURIEncode(s string, encodeSlash bool) string {
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
			(c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.' || c == '~':
			b.WriteByte(c)
		case c == '/' && !encodeSlash:
			b.WriteByte(c)
		default:
			b.WriteByte('%')
			b.WriteByte(upperHex[c>>4])
			b.WriteByte(upperHex[c&0x0f])
		}
	}
	return b.String()
}

const upperHex = "0123456789ABCDEF"

// hashSHA256 returns the lowercase hex SHA-256 of b.
func hashSHA256(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}
