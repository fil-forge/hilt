package sigv4

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http"
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

// stringToSign builds the AWS string-to-sign.
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
//
// On a GET or HEAD, a signed content-length the request does not carry is taken
// as 0. Some clients (aws-cli 2.38.0 through 2.39.3) sign Content-Length: 0 on
// a GET, and a reverse proxy built on Go's HTTP client drops that header when
// forwarding a bodyless request. A non-zero length always reaches us and is
// verified as sent. Other methods get no default: a PUT signed with a zero
// length and an unsigned payload could otherwise be replayed without the header
// and with a chunked body, which Hilt never sees.
//
// versitygw's signature check signs a missing content-length as 0 on every
// method. Its authentication middleware parses the header into a length that
// stays 0 when the header is absent, and its signer writes that length whenever
// the client signed content-length:
// https://github.com/fil-forge/versitygw/blob/23d4d71f50ac23877f3a4e5ed956f444e0df1058/s3api/middlewares/authentication.go#L139-L147
// https://github.com/fil-forge/versitygw/blob/23d4d71f50ac23877f3a4e5ed956f444e0df1058/aws/signer/v4/v4.go#L478-L482
// For a header that is present, versitygw signs the parsed number while we sign
// the value as received, so the two differ for values such as "05".
func (s *SignedRequest) canonicalHeaders() string {
	var b strings.Builder
	for _, name := range s.signedHeaders {
		var value string
		switch {
		case name == "host":
			value = s.host
		case name == "content-length" && isBodyless(s.method) && len(s.headers.Values(name)) == 0:
			value = "0"
		default:
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

// isBodyless reports whether S3 requests with this method never carry a body.
// OPTIONS is left out: S3 CORS preflights are not signed, and the authorizer
// refuses the method.
func isBodyless(method string) bool {
	return method == http.MethodGet || method == http.MethodHead
}
