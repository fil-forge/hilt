package sigv4

import (
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// TestSigV4KnownAnswer checks the canonical-request + string-to-sign + HMAC
// chain against AWS's documented worked example, anchoring SigV4 correctness:
// https://docs.aws.amazon.com/general/latest/gr/sigv4-create-canonical-request.html
func TestSigV4KnownAnswer(t *testing.T) {
	sr := &SignedRequest{
		Scheme:       SchemeV4,
		Regions:      []string{"us-east-1"},
		method:       "GET",
		canonicalURI: "/",
		query:        mustQuery(t, "Action=ListUsers&Version=2010-05-08"),
		headers: http.Header{
			"Content-Type": {"application/x-www-form-urlencoded; charset=utf-8"},
			"X-Amz-Date":   {"20150830T123600Z"},
		},
		host:          "iam.amazonaws.com",
		signedHeaders: []string{"content-type", "host", "x-amz-date"},
		payloadHash:   hashSHA256(nil),
		amzDate:       "20150830T123600Z",
		scope:         "20150830/us-east-1/iam/aws4_request",
	}

	const (
		secret = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"
		want   = "5d672d79c15b13162d9279b0855cfba6789a8edb4c82c400e06b5924a6f2b5d7"
	)
	require.Equal(t, want, sr.signV4(secret))
}

func mustQuery(t *testing.T, raw string) url.Values {
	t.Helper()
	v, err := url.ParseQuery(raw)
	require.NoError(t, err)
	return v
}

func TestRoundTrip(t *testing.T) {
	const (
		akid   = "z6MkExampleAccessKeyIdentifier000000000000000"
		secret = "uExampleSecretAccessKeyMaterial00000000000000"
		region = "us-east-1"
	)
	at := time.Date(2026, 6, 30, 12, 0, 0, 0, time.UTC)

	for _, scheme := range []Scheme{SchemeV4, SchemeV4a} {
		t.Run(string(scheme), func(t *testing.T) {
			req := Request{Method: "GET", URL: "https://bucket.s3.fil.one/path?x-id=ListBuckets"}

			signed, err := Presign(req, akid, secret, region, scheme, at, time.Hour)
			require.NoError(t, err)

			sr, err := Parse(signed)
			require.NoError(t, err)
			require.Equal(t, scheme, sr.Scheme)
			require.Equal(t, akid, sr.AccessKeyID)
			require.Equal(t, []string{region}, sr.Regions)

			require.NoError(t, Verify(sr, secret), "valid signature should verify")
			require.Error(t, Verify(sr, "uWrongSecret0000000000000000000000000000000"), "wrong secret should fail")
		})
	}
}

func TestVerifyRejectsTamperedSignature(t *testing.T) {
	const (
		akid   = "z6MkExampleAccessKeyIdentifier000000000000000"
		secret = "uExampleSecretAccessKeyMaterial00000000000000"
	)
	signed, err := Presign(
		Request{Method: "GET", URL: "https://bucket.s3.fil.one/"},
		akid, secret, "us-east-1", SchemeV4, time.Unix(0, 0).UTC(), time.Hour,
	)
	require.NoError(t, err)

	sr, err := Parse(signed)
	require.NoError(t, err)
	sr.signature = "deadbeef" // tamper
	require.Error(t, Verify(sr, secret))
}

func TestDeriveKeyV4aDeterministic(t *testing.T) {
	const (
		akid   = "z6MkExampleAccessKeyIdentifier000000000000000"
		secret = "uExampleSecretAccessKeyMaterial00000000000000"
	)
	k1, err := deriveKeyV4a(akid, secret)
	require.NoError(t, err)
	k2, err := deriveKeyV4a(akid, secret)
	require.NoError(t, err)
	other, err := deriveKeyV4a(akid, "uDifferentSecret00000000000000000000000000000")
	require.NoError(t, err)

	b1, err := k1.Bytes()
	require.NoError(t, err)
	b2, err := k2.Bytes()
	require.NoError(t, err)
	bOther, err := other.Bytes()
	require.NoError(t, err)

	require.Equal(t, b1, b2, "derivation must be deterministic")
	require.NotEqual(t, b1, bOther, "different secret yields a different key")
}

func TestParseHeaderAuth(t *testing.T) {
	req := Request{
		Method: "GET",
		URL:    "https://bucket.s3.fil.one/",
		Headers: map[string]string{
			"Authorization": "AWS4-HMAC-SHA256 Credential=z6MkAbc/20260616/us-west-2/s3/aws4_request, SignedHeaders=host;x-amz-date, Signature=abc123",
			"X-Amz-Date":    "20260616T091923Z",
		},
	}
	sr, err := Parse(req)
	require.NoError(t, err)
	require.Equal(t, SchemeV4, sr.Scheme)
	require.Equal(t, "z6MkAbc", sr.AccessKeyID)
	require.Equal(t, []string{"us-west-2"}, sr.Regions)
}

func TestParseRegionsV4a(t *testing.T) {
	// SigV4a credential scope omits the region; regions come from X-Amz-Region-Set.
	u := "https://bucket.s3.fil.one/?X-Amz-Algorithm=AWS4-ECDSA-P256-SHA256" +
		"&X-Amz-Credential=z6MkAbc%2F20260616%2Fs3%2Faws4_request" +
		"&X-Amz-Region-Set=us-east-1%2Cus-west-2" +
		"&X-Amz-SignedHeaders=host&X-Amz-Signature=abc&X-Amz-Date=20260616T091923Z"
	sr, err := Parse(Request{Method: "GET", URL: u})
	require.NoError(t, err)
	require.Equal(t, SchemeV4a, sr.Scheme)
	require.Equal(t, []string{"us-east-1", "us-west-2"}, sr.Regions)
}

func TestParseErrors(t *testing.T) {
	t.Run("unsigned", func(t *testing.T) {
		_, err := Parse(Request{Method: "GET", URL: "https://bucket.s3.fil.one/"})
		require.Error(t, err)
	})
	t.Run("malformed credential", func(t *testing.T) {
		_, err := Parse(Request{
			Method: "GET",
			URL:    "https://bucket.s3.fil.one/?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=z6MkAbc%2Fonly&X-Amz-SignedHeaders=host&X-Amz-Signature=abc&X-Amz-Date=20260616T091923Z",
		})
		require.Error(t, err)
	})
}

func TestValidateTimeBounds(t *testing.T) {
	const (
		akid   = "z6MkExampleAccessKeyIdentifier000000000000000"
		secret = "uExampleSecretAccessKeyMaterial00000000000000"
	)
	signedAt := time.Date(2026, 6, 30, 12, 0, 0, 0, time.UTC)

	presign := func(t *testing.T, at time.Time, expires time.Duration) *SignedRequest {
		t.Helper()
		signed, err := Presign(Request{Method: "GET", URL: "https://bucket.s3.fil.one/"}, akid, secret, "us-east-1", SchemeV4, at, expires)
		require.NoError(t, err)
		sr, err := Parse(signed)
		require.NoError(t, err)
		return sr
	}

	t.Run("presigned within window", func(t *testing.T) {
		sr := presign(t, signedAt, time.Hour)
		require.NoError(t, ValidateTimeBounds(sr, signedAt.Add(30*time.Minute)))
	})

	t.Run("presigned expired", func(t *testing.T) {
		sr := presign(t, signedAt, time.Hour)
		require.Error(t, ValidateTimeBounds(sr, signedAt.Add(2*time.Hour)))
	})

	t.Run("presigned not yet valid", func(t *testing.T) {
		sr := presign(t, signedAt, time.Hour)
		require.Error(t, ValidateTimeBounds(sr, signedAt.Add(-time.Minute)))
	})

	t.Run("presigned expires too large", func(t *testing.T) {
		sr := presign(t, signedAt, 8*24*time.Hour) // > 7 days
		require.Error(t, ValidateTimeBounds(sr, signedAt.Add(time.Hour)))
	})

	// Header auth carries no X-Amz-Expires; it's bound by the clock-skew window.
	t.Run("header auth within skew", func(t *testing.T) {
		sr := &SignedRequest{amzDate: signedAt.Format(amzDateFormat)}
		require.NoError(t, ValidateTimeBounds(sr, signedAt.Add(5*time.Minute)))
	})

	t.Run("header auth too skewed", func(t *testing.T) {
		sr := &SignedRequest{amzDate: signedAt.Format(amzDateFormat)}
		require.Error(t, ValidateTimeBounds(sr, signedAt.Add(time.Hour)))
	})
}
