package sigv4

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// awsSuiteSecret is the example secret access key AWS documents for its SigV4
// test suite (see testdata/aws-sig-v4-test-suite/README.md). All vectors are
// signed with it.
const awsSuiteSecret = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"

const awsSuiteRoot = "testdata/aws-sig-v4-test-suite"

// awsSuiteIncompatible lists vectors that a faithful S3-style verifier cannot
// reproduce, and are therefore asserted as expected-failures:
//
//   - Path-normalization vectors: the generic AWS suite normalizes the request
//     path (// -> /, /example/.. -> /, /./ -> /). S3 does NOT normalize, and
//     neither does this verifier (it signs the escaped path verbatim), so the
//     canonical URI — and thus the signature — differs.
//   - Multiline (folded) header vector: AWS joins the folded continuation lines
//     with commas (value1,value2,value3), but HTTP stacks — and therefore Ingot —
//     unfold obsolete line folding with spaces, so an S3 verifier fed a realistic
//     request cannot reproduce the comma-joined canonical form.
//
// Duplicate header keys are NOT incompatible: parseSreq combines them into one
// comma-separated value in appearance order, matching AWS's canonical-header rule.
var awsSuiteIncompatible = map[string]string{
	"get-slash":                  "S3 does not normalize request paths (// stays //)",
	"get-slashes":                "S3 does not normalize request paths",
	"get-slash-dot-slash":        "S3 does not normalize request paths (/./ stays)",
	"get-slash-pointless-dot":    "S3 does not normalize request paths",
	"get-relative":               "S3 does not normalize request paths (/example/.. stays)",
	"get-relative-relative":      "S3 does not normalize request paths",
	"get-header-value-multiline": "folded header values are unfolded with spaces, not AWS's commas",
}

// TestAWSSigV4Suite runs Parse + Verify over every AWS SigV4 test-suite vector.
// The S3-compatible vectors must verify; the ones exercising behaviour S3
// deliberately diverges from (see [awsSuiteIncompatible]) must fail.
func TestAWSSigV4Suite(t *testing.T) {
	var vectors []string
	err := filepath.WalkDir(awsSuiteRoot, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() && strings.HasSuffix(path, ".sreq") {
			vectors = append(vectors, path)
		}
		return nil
	})
	require.NoError(t, err)
	require.NotEmpty(t, vectors, "no .sreq vectors found under %s", awsSuiteRoot)

	for _, path := range vectors {
		name := strings.TrimSuffix(filepath.Base(path), ".sreq")
		rel, _ := filepath.Rel(awsSuiteRoot, path)
		t.Run(rel, func(t *testing.T) {
			req := parseSreq(t, path)

			sr, err := Parse(req)
			if err == nil {
				err = Verify(sr, awsSuiteSecret)
			}

			if reason, incompatible := awsSuiteIncompatible[name]; incompatible {
				require.Error(t, err, "expected verification to fail: %s", reason)
			} else {
				require.NoError(t, err, "vector should verify against AWS's signature")
			}
		})
	}
}

// parseSreq reads a signed-request vector file into a [Request]. It performs the
// minimal raw-HTTP parsing the vectors need (net/http.ReadRequest mangles "//"
// request targets and cannot yield a map[string]string). The empty-payload /
// body hash is injected as X-Amz-Content-Sha256, which the vectors omit but Parse
// requires — it is exactly the payload hash AWS signed with.
func parseSreq(t *testing.T, path string) Request {
	t.Helper()
	raw, err := os.ReadFile(path)
	require.NoError(t, err)

	// Split headers from body on the first blank line (CRLF or LF).
	head, body, ok := bytes.Cut(raw, []byte("\r\n\r\n"))
	if !ok {
		head, body, _ = bytes.Cut(raw, []byte("\n\n"))
	}

	lines := strings.Split(string(head), "\n")
	require.NotEmpty(t, lines)

	// Request line: METHOD <target> HTTP/1.1
	reqLine := strings.TrimRight(lines[0], "\r")
	method, rest, ok := strings.Cut(reqLine, " ")
	require.True(t, ok, "malformed request line %q", reqLine)
	target := rest
	if i := strings.LastIndex(rest, " HTTP/"); i >= 0 {
		target = rest[:i]
	}

	headers := map[string]string{}
	var lastKey string
	for _, line := range lines[1:] {
		line = strings.TrimRight(line, "\r")
		if line == "" {
			continue
		}
		// Continuation of the previous header (obsolete line folding).
		if lastKey != "" && (strings.HasPrefix(line, " ") || strings.HasPrefix(line, "\t")) {
			headers[lastKey] += " " + strings.TrimSpace(line)
			continue
		}
		key, value, ok := strings.Cut(line, ":")
		require.True(t, ok, "malformed header line %q", line)
		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)
		// Combine duplicate header keys into one comma-separated value in the
		// order they appear — matching AWS's canonical-header rule and how Ingot
		// maps an incoming request into a Hilt invocation.
		if existing, exists := headers[key]; exists {
			headers[key] = existing + "," + value
		} else {
			headers[key] = value
		}
		lastKey = key
	}

	host := headers["Host"]
	require.NotEmpty(t, host, "vector %s is missing a Host header", path)

	// The vectors omit X-Amz-Content-Sha256; inject the payload hash AWS signed
	// with (empty-string hash when there is no body).
	if _, ok := headers[amzContentSHA]; !ok {
		headers[amzContentSHA] = hashSHA256(body)
	}

	return Request{
		Method:  method,
		Headers: headers,
		URL:     "https://" + host + target,
	}
}
