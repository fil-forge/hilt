package auth

import (
	"encoding/base64"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestBodyChecksums pins each checksum header's digest against the
// algorithm's published check value for "123456789", as the SDKs compute
// them: the CRC-64 table in particular is hilt's own choice of polynomial.
func TestBodyChecksums(t *testing.T) {
	check := []byte("123456789")
	want := map[string]string{
		"x-amz-checksum-crc32":     "y/Q5Jg==",     // 0xCBF43926
		"x-amz-checksum-crc32c":    "4waSgw==",     // 0xE3069283
		"x-amz-checksum-crc64nvme": "rosUhgp5mIg=", // 0xAE8B14860A799888
		"x-amz-checksum-sha1":      "98O8HYCOBHMq32eZZczDTKeuNEE=",
		"x-amz-checksum-sha256":    "FeKw08M4keuw8e9gnsQZQgwg4yDOlMZfvIwzEkSOsiU=",
		"content-md5":              "JfnnlDI7RTiF9RgfG2JNCw==",
	}
	for _, h := range bodyChecksumHeaders {
		require.Equal(t, want[h.name], base64.StdEncoding.EncodeToString(h.sum(check)), h.name)
	}
	require.Len(t, want, len(bodyChecksumHeaders))
}
