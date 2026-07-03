package sigv4

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
)

// verifyV4 recomputes the AWS4-HMAC-SHA256 signature for req and compares it.
func verifyV4(req *SignedRequest, secretAccessKey string) error {
	key := deriveSigningKeyV4(secretAccessKey, req.scopeDate(), req.scopeRegion(), req.scopeService())
	return verifyV4WithKey(req, key)
}

// verifyV4WithKey verifies the HMAC signature using a precomputed signing key
// (the SigV4 derived key, as produced by DeriveKey).
func verifyV4WithKey(req *SignedRequest, key []byte) error {
	if !hmac.Equal([]byte(req.signV4WithKey(key)), []byte(req.signature)) {
		return fmt.Errorf("signature mismatch")
	}
	return nil
}

// signV4 computes the hex AWS4-HMAC-SHA256 signature for the request.
func (s *SignedRequest) signV4(secretAccessKey string) string {
	key := deriveSigningKeyV4(secretAccessKey, s.scopeDate(), s.scopeRegion(), s.scopeService())
	return s.signV4WithKey(key)
}

// signV4WithKey computes the hex signature from a precomputed signing key.
func (s *SignedRequest) signV4WithKey(key []byte) string {
	return hex.EncodeToString(hmacSHA256(key, []byte(s.stringToSign())))
}

// deriveSigningKeyV4 derives the SigV4 signing key:
// HMAC chain over date, region, service, then the "aws4_request" terminator,
// seeded with "AWS4" + secret.
func deriveSigningKeyV4(secret, date, region, service string) []byte {
	kDate := hmacSHA256([]byte("AWS4"+secret), []byte(date))
	kRegion := hmacSHA256(kDate, []byte(region))
	kService := hmacSHA256(kRegion, []byte(service))
	return hmacSHA256(kService, []byte(terminator))
}

func hmacSHA256(key, data []byte) []byte {
	h := hmac.New(sha256.New, key)
	h.Write(data)
	return h.Sum(nil)
}
