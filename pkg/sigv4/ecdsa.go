package sigv4

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
)

// signV4a computes a hex DER AWS4-ECDSA-P256-SHA256 signature for the request.
func (s *SignedRequest) signV4a(secretAccessKey string) (string, error) {
	priv, err := deriveKeyV4a(s.AccessKeyID, secretAccessKey)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256([]byte(s.stringToSign()))
	der, err := ecdsa.SignASN1(rand.Reader, priv, digest[:])
	if err != nil {
		return "", fmt.Errorf("signing: %w", err)
	}
	return hex.EncodeToString(der), nil
}

// verifyV4a verifies an AWS4-ECDSA-P256-SHA256 signature for req: it derives the
// access key's P-256 key and ECDSA-verifies the DER signature over the
// string-to-sign.
func verifyV4a(req *SignedRequest, secretAccessKey string) error {
	priv, err := deriveKeyV4a(req.AccessKeyID, secretAccessKey)
	if err != nil {
		return err
	}
	return verifyV4aWithPublicKey(req, &priv.PublicKey)
}

// verifyV4aWithKey verifies the signature using a compressed SEC1 P-256 public
// key (the SigV4a derived key, as produced by DeriveKey).
func verifyV4aWithKey(req *SignedRequest, key []byte) error {
	pub, err := parseCompressedP256(key)
	if err != nil {
		return err
	}
	return verifyV4aWithPublicKey(req, pub)
}

// verifyV4aWithPublicKey ECDSA-verifies the request's DER signature over the
// string-to-sign against pub.
func verifyV4aWithPublicKey(req *SignedRequest, pub *ecdsa.PublicKey) error {
	der, err := hex.DecodeString(req.signature)
	if err != nil {
		return fmt.Errorf("decoding signature: %w", err)
	}
	digest := sha256.Sum256([]byte(req.stringToSign()))
	if !ecdsa.VerifyASN1(pub, digest[:], der) {
		return errors.New("signature mismatch")
	}
	return nil
}

// parseCompressedP256 decodes a 33-byte compressed SEC1 point into an ECDSA P-256
// public key. The standard library has no non-deprecated compressed-point parser
// (crypto/ecdh rejects compressed points and ecdsa.ParseUncompressedPublicKey
// takes only uncompressed), so use elliptic.UnmarshalCompressed — the documented
// inverse of the compression DeriveKey applies — then re-encode as an
// uncompressed point for ecdsa.ParseUncompressedPublicKey.
func parseCompressedP256(key []byte) (*ecdsa.PublicKey, error) {
	x, y := elliptic.UnmarshalCompressed(elliptic.P256(), key)
	if x == nil {
		return nil, errors.New("sigv4a: invalid compressed public key")
	}
	uncompressed := make([]byte, 65)
	uncompressed[0] = 0x04
	x.FillBytes(uncompressed[1:33])
	y.FillBytes(uncompressed[33:65])
	return ecdsa.ParseUncompressedPublicKey(elliptic.P256(), uncompressed)
}

// derivedPublicKeyV4a derives the SigV4a P-256 key and returns its public key in
// compressed SEC1 form (33 bytes) — the s3.VerificationKey data for the "sigv4a"
// kind (see the RFC appendix, which encodes the same compressed bytes).
func derivedPublicKeyV4a(accessKeyID, secretAccessKey string) ([]byte, error) {
	priv, err := deriveKeyV4a(accessKeyID, secretAccessKey)
	if err != nil {
		return nil, err
	}
	// PublicKey.Bytes is the uncompressed SEC1 encoding (0x04 || X || Y); compress
	// it to 0x02|0x03(parity of Y) || X, avoiding the deprecated coordinate APIs.
	uncompressed, err := priv.PublicKey.Bytes()
	if err != nil {
		return nil, fmt.Errorf("sigv4a: marshaling public key: %w", err)
	}
	compressed := make([]byte, 33)
	compressed[0] = 0x02 | (uncompressed[64] & 1)
	copy(compressed[1:], uncompressed[1:33])
	return compressed, nil
}

// deriveKeyV4a derives the SigV4a ECDSA P-256 private key from an access key id
// and secret using AWS's NIST SP 800-108 counter-mode KDF (HMAC-SHA256 keyed by
// "AWS4A" + secret). It mirrors aws-sdk-go-v2's internal/v4a derivation so the
// key matches what an AWS client uses.
func deriveKeyV4a(accessKeyID, secretAccessKey string) (*ecdsa.PrivateKey, error) {
	const label = string(SchemeV4a) // "AWS4-ECDSA-P256-SHA256"
	nMinusTwo := new(big.Int).Sub(elliptic.P256().Params().N, big.NewInt(2))

	var d *big.Int
	for counter := 1; counter <= 0xFE; counter++ {
		// fixed input: 0x00000001 || label || 0x00 || accessKeyID || counter || 0x00000100
		var input bytes.Buffer
		input.Write([]byte{0x00, 0x00, 0x00, 0x01})
		input.WriteString(label)
		input.WriteByte(0x00)
		input.WriteString(accessKeyID)
		input.WriteByte(byte(counter))
		input.Write([]byte{0x00, 0x00, 0x01, 0x00})

		candidate := hmacSHA256([]byte("AWS4A"+secretAccessKey), input.Bytes())

		c := new(big.Int).SetBytes(candidate)
		if c.Cmp(nMinusTwo) <= 0 {
			d = c.Add(c, big.NewInt(1)) // d in [1, N-1]
			break
		}
	}
	if d == nil {
		return nil, errors.New("sigv4a: exhausted key-derivation counter")
	}

	// Derive the public point via crypto/ecdh (validates the scalar range) and
	// bridge to an *ecdsa.PrivateKey without the deprecated raw-coordinate APIs.
	ecdhKey, err := ecdh.P256().NewPrivateKey(d.FillBytes(make([]byte, 32)))
	if err != nil {
		return nil, fmt.Errorf("sigv4a: invalid derived scalar: %w", err)
	}
	pub, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), ecdhKey.PublicKey().Bytes())
	if err != nil {
		return nil, fmt.Errorf("sigv4a: parsing derived public key: %w", err)
	}
	return &ecdsa.PrivateKey{PublicKey: *pub, D: d}, nil
}
