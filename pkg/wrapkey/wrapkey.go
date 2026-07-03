// Package wrapkey provides the per-tenant X25519 FEE wrap-key primitive Hilt
// needs: key generation, custody encoding (multiformat-tagged private bytes for
// the vault), and the did:key / Multikey public-key encoding that Hilt publishes
// in a tenant's DID document and stores as the FEE recipient kid.
//
// This is deliberately NOT part of ucantone's multikey family. X25519 is a
// key-agreement key, not a signing key: it is not a ucan.Signer/Verifier and has
// no UCAN role, so it cannot register as a multikey decoder and does not belong
// in a UCAN library. The heavy FEE crypto (ECDH-ES+A256KW wrap/unwrap) lives in
// Ingot's fee tree; Hilt only mints a keypair and encodes its public half. The
// one thing both sides share is the did:key/Multikey wire format (multicodec
// x25519-pub 0xec + base58btc), which each implements independently against the
// standard — pinned here by TestEncodingVector so the two can't drift.
package wrapkey

import (
	"crypto/ecdh"
	"crypto/rand"
	"fmt"

	"github.com/fil-forge/ucantone/did"
	"github.com/fil-forge/ucantone/did/key"
	"github.com/multiformats/go-multibase"
	"github.com/multiformats/go-multicodec"
	"github.com/multiformats/go-varint"
)

const (
	// PublicKeyCode is the multicodec code for an X25519 public key (x25519-pub).
	PublicKeyCode = multicodec.X25519Pub
	// PrivateKeyCode is the multicodec code for an X25519 private key
	// (x25519-priv).
	PrivateKeyCode = multicodec.X25519Priv
)

// KeySize is the length in bytes of a raw X25519 public or private key.
const KeySize = 32

var curve = ecdh.X25519()

// tag prepends the multiformats varint for code to b.
func tag(code multicodec.Code, b []byte) []byte {
	n := varint.UvarintSize(uint64(code))
	out := make([]byte, n+len(b))
	varint.PutUvarint(out, uint64(code))
	copy(out[n:], b)
	return out
}

// untag verifies and strips the multiformats varint for code from b.
func untag(code multicodec.Code, b []byte) ([]byte, error) {
	got, n, err := varint.FromUvarint(b)
	if err != nil {
		return nil, fmt.Errorf("reading multicodec varint: %w", err)
	}
	if multicodec.Code(got) != code {
		return nil, fmt.Errorf("expected multicodec %s [0x%02x], got %s [0x%02x]", code, uint64(code), multicodec.Code(got), got)
	}
	return b[n:], nil
}

// KeyPair is an X25519 key-agreement keypair. It cannot sign or verify; it
// exists only to be an ECDH / FEE recipient.
type KeyPair struct {
	priv *ecdh.PrivateKey
}

// Generate creates a new random X25519 keypair.
func Generate() (*KeyPair, error) {
	priv, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generating X25519 key: %w", err)
	}
	return &KeyPair{priv: priv}, nil
}

// FromRaw builds a keypair from raw (untagged) 32-byte private key bytes.
func FromRaw(b []byte) (*KeyPair, error) {
	priv, err := curve.NewPrivateKey(b)
	if err != nil {
		return nil, fmt.Errorf("invalid X25519 private key: %w", err)
	}
	return &KeyPair{priv: priv}, nil
}

// Decode decodes a keypair from multiformat-tagged private key bytes (the form
// produced by [KeyPair.Bytes]): the x25519-priv varint followed by the 32-byte
// raw key. It is how a sealed vault value is read back.
func Decode(b []byte) (*KeyPair, error) {
	raw, err := untag(PrivateKeyCode, b)
	if err != nil {
		return nil, err
	}
	return FromRaw(raw)
}

// Bytes returns the private key with its multiformats prefix (x25519-priv). This
// is the form to seal in the vault, so the key type is recoverable on decode.
func (k *KeyPair) Bytes() []byte { return tag(PrivateKeyCode, k.priv.Bytes()) }

// Raw returns the 32-byte raw private key, without multiformats tags.
func (k *KeyPair) Raw() []byte { return k.priv.Bytes() }

// Public returns the public half of the keypair.
func (k *KeyPair) Public() *PublicKey { return &PublicKey{pub: k.priv.PublicKey()} }

// KeyDID returns the did:key DID for the public half — the value published as a
// DID-document verification method.
func (k *KeyPair) KeyDID() did.DID { return k.Public().KeyDID() }

// PublicKey is an X25519 public key.
type PublicKey struct {
	pub *ecdh.PublicKey
}

// PublicFromRaw builds a public key from raw (untagged) 32-byte bytes.
func PublicFromRaw(b []byte) (*PublicKey, error) {
	pub, err := curve.NewPublicKey(b)
	if err != nil {
		return nil, fmt.Errorf("invalid X25519 public key: %w", err)
	}
	return &PublicKey{pub: pub}, nil
}

// Raw returns the 32-byte raw public key, without multiformats tags.
func (p *PublicKey) Raw() []byte { return p.pub.Bytes() }

// Bytes returns the public key with its multiformats prefix (x25519-pub).
func (p *PublicKey) Bytes() []byte { return tag(PublicKeyCode, p.pub.Bytes()) }

// String returns the multibase (base58btc) encoding of the tagged public key —
// the fingerprint used as the FEE recipient kid, and the identifier of the key's
// did:key DID.
func (p *PublicKey) String() string {
	s, _ := multibase.Encode(multibase.Base58BTC, p.Bytes())
	return s
}

// KeyDID returns the did:key DID for this public key, e.g. did:key:z6LS….
func (p *PublicKey) KeyDID() did.DID {
	return did.New(key.Method, p.String())
}
