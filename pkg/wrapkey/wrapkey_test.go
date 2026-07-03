package wrapkey

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/fil-forge/ucantone/did/key"
)

// TestEncodingVector pins the did:key/Multikey wire format against an
// independent anchor so Hilt's encoding and Ingot's FEE-recipient parser cannot
// silently drift. The input is the X25519 public key from RFC 7748 §6.1
// ("Alice"), and the expected value is its did:key form: base58btc of the
// x25519-pub multicodec (0xec) followed by the 32 raw key bytes. If the prefix,
// multibase, or byte order ever changes, this test fails.
func TestEncodingVector(t *testing.T) {
	const rfc7748AlicePub = "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"
	const wantString = "z6LSkdrX4EvewpktHBjvNxRDogPdC5iVF8LT3LPKefGAgi89"
	const wantDID = "did:key:" + wantString

	raw, err := hex.DecodeString(rfc7748AlicePub)
	if err != nil {
		t.Fatal(err)
	}

	pub, err := PublicFromRaw(raw)
	if err != nil {
		t.Fatalf("PublicFromRaw: %v", err)
	}

	if got := pub.String(); got != wantString {
		t.Errorf("String() = %q, want %q", got, wantString)
	}
	if got := pub.KeyDID().String(); got != wantDID {
		t.Errorf("KeyDID() = %q, want %q", got, wantDID)
	}

	// The tagged public bytes must be the x25519-pub varint (0xec 0x01)
	// followed by the raw key.
	wantBytes := append([]byte{0xec, 0x01}, raw...)
	if got := pub.Bytes(); !bytes.Equal(got, wantBytes) {
		t.Errorf("Bytes() = % x, want % x", got, wantBytes)
	}
}

// TestGenerateRoundTrip exercises the custody path: generate a key, seal it
// (tagged private bytes), read it back, and confirm the public identity is
// stable across the round trip.
func TestGenerateRoundTrip(t *testing.T) {
	kp, err := Generate()
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}

	if len(kp.Raw()) != KeySize {
		t.Errorf("Raw() length = %d, want %d", len(kp.Raw()), KeySize)
	}

	// Bytes() is the tagged private form written to the vault.
	sealed := kp.Bytes()
	wantPrefix := []byte{0x82, 0x26} // x25519-priv (0x1302) as unsigned varint.
	if !bytes.HasPrefix(sealed, wantPrefix) {
		t.Errorf("sealed prefix = % x, want prefix % x", sealed[:2], wantPrefix)
	}
	if len(sealed) != len(wantPrefix)+KeySize {
		t.Errorf("sealed length = %d, want %d", len(sealed), len(wantPrefix)+KeySize)
	}

	back, err := Decode(sealed)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if !bytes.Equal(back.Raw(), kp.Raw()) {
		t.Error("Decode round trip changed the raw private key")
	}
	if back.Public().String() != kp.Public().String() {
		t.Error("Decode round trip changed the public identity")
	}
}

// TestDecodeRejectsWrongCodec ensures Decode refuses bytes tagged with a
// non-X25519-priv multicodec, rather than silently accepting them.
func TestDecodeRejectsWrongCodec(t *testing.T) {
	kp, err := Generate()
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	// Tagged as x25519-pub (0xec) instead of x25519-priv.
	wrong := tag(PublicKeyCode, kp.Raw())
	if _, err := Decode(wrong); err == nil {
		t.Error("Decode accepted bytes tagged with the wrong multicodec")
	}
}

// TestFromRawRejectsBadLength ensures raw constructors validate key length.
func TestFromRawRejectsBadLength(t *testing.T) {
	if _, err := FromRaw(make([]byte, KeySize-1)); err == nil {
		t.Error("FromRaw accepted a short private key")
	}
	if _, err := PublicFromRaw(make([]byte, KeySize+1)); err == nil {
		t.Error("PublicFromRaw accepted an over-long public key")
	}
}

// TestKeyDIDMethod confirms the published verification method is a did:key.
func TestKeyDIDMethod(t *testing.T) {
	kp, err := Generate()
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if got := kp.KeyDID().Method(); got != key.Method {
		t.Errorf("KeyDID method = %q, want %q", got, key.Method)
	}
}
