// SPDX-License-Identifier: AGPL-3.0-or-later

package envelope

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"testing"
)

// TestDecodeB64URLStrict: crypto review 2026-09-28, finding 10: only unpadded base64url, the form
// every producer emits, decodes. Padding, the standard alphabet, whitespace and non-canonical
// trailing bits are rejected, so a key or a signature has exactly one spelling.
func TestDecodeB64URLStrict(t *testing.T) {
	raw := []byte{0xfb, 0xff, 0x01, 0x02}
	enc := B64URL(raw)
	if enc != "-_8BAg" {
		t.Fatalf("encoder: %s", enc)
	}
	if got, err := DecodeB64URL(enc); err != nil || !bytes.Equal(got, raw) {
		t.Fatalf("round trip: %x %v", got, err)
	}
	if got, err := DecodeB64URL(""); err != nil || len(got) != 0 {
		t.Errorf("empty: %x %v", got, err)
	}
	for _, s := range []string{
		"+_8BAg", "-/8BAg", // standard alphabet
		"AQI=", "AQ==", "-_8BAg==", // padding
		"AR", "AQJ", // non-zero trailing bits: another spelling of the same bytes
		"AQI\n", " AQI", "AQI ", "AQ\nI", // whitespace
		"A", // a lone sextet is not a byte
	} {
		if b, err := DecodeB64URL(s); err == nil {
			t.Errorf("%q accepted as %x", s, b)
		}
	}
	// keys go through the same decoder: the padded spelling is refused, hex still works
	pub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	if k, err := DecodeKey(B64URL(pub)); err != nil || !bytes.Equal(k, pub) {
		t.Errorf("base64url key: %v", err)
	}
	if k, err := DecodeKey(hex.EncodeToString(pub)); err != nil || !bytes.Equal(k, pub) {
		t.Errorf("hex key: %v", err)
	}
	if _, err := DecodeKey(B64URL(pub) + "="); err == nil {
		t.Error("padded key accepted")
	}
}
