// SPDX-License-Identifier: AGPL-3.0-or-later

package envelope

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"testing"
)

func TestSmallOrderEd25519Rejected(t *testing.T) {
	id := make([]byte, 32)
	id[0] = 1
	sig := make([]byte, 64)
	sig[0] = 1 // R = identity, S = 0: verifies under the identity key for every message
	if !ed25519.Verify(id, []byte("hello"), sig) {
		t.Fatal("crypto/ed25519 no longer accepts the identity forgery; the table may be obsolete")
	}
	for _, p := range ed25519SmallOrder {
		if _, err := DecodeKey(hex.EncodeToString(p)); err == nil {
			t.Fatalf("hex %x accepted", p)
		}
		if _, err := ParseDeviceKey("ed25519", B64URL(p)); err == nil {
			t.Fatalf("base64url %x accepted", p)
		}
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeKey(hex.EncodeToString(pub)); err != nil {
		t.Fatal(err)
	}
	msg := []byte("ok")
	k, err := ParseDeviceKey("", B64URL(pub))
	if err != nil {
		t.Fatal(err)
	}
	if !k.Verify(msg, B64URL(ed25519.Sign(priv, msg))) {
		t.Fatal("honest key did not verify")
	}
}
