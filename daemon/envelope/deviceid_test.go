// SPDX-License-Identifier: AGPL-3.0-or-later

package envelope

// Regression for crypto-review finding 2 (2026-09-28): a device key is accepted only when
// deviceId = sha256(key), as at pairing time. Reviewer PoC tests
// (TestReviewGatewayDBKeySubstitution, TestReviewConfigEd25519IDMismatch) previously passed
// with reason=""; now they are rejections.

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"strings"
	"testing"
	"time"
)

func idTicket(t *testing.T, signer ed25519.PrivateKey, deviceID, digest string) *DecisionBody {
	t.Helper()
	p := ExecPayload(testSupervisorID, PendingID(digest), digest, "allow", time.Now().UnixMilli(), NewNonce())
	msg, err := SigningString(deviceID, p)
	if err != nil {
		t.Fatal(err)
	}
	return &DecisionBody{DeviceID: deviceID, Payload: p, Signature: B64URL(ed25519.Sign(signer, msg))}
}

func idVerify(b *DecisionBody, d *Devices, digest string) string {
	return Verify(b, VerifyCtx{Now: time.Now(), TsWindow: time.Minute, SupervisorID: testSupervisorID, Devices: d, Nonces: NewNonceCache(time.Minute),
		Pending: func(string) string { return digest }})
}

// Agent overwrote the trusted phone's public_key in the gateway DB (gateway_db) and signed a ticket itself.
func TestGatewayDBKeySubstitutionRejected(t *testing.T) {
	phonePub, _, _ := ed25519.GenerateKey(rand.Reader)
	phoneID := DeviceID(phonePub)
	atkPub, atkPriv, _ := ed25519.GenerateKey(rand.Reader)
	d := NewDevices([]TrustedDevice{{ID: phoneID}}, "auto")
	d.Lookup = func(string) (string, error) { return B64URL(atkPub), nil }
	digest := SHA256Hex([]byte("some exec envelope"))
	if r := idVerify(idTicket(t, atkPriv, phoneID, digest), d, digest); r != "gateway_pubkey_mismatch" {
		t.Fatalf("substituted gateway_db key: reason=%q, want gateway_pubkey_mismatch", r)
	}
	// with a pinned config key, the tampered DB key is ignored and does not interfere with the phone
	_, phonePriv, _ := ed25519.GenerateKey(rand.Reader)
	phonePub = phonePriv.Public().(ed25519.PublicKey)
	phoneID = DeviceID(phonePub)
	d = NewDevices([]TrustedDevice{{ID: phoneID, Pubkey: B64URL(phonePub)}}, "auto")
	d.Lookup = func(string) (string, error) { return B64URL(atkPub), nil }
	if k, r := d.Key(phoneID); r != "" || !k.Equal(Ed25519Key(phonePub)) {
		t.Fatalf("pinned key with tampered db: %q", r)
	}
	if r := idVerify(idTicket(t, atkPriv, phoneID, digest), d, digest); r != "bad_signature" {
		t.Fatalf("attacker ticket with pinned key: %q", r)
	}
	if r := idVerify(idTicket(t, phonePriv, phoneID, digest), d, digest); r != "" {
		t.Fatalf("phone ticket with pinned key: %q", r)
	}
	// a DB key matching the id is still accepted (legacy entries without pubkey)
	d = NewDevices([]TrustedDevice{{ID: phoneID}}, "auto")
	d.Lookup = func(string) (string, error) { return B64URL(phonePub), nil }
	if r := idVerify(idTicket(t, phonePriv, phoneID, digest), d, digest); r != "" {
		t.Fatalf("matching gateway_db key: %q", r)
	}
}

// Config entry {id: X, pubkey: K} where sha256(K) != X: Ed25519 and ES256.
func TestConfigKeyIDMismatchRejected(t *testing.T) {
	someID := SHA256Hex([]byte("not this key"))
	atkPub, atkPriv, _ := ed25519.GenerateKey(rand.Reader)
	td := TrustedDevice{ID: someID, Pubkey: B64URL(atkPub)}
	d := NewDevices([]TrustedDevice{td}, "")
	digest := SHA256Hex([]byte("env"))
	if r := idVerify(idTicket(t, atkPriv, someID, digest), d, digest); r != "config_pubkey_invalid" {
		t.Fatalf("config ed25519 id mismatch: reason=%q, want config_pubkey_invalid", r)
	}
	if err := CheckTrusted(td); err == nil {
		t.Fatal("CheckTrusted accepted an ed25519 key under a foreign id")
	}
	ec, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err := CheckTrusted(TrustedDevice{ID: someID, Pubkey: ES256Key(&ec.PublicKey).B64(), Alg: "es256"}); err == nil {
		t.Fatal("CheckTrusted accepted an es256 key under a foreign id")
	}
	// own keys, entry without pubkey, id with uppercase and spaces: all accepted
	ok := []TrustedDevice{
		{ID: DeviceID(atkPub), Pubkey: B64URL(atkPub)},
		{ID: ES256Key(&ec.PublicKey).ID(), Pubkey: ES256Key(&ec.PublicKey).B64(), Alg: "es256"},
		{ID: someID},
		{ID: " " + strings.ToUpper(DeviceID(atkPub)) + " ", Pubkey: B64URL(atkPub)},
	}
	for i, td := range ok {
		if err := CheckTrusted(td); err != nil {
			t.Errorf("ok[%d]: %v", i, err)
		}
	}
	if err := CheckTrusted(TrustedDevice{ID: someID, Pubkey: "not-a-key"}); err == nil {
		t.Error("CheckTrusted accepted an unparsable pubkey")
	}
	if err := CheckTrusted(TrustedDevice{ID: someID, Alg: "rs256"}); err == nil {
		t.Error("CheckTrusted accepted alg rs256")
	}
}
