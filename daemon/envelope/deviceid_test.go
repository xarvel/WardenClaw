// SPDX-License-Identifier: AGPL-3.0-or-later

package envelope

// Regression for crypto-review finding 2 (2026-09-28): a device key is accepted only when
// deviceId = sha256(key), as at pairing time. The reviewer PoC test
// (TestReviewConfigEd25519IDMismatch) previously passed with reason=""; now it is a rejection.
// The gateway DB as a second key source (the other PoC) is gone altogether.

import (
	"crypto/ed25519"
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

// An entry without pubkey has no key source: the device is refused, whoever signs.
func TestEntryWithoutPubkeyRejected(t *testing.T) {
	phonePub, phonePriv, _ := ed25519.GenerateKey(rand.Reader)
	phoneID := DeviceID(phonePub)
	_, atkPriv, _ := ed25519.GenerateKey(rand.Reader)
	d := NewDevices([]TrustedDevice{{ID: phoneID}})
	digest := SHA256Hex([]byte("some exec envelope"))
	for name, signer := range map[string]ed25519.PrivateKey{"phone": phonePriv, "attacker": atkPriv} {
		if r := idVerify(idTicket(t, signer, phoneID, digest), d, digest); r != "unknown_device" {
			t.Fatalf("%s ticket for an entry without pubkey: reason=%q, want unknown_device", name, r)
		}
	}
	// with a pinned config key only the phone signs
	d = NewDevices([]TrustedDevice{{ID: phoneID, Pubkey: B64URL(phonePub)}})
	if k, r := d.Key(phoneID); r != "" || !k.Equal(Ed25519Key(phonePub)) {
		t.Fatalf("pinned key: %q", r)
	}
	if r := idVerify(idTicket(t, atkPriv, phoneID, digest), d, digest); r != "bad_signature" {
		t.Fatalf("attacker ticket with pinned key: %q", r)
	}
	if r := idVerify(idTicket(t, phonePriv, phoneID, digest), d, digest); r != "" {
		t.Fatalf("phone ticket with pinned key: %q", r)
	}
}

// Config entry {id: X, pubkey: K} where sha256(K) != X.
func TestConfigKeyIDMismatchRejected(t *testing.T) {
	someID := SHA256Hex([]byte("not this key"))
	atkPub, atkPriv, _ := ed25519.GenerateKey(rand.Reader)
	td := TrustedDevice{ID: someID, Pubkey: B64URL(atkPub)}
	d := NewDevices([]TrustedDevice{td})
	digest := SHA256Hex([]byte("env"))
	if r := idVerify(idTicket(t, atkPriv, someID, digest), d, digest); r != "config_pubkey_invalid" {
		t.Fatalf("config ed25519 id mismatch: reason=%q, want config_pubkey_invalid", r)
	}
	if err := CheckTrusted(td); err == nil {
		t.Fatal("CheckTrusted accepted an ed25519 key under a foreign id")
	}
	// own key (alg absent and explicit), entry without pubkey, id with uppercase and spaces: all accepted
	ok := []TrustedDevice{
		{ID: DeviceID(atkPub), Pubkey: B64URL(atkPub)},
		{ID: DeviceID(atkPub), Pubkey: B64URL(atkPub), Alg: "ed25519"},
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
	for _, alg := range []string{"rs256", "es256", "ES256"} {
		if err := CheckTrusted(TrustedDevice{ID: someID, Alg: alg}); err == nil {
			t.Errorf("CheckTrusted accepted alg %q", alg)
		}
		if _, err := NormalizeAlg(alg); err == nil {
			t.Errorf("NormalizeAlg accepted %q", alg)
		}
	}
	// a 65-byte (SEC1 P-256) key is not an Ed25519 key, whatever the entry says
	sec1 := append([]byte{4}, make([]byte, 64)...)
	if _, err := ParseDeviceKey("", B64URL(sec1)); err == nil {
		t.Error("65-byte key accepted as ed25519")
	}
	d = NewDevices([]TrustedDevice{{ID: SHA256Hex(sec1), Pubkey: B64URL(sec1), Alg: "es256"}})
	if _, r := d.Key(SHA256Hex(sec1)); r != "config_alg_invalid" {
		t.Errorf("es256 entry: %s, want config_alg_invalid", r)
	}
}
