// SPDX-License-Identifier: AGPL-3.0-or-later

package main

// An es256 device (P-256, Secure Enclave: Apple Watch): pairing, tickets, refusal on
// hardware-required.

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/xarvel/WardenClaw/daemon/envelope"
	"github.com/xarvel/WardenClaw/daemon/hwkey/hwkeytest"
)

type watchDev struct {
	priv *ecdsa.PrivateKey
	key  envelope.DeviceKey
	id   string
}

func newWatch() watchDev {
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	k := envelope.ES256Key(&priv.PublicKey)
	return watchDev{priv: priv, key: k, id: k.ID()}
}

func (w watchDev) trusted() envelope.TrustedDevice {
	return envelope.TrustedDevice{ID: w.id, Pubkey: w.key.B64(), Alg: "es256", Name: "Apple Watch"}
}

// sign produces a signature as the Secure Enclave does (DER) or one already converted to raw r||s.
func (w watchDev) sign(msg []byte, der bool) string {
	if !der {
		return envelope.SignES256(w.priv, msg)
	}
	d, _ := envelope.SignES256DER(w.priv, msg)
	return envelope.B64URL(d)
}

func (w watchDev) ticket(it *pendingItem, decision string, der bool) envelope.DecisionBody {
	p := envelope.ExecPayload(supOf(it), it.ID, it.Digest, decision, envelope.NowMs(), envelope.NewNonce())
	msg, _ := envelope.SigningString(w.id, p)
	return envelope.DecisionBody{DeviceID: w.id, Payload: p, Signature: w.sign(msg, der)}
}

// ---------- pairing ----------

func TestWatchPairingES256(t *testing.T) {
	e := newRPCEnv(t)
	w := newWatch()
	encKey, _ := ecdh.X25519().GenerateKey(rand.Reader)
	enc := envelope.B64URL(encKey.PublicKey().Bytes())
	code, _ := e.s.pair.start(e.s.cfg.PairCodeTTL.Duration)
	// bodyAlg: alg in the request; signAlg: which alg went into the signed string; pub: which key is claimed
	submit := func(bodyAlg, signAlg, pub string) (*pairReq, string) {
		pp := envelope.PairPayload{Code: code, DeviceID: w.id, Pubkey: pub, Alg: signAlg, Enc: enc, Name: "Apple Watch", SupervisorID: e.s.supervisorID, Ts: envelope.NowMs(), Nonce: envelope.NewNonce()}
		msg, _ := envelope.PairSigningString(pp)
		pp.Alg = bodyAlg
		return e.s.pair.submit(pp, w.sign(msg, true), e.s.supervisorID, "relay", e.s.cfg.TsWindow.Duration, e.s.trustedDevice)
	}
	_, edPriv, _ := ed25519.GenerateKey(rand.Reader)
	edPub := envelope.B64URL(edPriv.Public().(ed25519.PublicKey))
	for _, c := range []struct {
		name                  string
		bodyAlg, signAlg, pub string
		want                  string
	}{
		{"no alg", "", "", w.key.B64(), "pubkey_invalid"},                                   // ed25519 by default, 65 bytes are not an Ed25519 key
		{"alg not signed", "es256", "", w.key.B64(), "bad_signature"},                       // tampering: alg appended after signing
		{"alg ed25519 with P-256 key", "ed25519", "ed25519", w.key.B64(), "pubkey_invalid"}, //
		{"upper-case alg", "ES256", "ES256", w.key.B64(), "alg_unsupported"},
		{"unknown alg", "rs256", "rs256", w.key.B64(), "alg_unsupported"},
		{"es256 with ed25519 key", "es256", "es256", edPub, "pubkey_invalid"},
	} {
		if _, reason := submit(c.bodyAlg, c.signAlg, c.pub); reason != c.want {
			t.Errorf("%s: %q", c.name, reason)
		}
	}
	req, reason := submit("es256", "es256", w.key.B64())
	if reason != "" || req.Status != "pending" || req.Fingerprint != envelope.Fingerprint(w.id) {
		t.Fatalf("pair: %q %+v", reason, req)
	}
	if l := e.s.pairList(); !strings.Contains(mustJSON(l), `"alg":"es256"`) {
		t.Fatalf("pair list lacks alg: %s", mustJSON(l))
	}
	if _, err := e.s.pairApprove(req.ID); err != nil {
		t.Fatal(err)
	}
	cfg, _ := os.ReadFile(e.s.cfg.path)
	if !strings.Contains(string(cfg), `"alg": "es256"`) || !strings.Contains(string(cfg), w.key.B64()) {
		t.Fatalf("config: %s", cfg)
	}
	if st := mustJSON(e.s.status()); !strings.Contains(st, `"alg":"es256"`) {
		t.Fatalf("status: %s", st)
	}
	// restart: the device from the config is es256 again
	c2, err := loadConfig(e.s.cfg.path)
	if err != nil {
		t.Fatal(err)
	}
	d2 := envelope.NewDevices(c2.TrustedDevices, "")
	if k, why := d2.Key(w.id); why != "" || k.Alg != "es256" {
		t.Fatalf("reload: %s %v", why, k.Alg)
	}
}

func mustJSON(v any) string { b, _ := json.Marshal(v); return string(b) }

// ---------- tickets ----------

func TestWatchTicketES256(t *testing.T) {
	phone, w := newDevice(), newWatch()
	s := newHWSupervisor(t, `{}`, phone)
	s.devices.Add(w.trusted())

	ch, it := startExec(t, s, 100, "cat", "/etc/hostname")
	if it == nil {
		t.Fatal("cat must wait for a ticket")
	}
	// an Ed25519 signature with the watch's deviceId; a corrupted DER signature
	_, ed, _ := ed25519.GenerateKey(rand.Reader)
	b := w.ticket(it, "allow", false)
	msg, _ := envelope.SigningString(w.id, b.Payload)
	b.Signature = envelope.B64URL(ed25519.Sign(ed, msg))
	if r := decideRaw(s, b); r["reason"] != "bad_signature" {
		t.Fatalf("ed25519 for es256: %v", r)
	}
	b = w.ticket(it, "allow", true)
	der, _ := envelope.DecodeB64URL(b.Signature)
	der[len(der)-1] ^= 1
	b.Signature = envelope.B64URL(der)
	if r := decideRaw(s, b); r["reason"] != "bad_signature" {
		t.Fatalf("tampered DER: %v", r)
	}
	// DER as from the Secure Enclave passes
	if r := decideRaw(s, w.ticket(it, "allow", true)); r["ok"] != true {
		t.Fatalf("allow DER: %v", r)
	}
	if o := wait(t, ch); !o.allow || !strings.Contains(o.rec.Reason, w.id[:12]) {
		t.Fatalf("outcome: %+v", o)
	}
	// raw r||s, deny (like "Deny" from the notification)
	ch2, it2 := startExec(t, s, 300, "cat", "/etc/passwd")
	if r := decideRaw(s, w.ticket(it2, "deny", false)); r["ok"] != true {
		t.Fatalf("deny raw: %v", r)
	}
	if o := wait(t, ch2); o.allow {
		t.Fatal("denied exec allowed")
	}
}

// A card with meta.hardware.required: an approval from the watch (without a YubiKey) is not
// accepted, a denial is.
func TestWatchCannotApproveHardwareRequired(t *testing.T) {
	a := hwkeytest.NewEd25519("wardenclaw")
	phone, w := newDevice(), newWatch()
	s := newHWSupervisor(t, hwPolicy, phone, a.Key())
	s.devices.Add(w.trusted())
	ch, it := startExec(t, s, 100, "rm", "-rf", "/tmp/x")
	if hm, _ := it.Meta["hardware"].(map[string]any); hm == nil || hm["required"] != true {
		t.Fatalf("meta.hardware: %#v", it.Meta)
	}
	for _, der := range []bool{true, false} {
		if r := decideRaw(s, w.ticket(it, "allow", der)); r["ok"] == true || r["reason"] != "hardware_required" || r["hardwareRule"] != "hw-rm" {
			t.Fatalf("watch allow on hardware-required: %v", r)
		}
	}
	// watch with a foreign (not its own) assertion: the challenge is bound to deviceId, cannot be swapped
	pb := ticket(phone, it, "allow", -1)
	wb := w.ticket(it, "allow", true)
	ch1, _ := envelope.HWChallenge(pb.DeviceID, pb.Payload)
	wb.HW = a.Assert(ch1)
	if r := decideRaw(s, wb); r["reason"] != "hw_challenge_mismatch" {
		t.Fatalf("phone assertion on watch ticket: %v", r)
	}
	if s.q.get(it.ID) == nil {
		t.Fatal("card must stay pending after rejected watch approvals")
	}
	if r := decideRaw(s, w.ticket(it, "deny", true)); r["ok"] != true {
		t.Fatalf("watch deny: %v", r)
	}
	if o := wait(t, ch); o.allow {
		t.Fatal("exec allowed")
	}
}
