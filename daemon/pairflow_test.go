// SPDX-License-Identifier: AGPL-3.0-or-later

package main

// The pairing rules on their own (pairing.submit) and the owner's side of it over the socket
// (pair.list, approve, reject, revoke). The same request carried by the relay: relaydev_test.go.

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/xarvel/WardenClaw/daemon/envelope"
)

// pairSubmit signs a pairing request of d as the app does and submits it; name is what gets
// signed, sent replaces it afterwards when not empty (tampering).
func pairSubmit(e *rpcEnv, d device, code, supID, name, sent string) (*pairReq, string) {
	enc, _ := ecdh.X25519().GenerateKey(rand.Reader)
	pp := envelope.PairPayload{Code: code, DeviceID: d.id, Pubkey: envelope.B64URL(d.priv.Public().(ed25519.PublicKey)),
		Enc: envelope.B64URL(enc.PublicKey().Bytes()), Name: name, SupervisorID: supID, Ts: envelope.NowMs(), Nonce: envelope.NewNonce()}
	msg, _ := envelope.PairSigningString(pp)
	if sent != "" {
		pp.Name = sent
	}
	return e.s.pair.submit(pp, envelope.B64URL(ed25519.Sign(d.priv, msg)), e.s.supervisorID, "relay", e.s.cfg.TsWindow.Duration, e.s.trustedDevice)
}

func TestPairingFlow(t *testing.T) {
	e := newRPCEnv(t)
	phone := newDevice()
	sup := e.s.supervisorID

	// without an active code: rejection
	if _, reason := pairSubmit(e, phone, "ABCD2345", sup, "Pixel", ""); reason != "pairing_not_active" {
		t.Fatalf("no code: %q", reason)
	}
	code, _ := e.s.pair.start(e.s.cfg.PairCodeTTL.Duration)
	// foreign supervisor, a signature over another name, wrong code
	if _, reason := pairSubmit(e, phone, code, strings.Repeat("0", 64), "Pixel", ""); reason != "wrong_supervisor" {
		t.Fatalf("wrong supervisor: %q", reason)
	}
	if _, reason := pairSubmit(e, phone, code, sup, "Pixel", "Evil"); reason != "bad_signature" {
		t.Fatalf("tampered: %q", reason)
	}
	if _, reason := pairSubmit(e, phone, "ZZZZ2222", sup, "x", ""); reason != "bad_code" {
		t.Fatalf("bad code: %q", reason)
	}

	// the real request
	req, reason := pairSubmit(e, phone, code, sup, "Pixel", "")
	if reason != "" || req.Status != "pending" || req.Fingerprint != envelope.Fingerprint(phone.id) {
		t.Fatalf("pair: %q %+v", reason, req)
	}
	// the code is one-time
	if _, reason := pairSubmit(e, newDevice(), code, sup, "x", ""); reason != "pairing_not_active" {
		t.Fatalf("code reuse: %q", reason)
	}
	if e.s.trustedDevice(phone.id) {
		t.Fatal("trusted before approval")
	}

	var list pairListResult
	if err := rpcDo(t, e.sock, "pair.list", map[string]any{}, &list); err != nil || len(list.Requests) != 1 || list.Requests[0].Fingerprint != envelope.Fingerprint(phone.id) {
		t.Fatalf("list: %v %+v", err, list)
	}
	if err := rpcDo(t, e.sock, "pair.approve", map[string]any{"id": req.ID}, nil); err != nil {
		t.Fatal(err)
	}
	if err := rpcDo(t, e.sock, "pair.approve", map[string]any{"id": req.ID}, nil); err == nil {
		t.Fatal("second approve must fail")
	}
	cfg, err := loadConfig(e.s.cfg.path)
	if err != nil || len(cfg.TrustedDevices) != 1 || cfg.TrustedDevices[0].ID != phone.id || cfg.TrustedDevices[0].Pubkey != envelope.B64URL(phone.priv.Public().(ed25519.PublicKey)) ||
		cfg.TrustedDevices[0].Name != "Pixel" || cfg.TrustedDevices[0].Enc == "" {
		t.Fatalf("config after approve: %v %+v", err, cfg)
	}
	if !e.s.trustedDevice(phone.id) {
		t.Fatal("not trusted after approval")
	}

	// revoke: from the config and from memory
	if err := rpcDo(t, e.sock, "pair.revoke", map[string]any{"device": phone.id[:10]}, nil); err != nil {
		t.Fatal(err)
	}
	cfg, _ = loadConfig(e.s.cfg.path)
	if len(cfg.TrustedDevices) != 0 || e.s.trustedDevice(phone.id) {
		t.Fatalf("after revoke: %+v", cfg.TrustedDevices)
	}
}

func TestPairingBruteForceKillsCodes(t *testing.T) {
	e := newRPCEnv(t)
	code, _ := e.s.pair.start(e.s.cfg.PairCodeTTL.Duration)
	d := newDevice()
	for i := 0; i < maxPairFails; i++ {
		pairSubmit(e, d, fmt.Sprintf("WRONG%03d", i), e.s.supervisorID, "x", "")
	}
	if _, reason := pairSubmit(e, d, code, e.s.supervisorID, "x", ""); reason != "pairing_not_active" {
		t.Fatalf("code must be dead after %d failures: %q", maxPairFails, reason)
	}
}

func TestPairingKeepsOtherConfigAndReject(t *testing.T) {
	e := newRPCEnv(t)
	os.WriteFile(e.s.cfg.path, []byte(`{"mode":"ticket","trusted_devices":[{"id":"<placeholder>","name":"old"}],"hardware_keys":[]}`), 0o600)
	for _, want := range []string{"reject", "approve"} {
		code, _ := e.s.pair.start(e.s.cfg.PairCodeTTL.Duration)
		req, reason := pairSubmit(e, newDevice(), code, e.s.supervisorID, "x", "")
		if reason != "" {
			t.Fatalf("pair: %q", reason)
		}
		if err := rpcDo(t, e.sock, "pair."+want, map[string]any{"id": req.ID}, nil); err != nil {
			t.Fatal(err)
		}
	}
	b, _ := os.ReadFile(e.s.cfg.path)
	var top map[string]any
	json.Unmarshal(b, &top)
	td, _ := top["trusted_devices"].([]any)
	if top["mode"] != "ticket" || len(td) != 2 || top["hardware_keys"] == nil {
		t.Fatalf("config: %s", b)
	}
	if st, _ := os.Stat(e.s.cfg.path); st.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v", st.Mode())
	}
}
