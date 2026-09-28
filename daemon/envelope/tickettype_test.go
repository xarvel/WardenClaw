// SPDX-License-Identifier: AGPL-3.0-or-later

package envelope

// Ticket type in the signing string (crypto-review 2026-09-28, finding 1): plugin tool-call
// decisions and wardend exec decisions use different signing strings; exec tickets are bound
// to a supervisor.

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// testSupervisorID is the supervisorId of "this" wardend in package tests (matches protocol/vectors).
const testSupervisorID = "39f713d0a644253f04529421b9f51b9b08979d08295959c4f3990ee617f5139f"

type ticketFixture struct {
	priv   ed25519.PrivateKey
	did    string
	sup    string
	digest string
	id     string
	devs   *Devices
	nonces *NonceCache
}

func newTicketFixture(t *testing.T) *ticketFixture {
	t.Helper()
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	did := DeviceID(pub)
	digest := SHA256Hex([]byte("real wardend envelope of a dangerous exec"))
	return &ticketFixture{priv: priv, did: did, sup: testSupervisorID, digest: digest, id: PendingID(digest),
		devs: NewDevices([]TrustedDevice{{ID: did, Pubkey: B64URL(pub)}}, ""), nonces: NewNonceCache(time.Minute)}
}

func (f *ticketFixture) ctx() VerifyCtx {
	return VerifyCtx{Now: time.Now(), TsWindow: time.Minute, SupervisorID: f.sup, Devices: f.devs, Nonces: f.nonces,
		Pending: func(id string) string {
			if id == f.id {
				return f.digest
			}
			return ""
		}}
}

func (f *ticketFixture) payload(typ, sup string) DecisionPayload {
	return DecisionPayload{Type: typ, SupervisorID: sup, ID: f.id, Digest: f.digest, Decision: "allow", Ts: json.Number(fmt.Sprint(time.Now().UnixMilli())), Nonce: NewNonce()}
}

// via JSON, as over the socket and the relay
func roundTrip(t *testing.T, b DecisionBody) (*DecisionBody, error) {
	t.Helper()
	raw, err := json.Marshal(b)
	if err != nil {
		t.Fatal(err)
	}
	return ParseDecision(raw)
}

// Regression for review PoC TestReviewToolTicketIsExecTicket: phone signed a tool-call
// card {id:"wd-...", digest of a wardend entry}. Previously a valid wardend ticket; now rejected.
func TestToolTicketIsNotExecTicket(t *testing.T) {
	f := newTicketFixture(t)

	// plugin tool-call ticket: type tool, no supervisorId
	tool := SignPayload(f.priv, f.payload(TicketTool, ""))
	pb, err := roundTrip(t, tool)
	if err != nil {
		t.Fatalf("tool ticket must parse (the plugin accepts it): %v", err)
	}
	if r := Verify(pb, f.ctx()); r != "ticket_type_mismatch" {
		t.Fatalf("tool ticket for a wardend record: %q, want ticket_type_mismatch", r)
	}

	// PoC-format signature (without type at all) fails parsing; Verify never sees it
	old := DecisionPayload{ID: f.id, Digest: f.digest, Decision: "allow", Ts: json.Number(fmt.Sprint(time.Now().UnixMilli())), Nonce: NewNonce()}
	msg, _ := Canonical(map[string]any{"deviceId": f.did, "id": old.ID, "digest": old.Digest, "decision": old.Decision, "ts": old.Ts, "nonce": old.Nonce})
	legacy := DecisionBody{DeviceID: f.did, Payload: old, Signature: B64URL(ed25519.Sign(f.priv, msg))}
	if _, err := roundTrip(t, legacy); err == nil || err.Error() != "type_invalid" {
		t.Fatalf("untyped ticket: %v, want type_invalid", err)
	}
	if r := Verify(&legacy, f.ctx()); r != "ticket_type_mismatch" {
		t.Fatalf("untyped ticket past the parser: %q", r)
	}

	// relabeling is not possible: type and supervisorId are covered by the signature
	relabeled := tool
	relabeled.Payload.Type, relabeled.Payload.SupervisorID = TicketExec, f.sup
	if r := Verify(&relabeled, f.ctx()); r != "bad_signature" {
		t.Fatalf("tool ticket relabeled as exec: %q, want bad_signature", r)
	}

	// type rejections do not claim the nonce: a real exec ticket with the same nonce is accepted
	p := f.payload(TicketExec, f.sup)
	p.Nonce = tool.Payload.Nonce
	good := SignPayload(f.priv, p)
	if pb, err := roundTrip(t, good); err != nil {
		t.Fatal(err)
	} else if r := Verify(pb, f.ctx()); r != "" {
		t.Fatalf("exec ticket rejected: %s", r)
	}
}

func TestExecTicketBoundToSupervisor(t *testing.T) {
	f := newTicketFixture(t)
	other := SHA256Hex([]byte("another wardend"))
	b := SignPayload(f.priv, f.payload(TicketExec, other))
	if r := Verify(&b, f.ctx()); r != "supervisor_mismatch" {
		t.Fatalf("exec ticket for another supervisor: %q, want supervisor_mismatch", r)
	}
	// supervisorId cannot be swapped to ours: it is covered by the signature
	b.Payload.SupervisorID = f.sup
	if r := Verify(&b, f.ctx()); r != "bad_signature" {
		t.Fatalf("supervisorId swapped after signing: %q, want bad_signature", r)
	}
	// a verifier without a supervisorId accepts nothing
	c := f.ctx()
	c.SupervisorID = ""
	g := SignPayload(f.priv, f.payload(TicketExec, f.sup))
	if r := Verify(&g, c); r != "supervisor_mismatch" {
		t.Fatalf("verifier without a supervisorId: %q", r)
	}
}

func TestTicketParseTypeAndSupervisor(t *testing.T) {
	f := newTicketFixture(t)
	for _, c := range []struct {
		name, typ, sup, want string
	}{
		{"exec", TicketExec, f.sup, ""},
		{"tool", TicketTool, "", ""},
		{"no-type", "", "", "type_invalid"},
		{"unknown-type", "wardenclaw.ticket.v1", f.sup, "type_invalid"},
		{"hw-domain-as-type", HWType, f.sup, "type_invalid"},
		{"exec-without-supervisor", TicketExec, "", "supervisor_id_invalid"},
		{"exec-bad-supervisor", TicketExec, "ABC", "supervisor_id_invalid"},
		{"tool-with-supervisor", TicketTool, f.sup, "supervisor_id_invalid"},
	} {
		_, err := roundTrip(t, SignPayload(f.priv, f.payload(c.typ, c.sup)))
		got := ""
		if err != nil {
			got = err.Error()
		}
		if got != c.want {
			t.Errorf("%s: %q, want %q", c.name, got, c.want)
		}
	}
}

// SigningString produces exactly the canonical JSON of the decision-signing-string* fixtures
// (generated by the plugin's JS).
func TestTicketSigningStringVectors(t *testing.T) {
	vf := loadVectors(t, filepath.FromSlash(vectorsDir+"/canonical_vectors.json"))
	n := 0
	for _, c := range vf.Cases {
		if !strings.HasPrefix(c.Name, "decision-signing-string") {
			continue
		}
		var v struct {
			DeviceID string `json:"deviceId"`
			DecisionPayload
		}
		if err := json.Unmarshal(c.Value, &v); err != nil {
			t.Fatalf("%s: %v", c.Name, err)
		}
		got, err := SigningString(v.DeviceID, v.DecisionPayload)
		if err != nil || string(got) != c.Canonical {
			t.Errorf("%s:\n got  %s\n want %s (%v)", c.Name, got, c.Canonical, err)
		}
		n++
	}
	if n != 2 {
		t.Fatalf("decision-signing-string vectors: %d, want 2 (exec and tool)", n)
	}
}

// Signing strings and second-factor challenges differ by type and by supervisor.
func TestTicketDomainsSeparated(t *testing.T) {
	f := newTicketFixture(t)
	exec := f.payload(TicketExec, f.sup)
	tool := exec
	tool.Type, tool.SupervisorID = TicketTool, ""
	other := exec
	other.SupervisorID = SHA256Hex([]byte("another wardend"))
	var sigs, chs [][]byte
	for _, p := range []DecisionPayload{exec, tool, other} {
		s, err := SigningString(f.did, p)
		if err != nil {
			t.Fatal(err)
		}
		ch, err := HWChallenge(f.did, p)
		if err != nil {
			t.Fatal(err)
		}
		sigs, chs = append(sigs, s), append(chs, ch)
	}
	for i := range sigs {
		for j := i + 1; j < len(sigs); j++ {
			if bytes.Equal(sigs[i], sigs[j]) || bytes.Equal(chs[i], chs[j]) {
				t.Fatalf("payloads %d and %d share a signing string or a challenge", i, j)
			}
		}
	}
	if !bytes.Contains(sigs[0], []byte(`"type":"`+TicketExec+`"`)) || !bytes.Contains(sigs[0], []byte(`"supervisorId":"`+f.sup+`"`)) {
		t.Fatalf("exec signing string: %s", sigs[0])
	}
	if bytes.Contains(sigs[1], []byte("supervisorId")) {
		t.Fatalf("tool signing string carries a supervisorId: %s", sigs[1])
	}
}
