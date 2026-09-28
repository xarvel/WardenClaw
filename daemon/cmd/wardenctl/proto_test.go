// SPDX-License-Identifier: AGPL-3.0-or-later

package main

// Compatibility with the app: the same vectors the app test reads, in a single copy
// in protocol/vectors/ at the monorepo root. Ed25519 signatures
// are deterministic, so we compare byte-for-byte what the wardenctl code builds.

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/xarvel/WardenClaw/daemon/envelope"
)

// fixtureDirs: the single copy of the protocol vectors (protocol/vectors at the monorepo root).
func fixtureDirs(t *testing.T) []string {
	return []string{filepath.Join("..", "..", "..", "protocol", "vectors")}
}

func loadJSON(t *testing.T, path string, v any) {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.UseNumber()
	if err := d.Decode(v); err != nil {
		t.Fatal(err)
	}
}

func seedKey(t *testing.T, hexSeed string) ed25519.PrivateKey {
	s, err := hex.DecodeString(hexSeed)
	if err != nil || len(s) != 32 {
		t.Fatal("seed")
	}
	return ed25519.NewKeyFromSeed(s)
}

func TestTransportVectorsCompat(t *testing.T) {
	for _, dir := range fixtureDirs(t) {
		var v struct {
			DeviceID, DevicePubkey, DeviceSeed, SupervisorID, SupervisorKey string
			Link                                                            struct{ Code, Host, Key, Text, URL string }
			Pair                                                            struct {
				Fingerprint   string
				Payload       envelope.PairPayload
				Signature     string
				SigningString string
			}
			Request struct {
				Action, Nonce, Signature, SigningString string
				Ts                                      int64
			}
			Response struct {
				Action, DeviceID, Body, Nonce, Signature, SigningString string
				Status                                                  int
			}
			DecideResponse struct {
				Action, DeviceID, Nonce, ID, Digest, Decision, Body, Signature, SigningString string
				Status                                                                        int
			}
			PingResponse struct {
				Nonce, Body, Signature, SigningString string
				Status                                int
			}
			UnauthResponse struct {
				Action, Body, Signature, SigningString string
				Status                                 int
			}
		}
		loadJSON(t, filepath.Join(dir, "transport_vectors.json"), &v)
		priv := seedKey(t, v.DeviceSeed)
		if deviceIDOf(priv) != v.DeviceID || envelope.B64URL(priv.Public().(ed25519.PublicKey)) != v.DevicePubkey {
			t.Fatalf("%s: deviceId/pubkey", dir)
		}
		// link
		l, err := envelope.ParsePairLink(v.Link.Text)
		if err != nil || l.Code != v.Link.Code || l.Key != v.Link.Key || l.URL != v.Link.URL || l.Host != v.Link.Host {
			t.Fatalf("%s: link %+v %v", dir, l, err)
		}
		pinned, _ := envelope.DecodeKey(l.Key)
		if envelope.DeviceID(pinned) != v.SupervisorID {
			t.Fatalf("%s: supervisorId from the link key", dir)
		}
		// signed request
		h := signedHeadersAt(priv, v.SupervisorID, v.Request.Action, v.Request.Nonce, v.Request.Ts)
		if h["X-Wardenclaw-Signature"] != v.Request.Signature || h["X-Wardenclaw-Device"] != v.DeviceID || h["X-Wardenclaw-Ts"] != "1790447985039" {
			t.Fatalf("%s: request headers %v", dir, h)
		}
		// pairing
		body, err := pairBody(priv, v.Pair.Payload)
		if err != nil {
			t.Fatal(err)
		}
		var pb map[string]any
		json.Unmarshal(body, &pb)
		if pb["signature"] != v.Pair.Signature || pb["code"] != v.Pair.Payload.Code || pb["pubkey"] != v.DevicePubkey {
			t.Fatalf("%s: pair body %s", dir, body)
		}
		if envelope.Fingerprint(v.DeviceID) != v.Pair.Fingerprint {
			t.Fatalf("%s: fingerprint", dir)
		}
		// supervisor response: accepted only with the pinned key and bound to its own request
		rb := []byte(v.Response.Body)
		want := expect{ctx: envelope.RespCtx{Action: v.Response.Action, DeviceID: v.Response.DeviceID, Nonce: v.Response.Nonce}}
		if v.Response.DeviceID != v.DeviceID {
			t.Fatalf("%s: response deviceId", dir)
		}
		if msg, _ := envelope.ResponseSigningString(want.ctx, v.Response.Status, rb); string(msg) != v.Response.SigningString {
			t.Fatalf("%s: response signing string\n%s\n%s", dir, msg, v.Response.SigningString)
		}
		if verifyResponse(pinned, want, v.Response.Status, rb, v.Response.Signature) != respBound {
			t.Fatalf("%s: valid response rejected", dir)
		}
		other, _, _ := ed25519.GenerateKey(nil)
		with := func(f func(*expect)) expect { w := want; f(&w); return w }
		for name, got := range map[string]respKind{
			"foreign nonce": verifyResponse(pinned, with(func(w *expect) { w.ctx.Nonce += "x" }), v.Response.Status, rb, v.Response.Signature),
			"other action":  verifyResponse(pinned, with(func(w *expect) { w.ctx.Action = "status" }), v.Response.Status, rb, v.Response.Signature),
			"other device":  verifyResponse(pinned, with(func(w *expect) { w.ctx.DeviceID = v.SupervisorID }), v.Response.Status, rb, v.Response.Signature),
			"other code":    verifyResponse(pinned, want, 500, rb, v.Response.Signature),
			"other body":    verifyResponse(pinned, want, v.Response.Status, append(rb, ' '), v.Response.Signature),
			"foreign key":   verifyResponse(other, want, v.Response.Status, rb, v.Response.Signature),
			"no signature":  verifyResponse(pinned, want, v.Response.Status, rb, ""),
			"as ping":       verifyResponse(pinned, expect{ping: true, ctx: envelope.RespCtx{Nonce: v.Response.Nonce}}, v.Response.Status, rb, v.Response.Signature),
		} {
			if got != respInvalid {
				t.Fatalf("%s: response accepted: %s (%d)", dir, name, got)
			}
		}
		// decide: signature with the ticket id and digest
		dr := v.DecideResponse
		dwant := expect{ctx: envelope.RespCtx{Action: "decide", DeviceID: v.DeviceID, Nonce: dr.Nonce, ID: dr.ID, Digest: dr.Digest}}
		if msg, _ := envelope.ResponseSigningString(dwant.ctx, dr.Status, []byte(dr.Body)); string(msg) != dr.SigningString {
			t.Fatalf("%s: decide signing string", dir)
		}
		if verifyResponse(pinned, dwant, dr.Status, []byte(dr.Body), dr.Signature) != respBound {
			t.Fatalf("%s: valid decide response rejected", dir)
		}
		for name, w := range map[string]expect{
			"other id":     with(func(w *expect) { *w = dwant; w.ctx.ID = "wd-" + strings.Repeat("0", 32) }),
			"other digest": with(func(w *expect) { *w = dwant; w.ctx.Digest = strings.Repeat("0", 64) }),
			"no ticket":    with(func(w *expect) { *w = dwant; w.ctx.ID, w.ctx.Digest = "", "" }),
		} {
			if verifyResponse(pinned, w, dr.Status, []byte(dr.Body), dr.Signature) != respInvalid {
				t.Fatalf("%s: decide response accepted: %s", dir, name)
			}
		}
		// ping: only with its own type
		pr := v.PingResponse
		if msg, _ := envelope.PingSigningString(pr.Nonce, pr.Status, []byte(pr.Body)); string(msg) != pr.SigningString {
			t.Fatalf("%s: ping signing string", dir)
		}
		if verifyResponse(pinned, expect{ping: true, ctx: envelope.RespCtx{Nonce: pr.Nonce}}, pr.Status, []byte(pr.Body), pr.Signature) != respBound {
			t.Fatalf("%s: valid ping rejected", dir)
		}
		// review scenario (finding 3): a middleman asks /v1/ping with the ticket nonce and returns
		// that response instead of the decide one: rejected, the decision does not count as made
		if pr.Nonce != dr.Nonce {
			t.Fatalf("%s: ping and decide vectors must share the nonce", dir)
		}
		if got := verifyResponse(pinned, dwant, pr.Status, []byte(pr.Body), pr.Signature); got != respInvalid {
			t.Fatalf("%s: ping accepted as a decide response (%d)", dir, got)
		}
		// pre-authentication rejection: signed but not bound to the request; not taken as success
		// or as ping
		ur := v.UnauthResponse
		if msg, _ := envelope.UnauthSigningString(ur.Action, ur.Status, []byte(ur.Body)); string(msg) != ur.SigningString {
			t.Fatalf("%s: unauth signing string", dir)
		}
		if got := verifyResponse(pinned, dwant, ur.Status, []byte(ur.Body), ur.Signature); got != respUnbound {
			t.Fatalf("%s: unauth for decide: %d", dir, got)
		}
		if got := verifyResponse(pinned, want, ur.Status, []byte(ur.Body), ur.Signature); got != respInvalid {
			t.Fatalf("%s: unauth for another action accepted: %d", dir, got)
		}
		if got := verifyResponse(pinned, expect{ping: true, ctx: envelope.RespCtx{Nonce: dr.Nonce}}, ur.Status, []byte(ur.Body), ur.Signature); got != respInvalid {
			t.Fatalf("%s: unauth accepted as ping: %d", dir, got)
		}
	}
}

func TestHWVectorsCompat(t *testing.T) {
	for _, dir := range fixtureDirs(t) {
		var v struct {
			Cases []struct {
				Name, Seed, DeviceID, SigningString, Signature, Challenge, ClientDataJSON, ClientDataHashHex string
				Payload                                                                                      envelope.DecisionPayload
			}
		}
		loadJSON(t, filepath.Join(dir, "hw_vectors.json"), &v)
		if len(v.Cases) == 0 {
			t.Fatal("no cases")
		}
		for _, c := range v.Cases {
			priv := seedKey(t, c.Seed)
			if c.Payload.Risk != nil || c.Payload.Type != envelope.TicketExec {
				// the CLI does not sign risk and signs only exec tickets; the string with risk
				// and the plugin tool ticket are checked via the shared SignPayload
				b := envelope.SignPayload(priv, c.Payload)
				if b.Signature != c.Signature {
					t.Fatalf("%s/%s: signature with risk", dir, c.Name)
				}
				continue
			}
			ts, _ := c.Payload.Ts.Int64()
			body, cdj, err := signTicket(priv, c.Payload.SupervisorID, c.Payload.ID, c.Payload.Digest, c.Payload.Decision, ts, c.Payload.Nonce)
			if err != nil {
				t.Fatal(err)
			}
			if body.DeviceID != c.DeviceID || body.Signature != c.Signature {
				t.Fatalf("%s/%s: ticket signature %s", dir, c.Name, body.Signature)
			}
			if string(cdj) != c.ClientDataJSON {
				t.Fatalf("%s/%s: clientDataJSON\n got %s\nwant %s", dir, c.Name, cdj, c.ClientDataJSON)
			}
			h := sha256.Sum256(cdj)
			if hex.EncodeToString(h[:]) != c.ClientDataHashHex || !strings.Contains(string(cdj), c.Challenge) {
				t.Fatalf("%s/%s: clientDataHash/challenge", dir, c.Name)
			}
			// the ticket body is parsed the same way as in wardend
			raw, _ := json.Marshal(body)
			if _, err := envelope.ParseDecision(raw); err != nil {
				t.Fatalf("%s/%s: ParseDecision: %v", dir, c.Name, err)
			}
		}
	}
}
