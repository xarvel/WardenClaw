// SPDX-License-Identifier: AGPL-3.0-or-later

package main

// Own transport and pairing without seccomp: an in-process supervisor (newHWSupervisor),
// HTTP via httptest, RPC pair.* over a real unix socket.

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"

	"github.com/xarvel/WardenClaw/daemon/envelope"
)

type httpEnv struct {
	s    *supervisor
	srv  *httptest.Server
	sock string
}

func newHTTPEnv(t *testing.T, trusted ...device) *httpEnv {
	t.Helper()
	d := newDevice()
	if len(trusted) > 0 {
		d = trusted[0]
	}
	s := newHWSupervisor(t, `{}`, d)
	if len(trusted) == 0 {
		s.devices.Remove(d.id)
	}
	s.pair = newPairing()
	s.supervisorID = envelope.DeviceID(s.key.Public().(ed25519.PublicKey))
	h := newHTTPAPI(s)
	srv := httptest.NewServer(h.handler())
	t.Cleanup(srv.Close)
	s.http = h
	s.cfg.PublicURL = srv.URL
	sock := filepath.Join(s.cfg.StateDir, "w.sock")
	r, err := startRPC(sock, s)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(r.close)
	return &httpEnv{s: s, srv: srv, sock: sock}
}

type resp struct {
	status   int
	body     map[string]any
	raw      []byte
	sigOK    bool // signed and bound to this request (for ping, to its nonce), as the app checks
	unauthOK bool // signed rejection before authentication for the same action (not bound to the request)
}

var pathAction = map[string]string{"/v1/ping": "ping", "/v1/pending": "pending", "/v1/status": "status", "/v1/decide": "decide",
	"/v1/pair": "pair", "/v1/pair/status": "pair.status", "/v1/push/register": "push.register", "/v1/push/unregister": "push.unregister"}

// respCtxFor: what the client expects the response to be bound to: action by path, deviceId from
// the header (for decide and pair from the body), for decide the ticket id and digest; nonce is the
// request nonce.
func respCtxFor(path string, hdr map[string]string, body []byte, nonce string) envelope.RespCtx {
	if i := strings.IndexByte(path, '?'); i >= 0 {
		path = path[:i]
	}
	c := envelope.RespCtx{Action: pathAction[path], Nonce: nonce}
	for k, v := range hdr {
		if strings.EqualFold(k, "X-Wardenclaw-Device") {
			c.DeviceID = v
		}
	}
	var b struct {
		DeviceID string `json:"deviceId"`
		Payload  struct {
			ID     string `json:"id"`
			Digest string `json:"digest"`
		} `json:"payload"`
	}
	json.Unmarshal(body, &b)
	switch c.Action {
	case "decide":
		c.DeviceID, c.ID, c.Digest = b.DeviceID, b.Payload.ID, b.Payload.Digest
	case "pair":
		c.DeviceID = b.DeviceID
	}
	return c
}

// respSigOK: the response signature for request c (ping with its own type) and the signature of
// an unauth rejection.
func respSigOK(pub ed25519.PublicKey, c envelope.RespCtx, status int, raw []byte, sig string) (bool, bool) {
	var msg []byte
	if c.Action == "ping" {
		msg, _ = envelope.PingSigningString(c.Nonce, status, raw)
	} else {
		msg, _ = envelope.ResponseSigningString(c, status, raw)
	}
	um, _ := envelope.UnauthSigningString(c.Action, status, raw)
	return envelope.VerifySig(pub, msg, sig), envelope.VerifySig(pub, um, sig)
}

// do: a request; nonce is what to verify the response signature with (as the app does).
func (e *httpEnv) do(t *testing.T, method, path string, hdr map[string]string, body []byte, nonce string) resp {
	t.Helper()
	req, _ := http.NewRequest(method, e.srv.URL+path, bytes.NewReader(body))
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	raw, _ := io.ReadAll(res.Body)
	var m map[string]any
	json.Unmarshal(raw, &m)
	pub := e.s.key.Public().(ed25519.PublicKey)
	ok, unauthOK := respSigOK(pub, respCtxFor(path, hdr, body, nonce), res.StatusCode, raw, res.Header.Get("X-Wardend-Signature"))
	return resp{res.StatusCode, m, raw, ok, unauthOK}
}

// TestHTTPPingIsNotDecideResponse: crypto review, finding 3: a middleman sees the ticket nonce,
// does not forward decide, but asks the real wardend for /v1/ping with the same nonce and hands this
// signed response to the phone. Previously the response string was {type, nonce, status,
// bodySha256}, and the phone accepted ping as "decision accepted". Now ping is signed with its own
// type, and the decide response is bound to action, deviceId, nonce, ticket id and digest: a ping,
// a response to another ticket and a rejection of a garbage ticket with the same nonce do not pass
// for a response to this ticket, the record waits for the real decision.
func TestHTTPPingIsNotDecideResponse(t *testing.T) {
	d := newDevice()
	e := newHTTPEnv(t, d)
	pub := e.s.key.Public().(ed25519.PublicKey)
	ch, it := startExec(t, e.s, 100, "ls", "-la")
	if it == nil {
		t.Fatal("ls must wait for a ticket")
	}
	tk := ticket(d, it, "deny", -1)
	raw, _ := json.Marshal(tk)
	want := respCtxFor("/v1/decide", nil, raw, tk.Payload.Nonce)
	if want.Action != "decide" || want.ID != it.ID || want.Digest != it.Digest || want.DeviceID != d.id {
		t.Fatalf("ctx %+v", want)
	}
	// 1. ping with the ticket nonce
	req, _ := http.NewRequest("GET", e.srv.URL+"/v1/ping?nonce="+tk.Payload.Nonce, nil)
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	pingRaw, _ := io.ReadAll(res.Body)
	res.Body.Close()
	pingSig := res.Header.Get("X-Wardend-Signature")
	if ok, _ := respSigOK(pub, envelope.RespCtx{Action: "ping", Nonce: tk.Payload.Nonce}, res.StatusCode, pingRaw, pingSig); !ok {
		t.Fatalf("ping itself must verify: %s", pingRaw)
	}
	if ok, unauthOK := respSigOK(pub, want, res.StatusCode, pingRaw, pingSig); ok || unauthOK {
		t.Fatalf("ping response accepted as the decide response (bound %v, unauth %v)", ok, unauthOK)
	}
	// 2. a garbage ticket with the same nonce, id and digest: a signed rejection, but not a
	// response to this ticket
	junk := tk
	junk.Signature = envelope.B64URL(make([]byte, 64))
	jraw, _ := json.Marshal(junk)
	jr := e.do(t, "POST", "/v1/decide", nil, jraw, tk.Payload.Nonce)
	if jr.body["ok"] != false || jr.body["reason"] != "bad_signature" || jr.sigOK || !jr.unauthOK {
		t.Fatalf("junk ticket: %s (bound %v, unauth %v)", jr.raw, jr.sigOK, jr.unauthOK)
	}
	// 3. a response to another ticket of the same device does not pass for a response to this one
	ch2, it2 := startExec(t, e.s, 101, "id")
	if it2 == nil {
		t.Fatal("id must wait for a ticket")
	}
	tk2 := ticket(d, it2, "deny", -1)
	raw2, _ := json.Marshal(tk2)
	req2, _ := http.NewRequest("POST", e.srv.URL+"/v1/decide", bytes.NewReader(raw2))
	res2, err := http.DefaultClient.Do(req2)
	if err != nil {
		t.Fatal(err)
	}
	other, _ := io.ReadAll(res2.Body)
	res2.Body.Close()
	if ok, unauthOK := respSigOK(pub, want, res2.StatusCode, other, res2.Header.Get("X-Wardend-Signature")); ok || unauthOK {
		t.Fatalf("response to another ticket accepted (bound %v, unauth %v)", ok, unauthOK)
	}
	if o := wait(t, ch2); o.allow {
		t.Fatal("second exec must be denied")
	}
	// the record is still waiting: neither the ping nor the garbage decided it
	if e.s.q.digestOf(it.ID) != it.Digest {
		t.Fatal("the first exec must still be pending")
	}
	// the real response to this ticket passes and refers to it
	dr := e.do(t, "POST", "/v1/decide", nil, raw, tk.Payload.Nonce)
	if !dr.sigOK || dr.body["ok"] != true || dr.body["id"] != it.ID || dr.body["decision"] != "deny" {
		t.Fatalf("real decide: %s (bound %v)", dr.raw, dr.sigOK)
	}
	if o := wait(t, ch); o.allow {
		t.Fatal("exec must be denied")
	}
}

// pluginHeaders: headers in the wardenclaw-gate plugin request format (a string without type and
// supervisorId).
func pluginHeaders(priv ed25519.PrivateKey, action string, ts int64, nonce string) map[string]string {
	id := envelope.DeviceID(priv.Public().(ed25519.PublicKey))
	msg, _ := envelope.Canonical(map[string]any{"action": action, "deviceId": id, "ts": ts, "nonce": nonce})
	return map[string]string{"X-Wardenclaw-Device": id, "X-Wardenclaw-Ts": strconv.FormatInt(ts, 10), "X-Wardenclaw-Nonce": nonce,
		"X-Wardenclaw-Signature": envelope.B64URL(ed25519.Sign(priv, msg))}
}

func signedHeaders(priv ed25519.PrivateKey, sup, action string, ts int64, nonce string) map[string]string {
	id := envelope.DeviceID(priv.Public().(ed25519.PublicKey))
	msg, _ := envelope.RequestSigningString(sup, action, id, ts, nonce)
	return map[string]string{"X-Wardenclaw-Device": id, "X-Wardenclaw-Ts": strconv.FormatInt(ts, 10), "X-Wardenclaw-Nonce": nonce,
		"X-Wardenclaw-Signature": envelope.B64URL(ed25519.Sign(priv, msg))}
}

func TestHTTPPendingDecideSigned(t *testing.T) {
	d := newDevice()
	e := newHTTPEnv(t, d)
	stranger := newDevice()

	r := e.do(t, "GET", "/v1/ping?nonce=abc12345", nil, nil, "abc12345")
	if r.status != 200 || !r.sigOK || r.body["supervisorId"] != e.s.supervisorID {
		t.Fatalf("ping: %d %v %s", r.status, r.sigOK, r.raw)
	}
	// a response signed for another nonce does not pass on the client
	if r2 := e.do(t, "GET", "/v1/ping?nonce=abc12345", nil, nil, "other-nonce"); r2.sigOK {
		t.Fatal("response signature must be bound to request nonce")
	}

	now := envelope.NowMs()
	for _, c := range []struct {
		name string
		hdr  map[string]string
		want string
	}{
		{"no headers", nil, "device_id_invalid"},
		{"stranger", signedHeaders(stranger.priv, e.s.supervisorID, "pending", now, "n-stranger-1"), "untrusted_device"},
		{"wrong action", signedHeaders(d.priv, e.s.supervisorID, "status", now, "n-action-1"), "bad_signature"},
		{"stale", signedHeaders(d.priv, e.s.supervisorID, "pending", now-5*60_000, "n-stale-1"), "stale_timestamp"},
		// finding 8: a request signed for another wardend or in the wardenclaw-gate plugin format
		// ({action, deviceId, ts, nonce} without type) does not pass here
		{"other wardend", signedHeaders(d.priv, strings.Repeat("0", 64), "pending", now, "n-othersup-1"), "bad_signature"},
		{"plugin format", pluginHeaders(d.priv, "pending", now, "n-plugin-1"), "bad_signature"},
	} {
		r := e.do(t, "GET", "/v1/pending", c.hdr, nil, c.hdr["X-Wardenclaw-Nonce"])
		// a rejection before authentication is signed with the unauth type: the caller's nonce and
		// deviceId are not in it
		if r.status != 401 || r.body["reason"] != c.want || !r.unauthOK || r.sigOK {
			t.Errorf("%s: %d %s (sig %v, unauth %v)", c.name, r.status, r.raw, r.sigOK, r.unauthOK)
		}
	}
	h := signedHeaders(d.priv, e.s.supervisorID, "pending", now, "n-ok-000001")
	if r := e.do(t, "GET", "/v1/pending", h, nil, "n-ok-000001"); r.status != 200 || !r.sigOK || r.body["seq"] == nil {
		t.Fatalf("pending: %d %s", r.status, r.raw)
	}
	if r := e.do(t, "GET", "/v1/pending", h, nil, "n-ok-000001"); r.status != 401 || r.body["reason"] != "nonce_reused" || r.sigOK || !r.unauthOK {
		t.Fatalf("replay: %d %s", r.status, r.raw)
	}

	// long-poll wakes up on a new card; decide over HTTP releases the exec
	seq := int64(e.s.q.seq)
	got := make(chan resp, 1)
	go func() {
		h := signedHeaders(d.priv, e.s.supervisorID, "pending", envelope.NowMs(), "n-poll-000001")
		got <- e.do(t, "GET", fmt.Sprintf("/v1/pending?since=%d&wait=5000", seq), h, nil, "n-poll-000001")
	}()
	time.Sleep(100 * time.Millisecond)
	ch, it := startExec(t, e.s, 100, "ls", "-la")
	if it == nil {
		t.Fatal("ls must wait for a ticket")
	}
	pr := <-got
	items, _ := pr.body["pending"].([]any)
	if pr.status != 200 || len(items) != 1 || items[0].(map[string]any)["id"] != it.ID {
		t.Fatalf("long-poll: %d %s", pr.status, pr.raw)
	}
	tk := ticket(d, it, "allow", -1)
	raw, _ := json.Marshal(tk)
	dr := e.do(t, "POST", "/v1/decide", nil, raw, tk.Payload.Nonce)
	if dr.status != 200 || dr.body["ok"] != true || !dr.sigOK || dr.body["id"] != it.ID || dr.body["decision"] != "allow" {
		t.Fatalf("decide: %d %s", dr.status, dr.raw)
	}
	if o := wait(t, ch); !o.allow {
		t.Fatalf("exec not allowed: %+v", o.rec)
	}
	// a replay of the same ticket: the nonce_reused rejection is not bound to the ticket (otherwise
	// a middleman forwarding the ticket would hand the phone a "rejection" instead of the real reply)
	if dr := e.do(t, "POST", "/v1/decide", nil, raw, tk.Payload.Nonce); dr.body["ok"] != false || dr.sigOK || !dr.unauthOK {
		t.Fatalf("replayed ticket: %s (sig %v, unauth %v)", dr.raw, dr.sigOK, dr.unauthOK)
	}
	st := e.do(t, "GET", "/v1/status", signedHeaders(d.priv, e.s.supervisorID, "status", envelope.NowMs(), "n-status-01"), nil, "n-status-01")
	if st.status != 200 || st.body["journal"] != nil || st.body["supervisorId"] != e.s.supervisorID {
		t.Fatalf("status: %d %s", st.status, st.raw)
	}
	// the chain head is in the signed status, so the phone can pin the journal's tail
	head, _ := st.body["journalHead"].(map[string]any)
	if seq, _ := head["seq"].(float64); seq < 1 || head["hash"] != e.s.jr.Head().Hash || len(e.s.jr.Head().Hash) != 64 {
		t.Fatalf("status journalHead: %v (journal %+v)", head, e.s.jr.Head())
	}
}

// pairBody: a pairing request the way the app sends it.
func pairBody(d device, code, supID, name string) ([]byte, string) {
	pub := d.priv.Public().(ed25519.PublicKey)
	nonce := envelope.NewNonce()
	pp := envelope.PairPayload{Code: code, DeviceID: d.id, Pubkey: envelope.B64URL(pub), Name: name, SupervisorID: supID, Ts: envelope.NowMs(), Nonce: nonce}
	msg, _ := envelope.PairSigningString(pp)
	b, _ := json.Marshal(map[string]any{"code": pp.Code, "deviceId": pp.DeviceID, "pubkey": pp.Pubkey, "name": pp.Name,
		"supervisorId": pp.SupervisorID, "ts": pp.Ts, "nonce": pp.Nonce, "signature": envelope.B64URL(ed25519.Sign(d.priv, msg))})
	return b, nonce
}

func rpcDo(t *testing.T, sock, method string, params any, out any) error {
	t.Helper()
	c, err := dialRPC(sock)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	return c.call(method, params, out)
}

func TestPairingFlow(t *testing.T) {
	e := newHTTPEnv(t)
	phone := newDevice()

	// without an active code: rejection
	b, n := pairBody(phone, "ABCD2345", e.s.supervisorID, "Pixel")
	if r := e.do(t, "POST", "/v1/pair", nil, b, n); r.status != 403 || r.body["reason"] != "pairing_not_active" {
		t.Fatalf("no code: %d %s", r.status, r.raw)
	}
	var st struct {
		Code string `json:"code"`
		Link string `json:"link"`
	}
	if err := rpcDo(t, e.sock, "pair.start", map[string]any{}, &st); err != nil {
		t.Fatal(err)
	}
	link, err := envelope.ParsePairLink(st.Link)
	if err != nil || link.URL != e.srv.URL || link.Code != st.Code || link.Key != e.s.jr.PublicKey() {
		t.Fatalf("link %q: %v %+v", st.Link, err, link)
	}
	// the key from the QR = the key that signs the responses; supervisorId = sha256(key)
	pinned, _ := envelope.DecodeKey(link.Key)
	if envelope.DeviceID(pinned) != e.s.supervisorID {
		t.Fatal("supervisorId != sha256(key)")
	}

	// foreign supervisor, invalid signature, wrong code
	b, n = pairBody(phone, link.Code, strings.Repeat("0", 64), "Pixel")
	if r := e.do(t, "POST", "/v1/pair", nil, b, n); r.body["reason"] != "wrong_supervisor" {
		t.Fatalf("wrong supervisor: %s", r.raw)
	}
	b, n = pairBody(phone, link.Code, e.s.supervisorID, "Pixel")
	var m map[string]any
	json.Unmarshal(b, &m)
	m["name"] = "Evil" // signature over a different name
	bad, _ := json.Marshal(m)
	if r := e.do(t, "POST", "/v1/pair", nil, bad, n); r.body["reason"] != "bad_signature" {
		t.Fatalf("tampered: %s", r.raw)
	}
	if r := e.do(t, "POST", "/v1/pair", nil, mustPair(phone, "ZZZZ2222", e.s.supervisorID), ""); r.body["reason"] != "bad_code" {
		t.Fatalf("bad code: %s", r.raw)
	}

	// the real request
	r := e.do(t, "POST", "/v1/pair", nil, b, n)
	if r.status != 200 || r.body["status"] != "pending" || !r.sigOK || r.body["fingerprint"] != envelope.Fingerprint(phone.id) {
		t.Fatalf("pair: %d %s", r.status, r.raw)
	}
	id := r.body["id"].(string)
	// the code is one-time
	other := newDevice()
	if r := e.do(t, "POST", "/v1/pair", nil, mustPair(other, link.Code, e.s.supervisorID), ""); r.body["reason"] != "pairing_not_active" {
		t.Fatalf("code reuse: %s", r.raw)
	}
	// status: signed with the key from the request; before approval it is pending and there is no
	// access to pending
	ps := func(dev device, nonce string) resp {
		return e.do(t, "GET", "/v1/pair/status?id="+id, signedHeaders(dev.priv, e.s.supervisorID, "pair.status", envelope.NowMs(), nonce), nil, nonce)
	}
	if r := ps(phone, "n-ps-000001"); r.body["status"] != "pending" || !r.sigOK {
		t.Fatalf("pair status: %s", r.raw)
	}
	if r := ps(other, "n-ps-000002"); r.status != 401 {
		t.Fatalf("pair status by other device: %s", r.raw)
	}
	if r := e.do(t, "GET", "/v1/pending", signedHeaders(phone.priv, e.s.supervisorID, "pending", envelope.NowMs(), "n-pend-0001"), nil, "n-pend-0001"); r.status != 401 {
		t.Fatalf("pending before approve: %s", r.raw)
	}

	var list pairListResult
	if err := rpcDo(t, e.sock, "pair.list", map[string]any{}, &list); err != nil || len(list.Requests) != 1 || list.Requests[0].Fingerprint != envelope.Fingerprint(phone.id) {
		t.Fatalf("list: %v %+v", err, list)
	}
	if err := rpcDo(t, e.sock, "pair.approve", map[string]any{"id": id}, nil); err != nil {
		t.Fatal(err)
	}
	if err := rpcDo(t, e.sock, "pair.approve", map[string]any{"id": id}, nil); err == nil {
		t.Fatal("second approve must fail")
	}
	cfg, err := loadConfig(e.s.cfg.path)
	if err != nil || len(cfg.TrustedDevices) != 1 || cfg.TrustedDevices[0].ID != phone.id || cfg.TrustedDevices[0].Pubkey != envelope.B64URL(phone.priv.Public().(ed25519.PublicKey)) || cfg.TrustedDevices[0].Name != "Pixel" {
		t.Fatalf("config after approve: %v %+v", err, cfg)
	}
	if r := ps(phone, "n-ps-000003"); r.body["status"] != "approved" {
		t.Fatalf("pair status after approve: %s", r.raw)
	}
	if r := e.do(t, "GET", "/v1/pending", signedHeaders(phone.priv, e.s.supervisorID, "pending", envelope.NowMs(), "n-pend-0002"), nil, "n-pend-0002"); r.status != 200 {
		t.Fatalf("pending after approve: %s", r.raw)
	}

	// revoke: from the config and from memory
	if err := rpcDo(t, e.sock, "pair.revoke", map[string]any{"device": phone.id[:10]}, nil); err != nil {
		t.Fatal(err)
	}
	cfg, _ = loadConfig(e.s.cfg.path)
	if len(cfg.TrustedDevices) != 0 {
		t.Fatalf("config after revoke: %+v", cfg.TrustedDevices)
	}
	if r := ps(phone, "n-ps-000004"); r.body["status"] != "revoked" {
		t.Fatalf("pair status after revoke: %s", r.raw)
	}
	if r := e.do(t, "GET", "/v1/pending", signedHeaders(phone.priv, e.s.supervisorID, "pending", envelope.NowMs(), "n-pend-0003"), nil, "n-pend-0003"); r.status != 401 {
		t.Fatalf("pending after revoke: %s", r.raw)
	}
}

func mustPair(d device, code, sup string) []byte {
	b, _ := pairBody(d, code, sup, "x")
	return b
}

func TestPairingBruteForceKillsCodes(t *testing.T) {
	e := newHTTPEnv(t)
	var st struct{ Code string }
	if err := rpcDo(t, e.sock, "pair.start", map[string]any{}, &st); err != nil {
		t.Fatal(err)
	}
	d := newDevice()
	for i := 0; i < maxPairFails; i++ {
		e.do(t, "POST", "/v1/pair", nil, mustPair(d, fmt.Sprintf("WRONG%03d", i), e.s.supervisorID), "")
	}
	if r := e.do(t, "POST", "/v1/pair", nil, mustPair(d, st.Code, e.s.supervisorID), ""); r.body["reason"] != "pairing_not_active" {
		t.Fatalf("code must be dead after %d failures: %s", maxPairFails, r.raw)
	}
}

func TestPairingKeepsOtherConfigAndReject(t *testing.T) {
	e := newHTTPEnv(t)
	os.WriteFile(e.s.cfg.path, []byte(`{"mode":"ticket","trusted_devices":[{"id":"<placeholder>","name":"old"}],"hardware_keys":[]}`), 0o600)
	for _, want := range []string{"reject", "approve"} {
		var st struct{ Code string }
		rpcDo(t, e.sock, "pair.start", map[string]any{}, &st)
		d := newDevice()
		r := e.do(t, "POST", "/v1/pair", nil, mustPair(d, st.Code, e.s.supervisorID), "")
		if r.status != 200 {
			t.Fatalf("pair: %s", r.raw)
		}
		if err := rpcDo(t, e.sock, "pair."+want, map[string]any{"id": r.body["id"]}, nil); err != nil {
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

// A socket client under a seccomp filter (like the gateway/agent under wardend) does not control
// pairing.
func TestPairRPCRefusedUnderFilter(t *testing.T) {
	e := newHTTPEnv(t)
	if e.s.peerSupervised(os.Getpid()) {
		t.Fatal("test process itself must be allowed")
	}
	cmd := exec.Command(os.Args[0], "-test.run=^$")
	cmd.Env = append(os.Environ(), "WARDEND_TEST_HELPER=filtered")
	out, _ := cmd.StdoutPipe()
	stdin, _ := cmd.StdinPipe()
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { stdin.Close(); cmd.Wait() }()
	buf := make([]byte, 16)
	if n, _ := out.Read(buf); !strings.HasPrefix(string(buf[:n]), "ready") {
		t.Fatalf("helper: %q", buf[:n])
	}
	if !e.s.peerSupervised(cmd.Process.Pid) {
		t.Fatal("process with an extra seccomp filter must count as supervised")
	}
	// a descendant of the supervisor's child (even without an extra filter)
	sl := exec.Command("sleep", "5")
	sl.Start()
	defer sl.Process.Kill()
	e.s.childPid = os.Getpid()
	if !e.s.peerSupervised(sl.Process.Pid) {
		t.Fatal("descendant of the supervised child must count as supervised")
	}
	e.s.childPid = -1
}

// helperFiltered: TestMain mode: install an allowing seccomp filter and wait on stdin.
func helperFiltered() {
	unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)
	prog := []unix.SockFilter{{Code: 0x06, K: 0x7fff0000}} // BPF_RET|BPF_K SECCOMP_RET_ALLOW
	fp := unix.SockFprog{Len: 1, Filter: &prog[0]}
	if _, _, errno := unix.Syscall(unix.SYS_SECCOMP, 1 /* SET_MODE_FILTER */, 0, uintptrOf(&fp)); errno != 0 {
		fmt.Println("seccomp:", errno)
		os.Exit(1)
	}
	fmt.Print("ready")
	io.Copy(io.Discard, os.Stdin)
	os.Exit(0)
}

func TestNtfyCoalescesAndHidesDetails(t *testing.T) {
	var bodies []string
	got := make(chan struct{}, 10)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		bodies = append(bodies, r.Header.Get("Title")+"|"+string(b)+"|"+r.Header.Get("Authorization"))
		got <- struct{}{}
	}))
	defer srv.Close()
	d := newDevice()
	s := newHWSupervisor(t, `{}`, d)
	s.ntfy = newNotifier(srv.URL, "tok", nil)
	sent := make(chan struct{}, 10)
	s.ntfy.sent = func() { sent <- struct{}{} }
	ctx, cancel := contextWithCancel()
	defer cancel()
	go s.ntfy.run(ctx)
	ch1, it1 := startExec(t, s, 100, "curl", "https://secret.example/token")
	ch2, it2 := startExec(t, s, 200, "ls", "/private")
	<-sent
	select {
	case <-got:
	case <-time.After(3 * time.Second):
		t.Fatal("no ntfy request")
	}
	time.Sleep(200 * time.Millisecond)
	if len(bodies) != 1 {
		t.Fatalf("expected one coalesced notification, got %d", len(bodies))
	}
	if strings.Contains(bodies[0], "curl") || strings.Contains(bodies[0], "secret") || !strings.HasSuffix(bodies[0], "|Bearer tok") {
		t.Fatalf("notification leaks details or lacks token: %q", bodies[0])
	}
	decideRaw(s, ticket(d, it1, "deny", -1))
	decideRaw(s, ticket(d, it2, "deny", -1))
	wait(t, ch1)
	wait(t, ch2)
}

func uintptrOf(fp *unix.SockFprog) uintptr { return uintptr(unsafe.Pointer(fp)) }

func contextWithCancel() (context.Context, context.CancelFunc) {
	return context.WithCancel(context.Background())
}
