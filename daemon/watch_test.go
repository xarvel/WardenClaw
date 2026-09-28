// SPDX-License-Identifier: AGPL-3.0-or-later

package main

// Apple Watch as an es256 device (P-256, Secure Enclave): pairing, tickets, requests, refusal on
// hardware-required; push tokens (register/unregister) and the APNs client against an HTTP/2
// mock server.

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

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

func (w watchDev) headers(sup, action string, nonce string, body any, der bool) map[string]string {
	ts := envelope.NowMs()
	var msg []byte
	if body != nil {
		msg, _ = envelope.RequestBodySigningString(sup, action, w.id, ts, nonce, body)
	} else {
		msg, _ = envelope.RequestSigningString(sup, action, w.id, ts, nonce)
	}
	return map[string]string{"X-Wardenclaw-Device": w.id, "X-Wardenclaw-Ts": strconv.FormatInt(ts, 10), "X-Wardenclaw-Nonce": nonce,
		"X-Wardenclaw-Signature": w.sign(msg, der)}
}

// ---------- pairing ----------

func TestWatchPairingES256(t *testing.T) {
	e := newHTTPEnv(t)
	w := newWatch()
	var st struct {
		Code string `json:"code"`
	}
	if err := rpcDo(t, e.sock, "pair.start", map[string]any{}, &st); err != nil {
		t.Fatal(err)
	}
	// body: alg in the body; signAlg: which alg went into the signed string; pub: which key is claimed
	mk := func(bodyAlg, signAlg, pub string) []byte {
		pp := envelope.PairPayload{Code: st.Code, DeviceID: w.id, Pubkey: pub, Alg: signAlg, Name: "Apple Watch", SupervisorID: e.s.supervisorID, Ts: envelope.NowMs(), Nonce: envelope.NewNonce()}
		msg, _ := envelope.PairSigningString(pp)
		pp.Alg = bodyAlg
		m := map[string]any{"code": pp.Code, "deviceId": pp.DeviceID, "pubkey": pp.Pubkey, "name": pp.Name, "supervisorId": pp.SupervisorID,
			"ts": pp.Ts, "nonce": pp.Nonce, "signature": w.sign(msg, true)}
		if bodyAlg != "" {
			m["alg"] = bodyAlg
		}
		b, _ := json.Marshal(m)
		return b
	}
	_, edPriv, _ := ed25519.GenerateKey(rand.Reader)
	edPub := envelope.B64URL(edPriv.Public().(ed25519.PublicKey))
	for _, c := range []struct {
		name                  string
		bodyAlg, signAlg, pub string
		want                  string
	}{
		{"legacy form without alg", "", "", w.key.B64(), "pubkey_invalid"},                  // ed25519 by default, 65 bytes are not an Ed25519 key
		{"alg not signed", "es256", "", w.key.B64(), "bad_signature"},                       // tampering: alg appended after signing
		{"alg ed25519 with P-256 key", "ed25519", "ed25519", w.key.B64(), "pubkey_invalid"}, //
		{"upper-case alg", "ES256", "ES256", w.key.B64(), "alg_unsupported"},
		{"unknown alg", "rs256", "rs256", w.key.B64(), "alg_unsupported"},
		{"es256 with ed25519 key", "es256", "es256", edPub, "pubkey_invalid"},
	} {
		r := e.do(t, "POST", "/v1/pair", nil, mk(c.bodyAlg, c.signAlg, c.pub), "")
		if r.body["reason"] != c.want {
			t.Errorf("%s: %d %s", c.name, r.status, r.raw)
		}
	}
	r := e.do(t, "POST", "/v1/pair", nil, mk("es256", "es256", w.key.B64()), "")
	if r.status != 200 || r.body["status"] != "pending" || r.body["fingerprint"] != envelope.Fingerprint(w.id) {
		t.Fatalf("pair: %d %s", r.status, r.raw)
	}
	id := r.body["id"].(string)
	if l := e.s.pairList(); !strings.Contains(mustJSON(l), `"alg":"es256"`) {
		t.Fatalf("pair list lacks alg: %s", mustJSON(l))
	}
	if _, err := e.s.pairApprove(id); err != nil {
		t.Fatal(err)
	}
	cfg, _ := os.ReadFile(e.s.cfg.path)
	if !strings.Contains(string(cfg), `"alg": "es256"`) || !strings.Contains(string(cfg), w.key.B64()) {
		t.Fatalf("config: %s", cfg)
	}
	// after approval: pair.status (DER) and status (raw) are signed with the watch key
	if r := e.do(t, "GET", "/v1/pair/status?id="+id, w.headers(e.s.supervisorID, "pair.status", "n-wps-00001", nil, true), nil, "n-wps-00001"); r.body["status"] != "approved" || !r.sigOK {
		t.Fatalf("pair status: %s", r.raw)
	}
	r = e.do(t, "GET", "/v1/status", w.headers(e.s.supervisorID, "status", "n-wst-00001", nil, false), nil, "n-wst-00001")
	if r.status != 200 || !strings.Contains(string(r.raw), `"alg":"es256"`) {
		t.Fatalf("status: %d %s", r.status, r.raw)
	}
	// an Ed25519 signature under the watch's deviceId fails (the algorithm comes from the config)
	h := signedHeaders(edPriv, e.s.supervisorID, "pending", envelope.NowMs(), "n-wpe-00001")
	h["X-Wardenclaw-Device"] = w.id
	if r := e.do(t, "GET", "/v1/pending", h, nil, "n-wpe-00001"); r.body["reason"] != "bad_signature" {
		t.Fatalf("ed25519 sig for es256 device: %s", r.raw)
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

// ---------- APNs: HTTP/2 mock ----------

type apnsReq struct {
	proto int
	path  string
	hdr   http.Header
	body  []byte
}

type apnsMock struct {
	srv   *httptest.Server
	mu    sync.Mutex
	reqs  []apnsReq
	reply func(token string, n int) (int, string) // status and reason; nil: 200
	got   chan apnsReq
}

func newAPNSMock(t *testing.T) *apnsMock {
	m := &apnsMock{got: make(chan apnsReq, 32)}
	m.srv = httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		q := apnsReq{proto: r.ProtoMajor, path: r.URL.Path, hdr: r.Header.Clone(), body: b}
		m.mu.Lock()
		m.reqs = append(m.reqs, q)
		n := len(m.reqs)
		m.mu.Unlock()
		m.got <- q
		w.Header().Set("apns-id", "00000000-0000-0000-0000-00000000000"+strconv.Itoa(n%10))
		if m.reply != nil {
			if code, reason := m.reply(strings.TrimPrefix(r.URL.Path, "/3/device/"), n); code != 200 {
				w.WriteHeader(code)
				json.NewEncoder(w).Encode(map[string]string{"reason": reason})
				return
			}
		}
		w.WriteHeader(200)
	}))
	m.srv.EnableHTTP2 = true
	m.srv.StartTLS()
	t.Cleanup(m.srv.Close)
	return m
}

// attach points the client at the mock (both environments), trusts its certificate, HTTP/2 only.
func (m *apnsMock) attach(c *apnsClient) {
	pool := x509.NewCertPool()
	pool.AddCert(m.srv.Certificate())
	tr := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool}, ForceAttemptHTTP2: true}
	tr.Protocols = new(http.Protocols)
	tr.Protocols.SetHTTP2(true)
	c.hc = &http.Client{Transport: tr, Timeout: 5 * time.Second}
	c.hosts = map[string]string{"production": m.srv.URL, "sandbox": m.srv.URL}
}

// writeP8 writes an APNs key as from Apple Developer: PKCS#8 PEM, P-256, 0600.
func writeP8(t *testing.T, dir string, mode os.FileMode) (string, *ecdsa.PrivateKey) {
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, _ := x509.MarshalPKCS8PrivateKey(k)
	p := filepath.Join(dir, "AuthKey_ABC123DEFG.p8")
	if err := os.WriteFile(p, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), mode); err != nil {
		t.Fatal(err)
	}
	os.Chmod(p, mode)
	return p, k
}

func testAPNSConfig(keyFile string) *APNSConfig {
	return &APNSConfig{KeyFile: keyFile, KeyID: "ABC123DEFG", TeamID: "TEAM123456", TopicIOS: "com.wardenclaw.app", TopicWatch: "com.wardenclaw.app.watchkitapp"}
}

// checkJWT checks the header, claims and ES256 signature of the provider token.
func checkJWT(t *testing.T, bearer string, pub *ecdsa.PublicKey, now time.Time) {
	t.Helper()
	tok, ok := strings.CutPrefix(bearer, "bearer ")
	parts := strings.Split(tok, ".")
	if !ok || len(parts) != 3 {
		t.Fatalf("authorization: %q", bearer)
	}
	hb, _ := envelope.DecodeB64URL(parts[0])
	cb, _ := envelope.DecodeB64URL(parts[1])
	var h, c map[string]any
	json.Unmarshal(hb, &h)
	json.Unmarshal(cb, &c)
	if h["alg"] != "ES256" || h["kid"] != "ABC123DEFG" || len(h) != 2 {
		t.Fatalf("jwt header: %s", hb)
	}
	if c["iss"] != "TEAM123456" || c["iat"] != float64(now.Unix()) || len(c) != 2 {
		t.Fatalf("jwt claims: %s", cb)
	}
	sig, _ := envelope.DecodeB64URL(parts[2])
	if len(sig) != 64 || !envelope.VerifyES256(pub, []byte(parts[0]+"."+parts[1]), sig) {
		t.Fatal("jwt signature (raw r||s ES256) invalid")
	}
}

func TestAPNSClient(t *testing.T) {
	m := newAPNSMock(t)
	kf, key := writeP8(t, t.TempDir(), 0o600)
	c, err := newAPNSClient(*testAPNSConfig(kf))
	if err != nil {
		t.Fatal(err)
	}
	m.attach(c)
	now := time.Unix(1790447985, 0)
	c.now = func() time.Time { return now }
	tok := pushToken{DeviceID: "d", Platform: "apns", Token: strings.Repeat("ab", 32), Topic: "com.wardenclaw.app.watchkitapp", Environment: "sandbox"}
	exp := time.UnixMilli(1790448105039)
	card := "wd-0123456789abcdef0123456789abcdef"
	r, err := c.push(context.Background(), tok, card, exp)
	if err != nil || r.Status != 200 {
		t.Fatalf("push: %v %+v", err, r)
	}
	q := <-m.got
	if q.proto != 2 || q.path != "/3/device/"+tok.Token {
		t.Fatalf("proto %d path %s", q.proto, q.path)
	}
	for k, want := range map[string]string{"apns-topic": tok.Topic, "apns-push-type": "alert", "apns-priority": "10",
		"apns-expiration": "1790448105", "apns-collapse-id": card} {
		if got := q.hdr.Get(k); got != want {
			t.Errorf("%s = %q, want %q", k, got, want)
		}
	}
	checkJWT(t, q.hdr.Get("authorization"), &key.PublicKey, now)
	want := `{"aps":{"alert":{"title":"Approval request","body":"Open to review"},"category":"WARDEN_APPROVAL","sound":"default","interruption-level":"time-sensitive"},"cardId":"` + card + `"}`
	if string(q.body) != want {
		t.Fatalf("payload:\n%s\nwant\n%s", q.body, want)
	}
	// the JWT is cached for 50 minutes, then a new one
	first := q.hdr.Get("authorization")
	now = now.Add(49 * time.Minute)
	c.push(context.Background(), tok, card, exp)
	if q := <-m.got; q.hdr.Get("authorization") != first {
		t.Fatal("jwt must be cached for 50 min")
	}
	now = now.Add(2 * time.Minute)
	c.push(context.Background(), tok, card, exp)
	q = <-m.got
	if q.hdr.Get("authorization") == first {
		t.Fatal("jwt must be refreshed after 50 min")
	}
	checkJWT(t, q.hdr.Get("authorization"), &key.PublicKey, now)
	// ExpiredProviderToken → one retry with a fresh JWT
	m.reply = func(_ string, n int) (int, string) {
		if n == 4 {
			return 403, "ExpiredProviderToken"
		}
		return 200, ""
	}
	now = now.Add(time.Second)
	if r, err := c.push(context.Background(), tok, card, exp); err != nil || r.Status != 200 {
		t.Fatalf("retry: %v %+v", err, r)
	}
	<-m.got
	<-m.got
	// bad key / config
	bad := filepath.Join(t.TempDir(), "k.p8")
	os.WriteFile(bad, []byte("not a key"), 0o600)
	for name, cfg := range map[string]APNSConfig{
		"not pem":  *testAPNSConfig(bad),
		"no key":   *testAPNSConfig(filepath.Join(t.TempDir(), "missing.p8")),
		"key id":   {KeyFile: kf, KeyID: "short", TeamID: "TEAM123456", TopicIOS: "x"},
		"no topic": {KeyFile: kf, KeyID: "ABC123DEFG", TeamID: "TEAM123456"},
	} {
		if _, err := newAPNSClient(cfg); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// pushEnv is an HTTP environment with APNs on a mock server.
func pushEnv(t *testing.T, phone device) (*httpEnv, *apnsMock) {
	e := newHTTPEnv(t, phone)
	kf, _ := writeP8(t, t.TempDir(), 0o600)
	e.s.cfg.APNS = testAPNSConfig(kf)
	e.s.push = newPushService(e.s.cfg, e.s)
	if !e.s.push.enabled() {
		t.Fatalf("apns: %s", e.s.push.apnsErr)
	}
	m := newAPNSMock(t)
	m.attach(e.s.push.apns)
	return e, m
}

func regBody(id, token, topic, env string) map[string]any {
	return map[string]any{"deviceId": id, "platform": "apns", "token": token, "topic": topic, "environment": env}
}

func TestPushRegisterSigned(t *testing.T) {
	phone, w, stranger := newDevice(), newWatch(), newWatch()
	e, _ := pushEnv(t, phone)
	e.s.devices.Add(w.trusted())
	tokW, tokP := strings.Repeat("a1", 32), strings.Repeat("b2", 32)
	post := func(path, action string, dev watchDev, nonce string, signed, sent map[string]any, der bool) resp {
		raw, _ := json.Marshal(sent)
		return e.do(t, "POST", path, dev.headers(e.s.supervisorID, action, nonce, signed, der), raw, nonce)
	}
	body := regBody(w.id, tokW, "com.wardenclaw.app.watchkitapp", "sandbox")
	r := post("/v1/push/register", "push.register", w, "n-reg-00001", body, body, true)
	if r.status != 200 || r.body["ok"] != true || !r.sigOK {
		t.Fatalf("register: %d %s", r.status, r.raw)
	}
	if r := post("/v1/push/register", "push.register", w, "n-reg-00001", body, body, true); r.body["reason"] != "nonce_reused" {
		t.Fatalf("replay: %s", r.raw)
	}
	for _, c := range []struct {
		name         string
		dev          watchDev
		signed, sent map[string]any
		action       string
		want         string
	}{
		{"body swapped after signing", w, body, regBody(w.id, strings.Repeat("cc", 32), "com.wardenclaw.app.watchkitapp", "sandbox"), "push.register", "bad_signature"},
		{"signed as unregister", w, body, body, "push.unregister", "bad_signature"},
		{"untrusted device", stranger, regBody(stranger.id, tokW, "com.wardenclaw.app", "sandbox"), regBody(stranger.id, tokW, "com.wardenclaw.app", "sandbox"), "push.register", "untrusted_device"},
		{"other device's id in body", w, regBody(phone.id, tokW, "com.wardenclaw.app", "sandbox"), regBody(phone.id, tokW, "com.wardenclaw.app", "sandbox"), "push.register", "device_mismatch"},
		{"foreign topic", w, regBody(w.id, tokW, "com.evil.app", "sandbox"), regBody(w.id, tokW, "com.evil.app", "sandbox"), "push.register", "topic_not_allowed"},
		{"bad environment", w, regBody(w.id, tokW, "com.wardenclaw.app", "development"), regBody(w.id, tokW, "com.wardenclaw.app", "development"), "push.register", "environment_invalid"},
		{"upper-case token", w, regBody(w.id, strings.ToUpper(tokW), "com.wardenclaw.app", "sandbox"), regBody(w.id, strings.ToUpper(tokW), "com.wardenclaw.app", "sandbox"), "push.register", "token_invalid"},
	} {
		r := e.do(t, "POST", "/v1/push/register", c.dev.headers(e.s.supervisorID, c.action, "n-"+strings.ReplaceAll(c.name, " ", "-"), c.signed, true), []byte(mustJSON(c.sent)), "n-"+strings.ReplaceAll(c.name, " ", "-"))
		if r.body["reason"] != c.want {
			t.Errorf("%s: %d %s", c.name, r.status, r.raw)
		}
	}
	// the phone (ed25519) registers its token via the same mechanism
	pb := regBody(phone.id, tokP, "com.wardenclaw.app", "production")
	ts := envelope.NowMs()
	msg, _ := envelope.RequestBodySigningString(e.s.supervisorID, "push.register", phone.id, ts, "n-preg-0001", pb)
	h := map[string]string{"X-Wardenclaw-Device": phone.id, "X-Wardenclaw-Ts": strconv.FormatInt(ts, 10), "X-Wardenclaw-Nonce": "n-preg-0001",
		"X-Wardenclaw-Signature": envelope.B64URL(ed25519.Sign(phone.priv, msg))}
	if r := e.do(t, "POST", "/v1/push/register", h, []byte(mustJSON(pb)), "n-preg-0001"); r.status != 200 {
		t.Fatalf("phone register: %s", r.raw)
	}
	if n := len(e.s.push.store.snapshot()); n != 2 {
		t.Fatalf("tokens: %d", n)
	}
	fb, _ := os.ReadFile(e.s.cfg.PushTokens)
	if st, _ := os.Stat(e.s.cfg.PushTokens); st.Mode().Perm() != 0o600 || !strings.Contains(string(fb), tokW) {
		t.Fatalf("push_tokens.json %v: %s", st.Mode(), fb)
	}
	// status: tokens are not exposed, only their count
	if st := mustJSON(e.s.status()); !strings.Contains(st, `"tokens":2`) || strings.Contains(st, tokW) {
		t.Fatalf("status: %s", st)
	}
	// unregister: without token, all of the device's tokens; other devices' tokens are untouched
	ub := map[string]any{"deviceId": w.id}
	if r := post("/v1/push/unregister", "push.unregister", w, "n-unreg-001", ub, ub, false); r.status != 200 || r.body["removed"] != float64(1) {
		t.Fatalf("unregister: %s", r.raw)
	}
	// revoking a device also removes its tokens
	if _, err := e.s.pairRevoke(phone.id); err != nil {
		t.Fatal(err)
	}
	if n := len(e.s.push.store.snapshot()); n != 0 {
		t.Fatalf("tokens after revoke: %d", n)
	}
}

func TestPushNotConfigured(t *testing.T) {
	w := newWatch()
	e := newHTTPEnv(t)
	e.s.devices.Add(w.trusted())
	e.s.push = newPushService(e.s.cfg, e.s) // apns not set
	body := regBody(w.id, strings.Repeat("a1", 32), "com.wardenclaw.app", "sandbox")
	r := e.do(t, "POST", "/v1/push/register", w.headers(e.s.supervisorID, "push.register", "n-npc-00001", body, true), []byte(mustJSON(body)), "n-npc-00001")
	if r.status != 409 || r.body["reason"] != "push_not_configured" {
		t.Fatalf("%d %s", r.status, r.raw)
	}
	e.s.push.notify("wd-x", time.Now().Add(time.Minute)) // without apns: no-op, does not block
	if m := e.s.push.info(); m["apns"] != false {
		t.Fatalf("info: %v", m)
	}
}

// A new card → push to all tokens; the payload carries only the card id; 410 removes the token.
func TestPushOnNewCard(t *testing.T) {
	phone, w := newDevice(), newWatch()
	s := newHWSupervisor(t, `{}`, phone)
	s.devices.Add(w.trusted())
	kf, _ := writeP8(t, t.TempDir(), 0o600)
	s.cfg.APNS = testAPNSConfig(kf)
	s.push = newPushService(s.cfg, s)
	m := newAPNSMock(t)
	m.attach(s.push.apns)
	gone, live := strings.Repeat("0d", 32), strings.Repeat("1e", 32)
	m.reply = func(tok string, _ int) (int, string) {
		if tok == gone {
			return 410, "Unregistered"
		}
		return 200, ""
	}
	now := time.Now().UnixMilli()
	s.push.store.register(pushToken{DeviceID: w.id, Platform: "apns", Token: gone, Topic: "com.wardenclaw.app.watchkitapp", Environment: "sandbox", RegisteredAt: now})
	s.push.store.register(pushToken{DeviceID: w.id, Platform: "apns", Token: live, Topic: "com.wardenclaw.app.watchkitapp", Environment: "production", RegisteredAt: now + 1})
	s.push.store.register(pushToken{DeviceID: strings.Repeat("f", 64), Platform: "apns", Token: strings.Repeat("2f", 32), Topic: "com.wardenclaw.app", Environment: "sandbox", RegisteredAt: now + 2}) // not trusted: not sent
	done := make(chan map[string]apnsResult, 1)
	s.push.sent = func(_ string, r map[string]apnsResult) { done <- r }
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go s.push.run(ctx)

	ch, it := startExec(t, s, 100, "cat", "/home/secret-project/SECRET-ARG")
	var res map[string]apnsResult
	select {
	case res = <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("no push")
	}
	if len(res) != 2 || res[live].Status != 200 || res[gone].Status != 410 {
		t.Fatalf("results: %+v", res)
	}
	m.mu.Lock()
	reqs := append([]apnsReq(nil), m.reqs...)
	m.mu.Unlock()
	for _, q := range reqs {
		if strings.Contains(string(q.body), "SECRET") || strings.Contains(string(q.body), "hostname") || strings.Contains(string(q.body), "/home") ||
			!strings.Contains(string(q.body), `"cardId":"`+it.ID+`"`) {
			t.Fatalf("payload leaks or lacks card id: %s", q.body)
		}
		if q.hdr.Get("apns-collapse-id") != it.ID || q.hdr.Get("apns-expiration") != strconv.FormatInt(it.ExpiresAt/1000, 10) {
			t.Fatalf("headers: %v", q.hdr)
		}
	}
	toks := s.push.store.snapshot()
	for _, x := range toks {
		if x.Token == gone {
			t.Fatal("410 token not removed")
		}
	}
	if len(toks) != 2 {
		t.Fatalf("tokens left: %+v", toks)
	}
	jb, _ := os.ReadFile(s.cfg.Journal)
	if !strings.Contains(string(jb), `"push_token_removed"`) || !strings.Contains(string(jb), `"sent":1`) {
		t.Fatalf("journal:\n%s", jb)
	}
	decideRaw(s, w.ticket(it, "deny", true))
	wait(t, ch)
}

func TestSelfCheckAPNSKey(t *testing.T) {
	dir := t.TempDir()
	os.Chmod(dir, 0o700)
	exe := filepath.Join(dir, "wardend")
	os.WriteFile(exe, []byte("x"), 0o700)
	kf, _ := writeP8(t, dir, 0o600)
	cfg := &Config{StateDir: dir, APNS: testAPNSConfig(kf)}
	if got := checkInstall(cfg, exe, true, false); hasFatal(got) {
		t.Fatalf("0600 key: %+v", got)
	}
	os.Chmod(kf, 0o640)
	if got := checkInstall(cfg, exe, true, false); !hasFatal(got) {
		t.Fatalf("group-readable APNs key must be fatal: %+v", got)
	}
}

func TestPushRPCListAndTest(t *testing.T) {
	phone := newDevice()
	e, m := pushEnv(t, phone)
	tok := strings.Repeat("3c", 32)
	e.s.push.store.register(pushToken{DeviceID: phone.id, Platform: "apns", Token: tok, Topic: "com.wardenclaw.app", Environment: "sandbox", RegisteredAt: 1})
	var l map[string]any
	if err := rpcDo(t, e.sock, "push.list", map[string]any{}, &l); err != nil {
		t.Fatal(err)
	}
	if s := mustJSON(l); strings.Contains(s, tok) || !strings.Contains(s, `"token":"3c3c3c3c…"`) || !strings.Contains(s, `"apns":true`) {
		t.Fatalf("push.list: %s", s)
	}
	var r struct {
		Results []map[string]any `json:"results"`
	}
	if err := rpcDo(t, e.sock, "push.test", map[string]any{"device": phone.id[:10]}, &r); err != nil {
		t.Fatal(err)
	}
	if len(r.Results) != 1 || r.Results[0]["status"] != float64(200) {
		t.Fatalf("push.test: %+v", r)
	}
	if q := <-m.got; !strings.Contains(string(q.body), `"cardId":"wd-test"`) {
		t.Fatalf("test payload: %s", q.body)
	}
}
