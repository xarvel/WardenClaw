// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/xarvel/WardenClaw/daemon/envelope"
	"github.com/xarvel/WardenClaw/daemon/relaylink"
	"github.com/xarvel/WardenClaw/daemon/relaylink/relaytest"
)

// ---------- payload encryption ----------

func unhex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// The X25519 keys of RFC 7748 section 6.1: both sides derive the same box key, and it depends on
// the pair of ids in the fixed order supervisor, device.
func TestRelayBoxKeyAgreement(t *testing.T) {
	a, _ := ecdh.X25519().NewPrivateKey(unhex(t, "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a"))
	b, _ := ecdh.X25519().NewPrivateKey(unhex(t, "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb"))
	if got := hex.EncodeToString(a.PublicKey().Bytes()); got != "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a" {
		t.Fatalf("public key %s", got)
	}
	shared, _ := a.ECDH(b.PublicKey())
	if got := hex.EncodeToString(shared); got != "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742" {
		t.Fatalf("shared secret %s", got)
	}
	sid, did := strings.Repeat("a", 64), strings.Repeat("b", 64)
	k1, err1 := relaylink.BoxKey(a, b.PublicKey(), sid, did)
	k2, err2 := relaylink.BoxKey(b, a.PublicKey(), sid, did)
	if err1 != nil || err2 != nil || !bytes.Equal(k1, k2) || len(k1) != 32 {
		t.Fatalf("keys differ: %x %x (%v, %v)", k1, k2, err1, err2)
	}
	if k3, _ := relaylink.BoxKey(a, b.PublicKey(), did, sid); bytes.Equal(k1, k3) {
		t.Fatal("the key does not depend on the order of the ids")
	}
	// a low-order point gives an all-zero shared secret: refused
	zero, _ := ecdh.X25519().NewPublicKey(make([]byte, 32))
	if _, err := relaylink.BoxKey(a, zero, sid, did); err == nil {
		t.Fatal("low-order peer key accepted")
	}
}

// The AEAD vector of draft-irtf-cfrg-xchacha-03 appendix A.3.1 through relaylink.Seal/relaylink.Open.
func TestRelayBoxXChaChaVector(t *testing.T) {
	key := unhex(t, "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f")
	nonce := unhex(t, "404142434445464748494a4b4c4d4e4f5051525354555657")
	aad := unhex(t, "50515253c0c1c2c3c4c5c6c7")
	pt := []byte("Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.")
	body, err := relaylink.Seal(key, nonce, pt, aad)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := envelope.DecodeB64URL(body)
	if !bytes.Equal(raw[:24], nonce) || len(raw) != 24+len(pt)+16 {
		t.Fatalf("layout: %d bytes", len(raw))
	}
	if got := hex.EncodeToString(raw[len(raw)-16:]); got != "c0875924c1c7987947deafd8780acf49" {
		t.Fatalf("tag %s", got)
	}
	got, err := relaylink.Open(key, body, aad)
	if err != nil || !bytes.Equal(got, pt) {
		t.Fatalf("open: %v", err)
	}
}

func TestRelayBoxBindsRouting(t *testing.T) {
	key := bytes.Repeat([]byte{7}, 32)
	aad := func(id, from, to, kind string, exp int64) []byte {
		b, err := relaylink.AAD(id, from, to, kind, exp)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	good := aad("i", "f", "t", "card", 10)
	if want := `{"exp":10,"from":"f","id":"i","kind":"card","to":"t","type":"wardenclaw.relay.aad.v1"}`; string(good) != want {
		t.Fatalf("aad %s", good)
	}
	body, _ := relaylink.Seal(key, nil, []byte(`{"a":1}`), good)
	if pt, err := relaylink.Open(key, body, good); err != nil || string(pt) != `{"a":1}` {
		t.Fatalf("round trip: %q %v", pt, err)
	}
	for name, bad := range map[string][]byte{"id": aad("x", "f", "t", "card", 10), "from": aad("i", "x", "t", "card", 10), "to": aad("i", "f", "x", "card", 10),
		"kind": aad("i", "f", "t", "ticket", 10), "exp": aad("i", "f", "t", "card", 11)} {
		if _, err := relaylink.Open(key, body, bad); !errors.Is(err, relaylink.ErrBox) {
			t.Errorf("rewritten %s: %v", name, err)
		}
	}
	for _, b := range []string{"", "!!", "AAAA", body[:len(body)-2] + "AA", body + "AA"} {
		if _, err := relaylink.Open(key, b, good); !errors.Is(err, relaylink.ErrBox) {
			t.Errorf("body %q: %v", b, err)
		}
	}
	if b2, _ := relaylink.Seal(key, nil, []byte(`{"a":1}`), good); b2 == body {
		t.Fatal("two boxes with the same nonce")
	}
}

func TestRelayKeyFile(t *testing.T) {
	p := filepath.Join(t.TempDir(), "relay_enc.key")
	k1, err := loadOrCreateRelayKey(p)
	if err != nil {
		t.Fatal(err)
	}
	k2, err := loadOrCreateRelayKey(p)
	if err != nil || !k1.Equal(k2) {
		t.Fatalf("reload: %v", err)
	}
	if st, _ := os.Stat(p); st.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v", st.Mode())
	}
	_ = os.WriteFile(p, []byte("zz\n"), 0o600)
	if _, err := loadOrCreateRelayKey(p); err == nil {
		t.Fatal("a damaged key file was replaced or accepted")
	}
}

func TestRelayURLConfig(t *testing.T) {
	for in, want := range map[string]string{"": "off", "off": "off", "wss://relay.wardenclaw.dev/": "wss://relay.wardenclaw.dev", "https://r.example:8443": "wss://r.example:8443",
		"ws://127.0.0.1:8787": "ws://127.0.0.1:8787", "ws://localhost:1/x": "ws://localhost:1/x"} {
		if got, err := normalizeRelayURL(in); err != nil || got != want {
			t.Errorf("%q: %q, %v", in, got, err)
		}
	}
	for _, in := range []string{"ws://relay.example", "http://relay.example", "relay.example", "wss://", "wss://u:p@relay.example", "wss://relay.example/v1/ws", "wss://relay.example?x=1"} {
		if got, err := normalizeRelayURL(in); err == nil {
			t.Errorf("%q accepted as %q", in, got)
		}
	}
	c := &Config{StateDir: t.TempDir(), RelayURL: "ws://relay.example"}
	if err := c.setDefaults(); err == nil {
		t.Fatal("setDefaults accepted a plain ws:// relay")
	}
	c = &Config{StateDir: t.TempDir()}
	if err := c.setDefaults(); err != nil || c.relayOn() || c.RelayKeyFile != filepath.Join(c.StateDir, "relay_enc.key") {
		t.Fatalf("defaults under test: %q %q %v", c.RelayURL, c.RelayKeyFile, err)
	}
	// out of the box the relay is on; "off" stays off however often the defaults are applied
	defaultRelayURL = "wss://relay.wardenclaw.dev"
	defer func() { defaultRelayURL = "" }()
	c = &Config{StateDir: t.TempDir()}
	if err := c.setDefaults(); err != nil || !c.relayOn() || c.RelayURL != "wss://relay.wardenclaw.dev" {
		t.Fatalf("default relay: %q %v", c.RelayURL, err)
	}
	c = &Config{StateDir: t.TempDir(), RelayURL: "off"}
	for range 2 {
		if err := c.setDefaults(); err != nil || c.relayOn() {
			t.Fatalf("relay_url off: %q %v", c.RelayURL, err)
		}
	}
}

// ---------- hello ----------

// The signing string is written out by hand here: what relay/src/channel.ts builds with
// canonicalJson({type, role, key, enc, ts, nonce, client}).
func TestRelayHelloSigningString(t *testing.T) {
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{1}, 32))
	pub := envelope.B64URL(key.Public().(ed25519.PublicKey))
	f, err := relaylink.Hello("supervisor", "wardend", version, key, "ENC", "NONCE", 1700000000000)
	if err != nil {
		t.Fatal(err)
	}
	want := fmt.Sprintf(`{"client":{"name":"wardend","protocol":1,"version":%q},"enc":"ENC","key":%q,"nonce":"NONCE","role":"supervisor","ts":1700000000000,"type":"wardenclaw.relay.hello.v1"}`, version, pub)
	sig, err := envelope.DecodeB64URL(f["sig"].(string))
	if err != nil || !ed25519.Verify(key.Public().(ed25519.PublicKey), []byte(want), sig) {
		t.Fatalf("the signature does not cover %s", want)
	}
	if f["type"] != "hello" || f["role"] != "supervisor" || f["key"] != pub || f["nonce"] != "NONCE" {
		t.Fatalf("frame %v", f)
	}
}

// relayFixture: a relay, a supervisor client and one paired device.
type relayFixture struct {
	t      *testing.T
	relay  *relaytest.Relay
	c      *relayClient
	devID  string
	devEnc *ecdh.PrivateKey
	cancel context.CancelFunc

	mu     sync.Mutex
	got    []string // "kind:plaintext" of delivered messages
	pairs  []string
	events []string
	accept bool
}

func newRelayFixture(t *testing.T) *relayFixture {
	x := &relayFixture{t: t, relay: relaytest.NewRelay(t), accept: true}
	_, key, _ := ed25519.GenerateKey(nil)
	enc, _ := ecdh.X25519().GenerateKey(rand.Reader)
	devPub, _, _ := ed25519.GenerateKey(nil)
	x.devID = envelope.DeviceID(devPub)
	x.devEnc, _ = ecdh.X25519().GenerateKey(rand.Reader)
	x.c = newRelayClient(x.relay.URL(), key, enc, relayHandlers{
		Devices: func() []string { return []string{x.devID} },
		PeerKey: func(id string) (*ecdh.PublicKey, bool) { return x.devEnc.PublicKey(), id == x.devID },
		Message: func(from, kind string, pt []byte, _ relaylink.Envelope) bool {
			x.mu.Lock()
			defer x.mu.Unlock()
			x.got = append(x.got, kind+":"+string(pt))
			return x.accept
		},
		Pair: func(_ []byte, _ string, e relaylink.Envelope) bool {
			x.mu.Lock()
			defer x.mu.Unlock()
			x.pairs = append(x.pairs, e.ID)
			return true
		},
		Event: func(ev string, _ map[string]any) {
			x.mu.Lock()
			defer x.mu.Unlock()
			x.events = append(x.events, ev)
		},
	})
	x.c.backoff = func(int) time.Duration { return 10 * time.Millisecond }
	x.c.rateEvery, x.c.rateRetry = time.Millisecond, 20*time.Millisecond // the pacing has its own test
	return x
}

func (x *relayFixture) start() {
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { x.c.run(ctx); close(done) }()
	x.cancel = cancel
	x.t.Cleanup(func() { cancel(); <-done })
	x.relay.Wait("resume")
}

// fromDevice builds a frame the way a device and the relay would: boxed for the supervisor.
func (x *relayFixture) fromDevice(kind, plaintext string) relaylink.Envelope {
	e := relaylink.Envelope{Type: "msg", ID: relaylink.MsgID(), To: x.c.id, From: x.devID, Seq: 1, Ts: time.Now().UnixMilli(), Exp: time.Now().Add(time.Minute).UnixMilli(), Kind: kind}
	key, err := relaylink.BoxKey(x.devEnc, x.c.enc.PublicKey(), x.c.id, x.devID)
	if err != nil {
		x.t.Fatal(err)
	}
	aad, _ := relaylink.AAD(e.ID, e.From, e.To, e.Kind, e.Exp)
	e.Body, _ = relaylink.Seal(key, nil, []byte(plaintext), aad)
	return e
}

func (x *relayFixture) snapshot() (got, events []string) {
	x.mu.Lock()
	defer x.mu.Unlock()
	return slices.Clone(x.got), slices.Clone(x.events)
}

func (x *relayFixture) hasEvent(name string) bool {
	_, ev := x.snapshot()
	return slices.Contains(ev, name)
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	for i := 0; i < 500; i++ {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timeout: %s", what)
}

func TestRelayConnectAndSend(t *testing.T) {
	x := newRelayFixture(t)
	if _, err := x.c.send(context.Background(), x.devID, "card", []byte("{}"), time.Now().Add(time.Minute)); !errors.Is(err, errRelayOffline) {
		t.Fatalf("send before the connection: %v", err)
	}
	x.start()
	x.relay.Mu.Lock()
	devs := slices.Clone(x.relay.Devices)
	x.relay.Mu.Unlock()
	if len(devs) != 1 || !slices.Equal(devs[0], []string{x.devID}) {
		t.Fatalf("devices sent: %v", devs)
	}
	exp := time.Now().Add(2 * time.Minute)
	id, err := x.c.send(context.Background(), x.devID, "card", []byte(`{"id":"wd-1"}`), exp)
	if err != nil {
		t.Fatal(err)
	}
	x.relay.Mu.Lock()
	e := x.relay.Stored[0]
	x.relay.Mu.Unlock()
	if e.ID != id || len(id) != 32 || e.To != x.devID || e.Kind != "card" || e.Exp != exp.UnixMilli() {
		t.Fatalf("stored frame %+v", e)
	}
	// the device opens it with its own key and the routing members as the relay forwards them
	key, _ := relaylink.BoxKey(x.devEnc, x.c.enc.PublicKey(), x.c.id, x.devID)
	aad, _ := relaylink.AAD(e.ID, x.c.id, e.To, e.Kind, e.Exp)
	if pt, err := relaylink.Open(key, e.Body, aad); err != nil || string(pt) != `{"id":"wd-1"}` {
		t.Fatalf("device side: %q %v", pt, err)
	}
	if strings.Contains(e.Body, "wd-1") {
		t.Fatal("plaintext in the body")
	}

	// a refusal of the relay is an error of send, never a silent success
	x.relay.Mu.Lock()
	x.relay.Refuse = "queue_full"
	x.relay.Mu.Unlock()
	var re *relaylink.Error
	if _, err := x.c.send(context.Background(), x.devID, "card", []byte("{}"), exp); !errors.As(err, &re) || re.Code != "queue_full" {
		t.Fatalf("refused send: %v", err)
	}
	if _, err := x.c.send(context.Background(), x.devID, "card", []byte("{}"), time.Now().Add(-time.Second)); !errors.As(err, &re) || re.Code != "expired" {
		t.Fatalf("expired send: %v", err)
	}
	if _, err := x.c.send(context.Background(), strings.Repeat("c", 64), "card", []byte("{}"), exp); err == nil {
		t.Fatal("send to a device without a key")
	}
	if _, err := x.c.send(context.Background(), x.devID, "card", bytes.Repeat([]byte("a"), relaylink.FrameMax), exp); !errors.As(err, &re) || re.Code != "too_large" {
		t.Fatalf("oversized send: %v", err)
	}
	if err := x.c.sendDevices(context.Background()); err != nil {
		t.Fatal(err)
	}
}

// An error frame goes to the request it names; one that names a frame nobody waits for to
// nobody; one that names nothing is given to no request and ends the connection.
func TestRelayErrorReference(t *testing.T) {
	x := newRelayFixture(t)
	wait := func(key string) chan relayResult {
		ch := make(chan relayResult, 1)
		x.c.waiters = append(x.c.waiters, relayWaiter{key: key, ch: ch})
		return ch
	}
	code := func(ch chan relayResult) string {
		select {
		case r := <-ch:
			return r.err.Error()
		default:
			return ""
		}
	}
	a, b, d := wait("msg:aa"), wait("msg:bb"), wait("devices")
	_ = x.c.handle(nil, &relaylink.Frame{Envelope: relaylink.Envelope{Type: "error", ID: "bb"}, Code: "queue_full"})
	_ = x.c.handle(nil, &relaylink.Frame{Envelope: relaylink.Envelope{Type: "error"}, Code: "not_recipient", What: "ack"})
	if code(a) != "" || code(b) != "relay: queue_full" || code(d) != "" {
		t.Fatal("an error with an id did not go to the frame it names")
	}
	_ = x.c.handle(nil, &relaylink.Frame{Envelope: relaylink.Envelope{Type: "error"}, Code: "ids_invalid", What: "devices"})
	if code(a) != "" || code(d) != "relay: ids_invalid" {
		t.Fatal("an error with what did not go to the request it names")
	}
	var re *relaylink.Error
	err := x.c.handle(nil, &relaylink.Frame{Envelope: relaylink.Envelope{Type: "error"}, Code: "expired"})
	if !errors.As(err, &re) || re.Code != "expired" || code(a) != "" || len(x.c.waiters) != 1 {
		t.Fatalf("an error without a reference: %v, waiters %d", err, len(x.c.waiters))
	}
}

// A burst of frames is spread out below the relay's limit instead of running into it, and a frame
// the relay still refuses as rate_limited goes out again: delayed, not lost.
func TestRelayPacesAndRetries(t *testing.T) {
	x := newRelayFixture(t)
	x.c.rateBurst, x.c.rateEvery = 4, 40*time.Millisecond
	x.start() // hello, devices, resume: three of the four tokens
	exp := time.Now().Add(time.Minute)
	start := time.Now()
	var wg sync.WaitGroup
	for i := 0; i < 6; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := x.c.send(context.Background(), x.devID, "card", []byte("{}"), exp); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	// one frame at once, five more at one per 40 ms
	if d := time.Since(start); d < 150*time.Millisecond {
		t.Fatalf("six frames with a budget of one went out in %v", d)
	}
	x.relay.Mu.Lock()
	x.relay.Refuse = "rate_limited"
	x.relay.Mu.Unlock()
	id, err := x.c.send(context.Background(), x.devID, "card", []byte("{}"), exp)
	if err != nil {
		t.Fatalf("a rate_limited frame was not sent again: %v", err)
	}
	x.relay.Mu.Lock()
	defer x.relay.Mu.Unlock()
	if n := len(x.relay.Stored); n != 7 || x.relay.Stored[6].ID != id {
		t.Fatalf("%d frames stored", n)
	}
	// a waiting request gives up with its context
	ctx, cancel := context.WithTimeout(context.Background(), time.Millisecond)
	defer cancel()
	x.c.mu.Lock()
	x.c.rateEvery, x.c.tokens = time.Hour, 0
	x.c.mu.Unlock()
	if err := x.c.pace(ctx, true); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("pace: %v", err)
	}
}

func TestRelayReceiveDedupeAndTamper(t *testing.T) {
	x := newRelayFixture(t)
	x.start()
	e := x.fromDevice("ticket", `{"deviceId":"d"}`)
	x.relay.Send(e)
	x.relay.Wait("ack:" + e.ID)
	x.relay.Send(e) // the relay delivers it again: acked again, handled once
	x.relay.Wait("ack:" + e.ID)
	if got, _ := x.snapshot(); !slices.Equal(got, []string{`ticket:{"deviceId":"d"}`}) {
		t.Fatalf("delivered %v", got)
	}

	// rewritten routing members, a body for another frame, an untrusted sender, a frame for
	// another supervisor, an expired frame: no handler, no ack
	bad := []relaylink.Envelope{}
	for i := 0; i < 6; i++ {
		bad = append(bad, x.fromDevice("ticket", `{"n":1}`))
	}
	bad[0].Exp += 1000
	bad[1].Kind = "status.req"
	bad[2].Body = bad[3].Body
	bad[3].From = strings.Repeat("e", 64)
	bad[4].To = strings.Repeat("f", 64)
	bad[5].Exp = time.Now().Add(-time.Second).UnixMilli()
	for _, b := range bad {
		x.relay.Send(b)
	}
	// a frame the handler refuses is not acked either
	x.mu.Lock()
	x.accept = false
	x.mu.Unlock()
	refused := x.fromDevice("ticket", `{"refused":true}`)
	x.relay.Send(refused)
	waitFor(t, "refused frame handled", func() bool { got, _ := x.snapshot(); return len(got) == 2 })
	x.mu.Lock()
	x.accept = true
	x.mu.Unlock()
	last := x.fromDevice("status.req", `{}`)
	x.relay.Send(last)
	x.relay.Wait("ack:" + last.ID)

	got, events := x.snapshot()
	if !slices.Equal(got, []string{`ticket:{"deviceId":"d"}`, `ticket:{"refused":true}`, `status.req:{}`}) {
		t.Fatalf("delivered %v", got)
	}
	x.relay.Mu.Lock()
	acks := slices.Clone(x.relay.Acks)
	x.relay.Mu.Unlock()
	if !slices.Equal(acks, []string{e.ID, e.ID, last.ID}) {
		t.Fatalf("acks %v", acks)
	}
	tamper, dropped := 0, 0
	for _, ev := range events {
		switch ev {
		case "relay_tamper":
			tamper++
		case "relay_dropped":
			dropped++
		}
	}
	if tamper != 3 || dropped != 3 {
		t.Fatalf("events %v", events)
	}

	// a pair frame names its own key in front of the box; opened with it, handed over, acked
	p := x.fromDevice("pair", `{}`)
	p.Type = "pair"
	p.Body = pairFrameBody(x.devEnc.PublicKey(), p.Body)
	nokey := x.fromDevice("pair", `{}`) // without the key in front: does not open, never acked
	nokey.Type = "pair"
	x.relay.Send(nokey)
	x.relay.Send(p)
	x.relay.Wait("ack:" + p.ID)
	x.mu.Lock()
	defer x.mu.Unlock()
	if !slices.Equal(x.pairs, []string{p.ID}) {
		t.Fatalf("pairs %v", x.pairs)
	}
}

func TestRelayReconnectResendsState(t *testing.T) {
	x := newRelayFixture(t)
	x.start()
	until := time.Now().Add(5 * time.Minute)
	if err := x.c.setPairing(context.Background(), until); err != nil {
		t.Fatal(err)
	}
	// queued while the supervisor is away: comes with the resume
	queued := x.fromDevice("ticket", `{"q":1}`)
	x.relay.Mu.Lock()
	x.relay.Queue = append(x.relay.Queue, queued)
	cur := x.relay.Cur
	x.relay.Mu.Unlock()
	cur.CloseWith(relayCloseSuperseded, "superseded")
	x.relay.Wait("ack:" + queued.ID)
	waitFor(t, "second hello", func() bool { return x.c.connected() && x.hasEvent("relay_disconnected") })

	x.relay.Mu.Lock()
	hellos, devs, pairing := x.relay.Hellos, len(x.relay.Devices), slices.Clone(x.relay.Pairing)
	x.relay.Mu.Unlock()
	if hellos != 2 || devs != 2 || !slices.Equal(pairing, []int64{until.UnixMilli(), until.UnixMilli()}) {
		t.Fatalf("hellos %d, devices %d, pairing %v", hellos, devs, pairing)
	}
	if got, _ := x.snapshot(); !slices.Equal(got, []string{`ticket:{"q":1}`}) {
		t.Fatalf("delivered %v", got)
	}
	if err := x.c.setPairing(context.Background(), time.Time{}); err != nil {
		t.Fatal(err)
	}
	x.relay.Mu.Lock()
	defer x.relay.Mu.Unlock()
	if x.relay.Pairing[len(x.relay.Pairing)-1] != 0 {
		t.Fatalf("pairing %v", x.relay.Pairing)
	}
}

func TestRelayHelloRefusedRetries(t *testing.T) {
	x := newRelayFixture(t)
	x.relay.Mu.Lock()
	x.relay.HelloErr = "bad_signature"
	x.relay.Mu.Unlock()
	x.start() // the first hello is refused, the second accepted
	if !x.hasEvent("relay_disconnected") {
		t.Fatal("no relay_disconnected after a refused hello")
	}
	x.relay.Mu.Lock()
	defer x.relay.Mu.Unlock()
	if x.relay.Hellos != 1 {
		t.Fatalf("hellos %d", x.relay.Hellos)
	}
}

func TestRelayBackoff(t *testing.T) {
	for attempt, top := range []time.Duration{time.Second, 2 * time.Second, 4 * time.Second, 8 * time.Second, 16 * time.Second, 32 * time.Second, time.Minute, time.Minute} {
		for i := 0; i < 50; i++ {
			if d := relayBackoff(attempt); d < top/2 || d > top {
				t.Fatalf("attempt %d: %v outside [%v, %v]", attempt, d, top/2, top)
			}
		}
	}
	if d := relayBackoff(1000); d > relayBackoffMax {
		t.Fatalf("%v", d)
	}
}

// The one test that talks to the deployed relay: WARDEN_RELAY_LIVE=1 go test -run TestRelayLive.
// A fresh random supervisor key, challenge, hello, welcome, the (empty) device list, clean close.
func TestRelayLive(t *testing.T) {
	if os.Getenv("WARDEN_RELAY_LIVE") != "1" {
		t.Skip("set WARDEN_RELAY_LIVE=1 to connect to the live relay")
	}
	base := os.Getenv("WARDEN_RELAY_URL")
	if base == "" {
		base = "wss://relay.wardenclaw.dev"
	}
	_, key, _ := ed25519.GenerateKey(nil)
	enc, _ := ecdh.X25519().GenerateKey(rand.Reader)
	c := newRelayClient(base, key, enc, relayHandlers{})
	ws, err := relaylink.Dial(context.Background(), c.endpoint(), http.Header{"User-Agent": {"wardend/" + version + " (test)"}}, relaylink.FrameMax)
	if err != nil {
		t.Fatal(err)
	}
	defer ws.Drop()
	if err := c.hello(ws); err != nil {
		t.Fatalf("hello: %v", err)
	}
	t.Logf("welcome: supervisor %s, frame limit %d, queue ttl %d ms", c.id, c.frame, c.ttl)
	read := func(want string) relaylink.Frame {
		ws.SetReadDeadline(time.Now().Add(10 * time.Second))
		for {
			raw, err := ws.ReadText()
			if err != nil {
				t.Fatalf("waiting for %s: %v", want, err)
			}
			var f relaylink.Frame
			_ = json.Unmarshal(raw, &f)
			t.Logf("relay: %s", raw)
			if f.Type == want {
				return f
			}
		}
	}
	if err := c.write(ws, map[string]any{"type": "devices", "ids": []string{}}); err != nil {
		t.Fatal(err)
	}
	if f := read("ack"); f.What != "devices" {
		t.Fatalf("ack %+v", f)
	}
	if err := c.write(ws, map[string]any{"type": "ping", "ts": time.Now().UnixMilli()}); err != nil {
		t.Fatal(err)
	}
	read("pong")
	if err := c.write(ws, map[string]any{"type": "resume"}); err != nil {
		t.Fatal(err)
	}
	if f := read("resumed"); f.Count != 0 {
		t.Fatalf("a fresh channel has %d queued frames", f.Count)
	}
	code, err := ws.CloseHandshake(relaylink.CloseNormal, "done", 10*time.Second)
	if err != nil {
		t.Fatalf("close: %v", err)
	}
	t.Logf("closed cleanly, relay answered with code %d", code)
}
