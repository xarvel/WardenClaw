// SPDX-License-Identifier: AGPL-3.0-or-later

package relaytest

import (
	"bytes"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/xarvel/WardenClaw/daemon/envelope"
	"github.com/xarvel/WardenClaw/daemon/relaylink"
)

var sidRe = regexp.MustCompile(`^[0-9a-f]{64}$`)

// Relay is an in-process relay that follows relay/src/channel.ts: hello, devices, pairing window,
// routing, acks, queues and resume. The exported members are what the tests look at, under Mu.
type Relay struct {
	t   *testing.T
	srv *httptest.Server

	Mu       sync.Mutex
	Cur      *Conn
	Hellos   int
	Devices  [][]string
	Pairing  []int64
	Stored   []relaylink.Envelope // msg frames the supervisor sent
	Acks     []string             // ids the supervisor acked
	Queue    []relaylink.Envelope // undelivered frames for the supervisor (resume)
	Refuse   string               // error code for the next msg from the supervisor
	HelloErr string               // error code for the next hello
	Events   chan string

	devs     map[string][]*Conn // connected devices; one device may hold several connections
	devAcked map[string]bool    // ids of stored frames a device acked
	seq      int64              // sequence numbers of frames from devices
}

// NewRelay starts a relay on a loopback port; it stops with the test.
func NewRelay(t *testing.T) *Relay {
	f := &Relay{t: t, Events: make(chan string, 256), devs: map[string][]*Conn{}, devAcked: map[string]bool{}}
	f.srv = httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.srv.Close)
	return f
}

// NewTLSRelay starts a relay that speaks TLS (wss://127.0.0.1:port), for the programs that take
// a relay from a pairing link, which names wss:// only. A client trusts it through CertFile.
func NewTLSRelay(t *testing.T) *Relay {
	f := &Relay{t: t, Events: make(chan string, 256), devs: map[string][]*Conn{}, devAcked: map[string]bool{}}
	f.srv = httptest.NewTLSServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.srv.Close)
	return f
}

// CertFile writes the certificate of a TLS relay as PEM into dir and returns the path: the value
// of SSL_CERT_FILE for a process that has to trust this relay.
func (f *Relay) CertFile(dir string) string {
	f.t.Helper()
	p := filepath.Join(dir, "relay-cert.pem")
	b := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: f.srv.Certificate().Raw})
	if err := os.WriteFile(p, b, 0o600); err != nil {
		f.t.Fatal(err)
	}
	return p
}

// URL is the base address of the relay (ws://127.0.0.1:port, wss:// for a TLS relay).
func (f *Relay) URL() string { return "ws" + strings.TrimPrefix(f.srv.URL, "http") }

// peer tells every connected device whether the supervisor is connected.
func (f *Relay) peer(online bool) {
	b, _ := json.Marshal(map[string]any{"type": "peer", "online": online})
	f.Mu.Lock()
	defer f.Mu.Unlock()
	for _, conns := range f.devs {
		for _, d := range conns {
			d.Text(string(b))
		}
	}
}

func (f *Relay) emit(s string) {
	select {
	case f.Events <- s:
	default:
	}
}

// Wait blocks until the relay saw the event.
func (f *Relay) Wait(name string) {
	f.t.Helper()
	deadline := time.After(5 * time.Second)
	for {
		select {
		case e := <-f.Events:
			if e == name {
				return
			}
		case <-deadline:
			f.t.Fatalf("relay: no %q", name)
		}
	}
}

// Send writes a frame to the connected supervisor, as the relay forwards one.
func (f *Relay) Send(v any) {
	b, _ := json.Marshal(v)
	f.Mu.Lock()
	c := f.Cur
	f.Mu.Unlock()
	if c != nil {
		c.Text(string(b))
	}
}

func (f *Relay) serve(w http.ResponseWriter, r *http.Request) {
	sid, ok := strings.CutPrefix(r.URL.Path, "/v1/ws/")
	if !ok || !sidRe.MatchString(sid) {
		http.Error(w, `{"ok":false,"reason":"not_found"}`, http.StatusNotFound)
		return
	}
	s := Accept(f.t, w, r)
	if s == nil {
		return
	}
	defer s.Close()
	send := func(v any) { b, _ := json.Marshal(v); s.Text(string(b)) }
	fail := func(code string) {
		send(map[string]any{"type": "error", "code": code, "close": true})
		s.CloseWith(4002, code)
	}
	nonce := envelope.NewNonce()
	send(map[string]any{"type": "challenge", "nonce": nonce, "ts": time.Now().UnixMilli()})
	authed := false
	for {
		op, p, err := s.Read()
		if err != nil || op == OpClose {
			return
		}
		if op != OpText {
			continue
		}
		dec := json.NewDecoder(bytes.NewReader(p))
		dec.UseNumber()
		var m map[string]any
		if dec.Decode(&m) != nil {
			fail("frame_invalid")
			return
		}
		typ, _ := m["type"].(string)
		if !authed {
			if typ != "hello" {
				fail("hello_expected")
				return
			}
			f.Mu.Lock()
			code := f.HelloErr
			f.HelloErr = ""
			f.Mu.Unlock()
			if code == "" {
				code = f.checkHello(m, nonce, sid)
			}
			if code != "" {
				fail(code)
				return
			}
			if m["role"] == "device" {
				pub, _ := envelope.DecodeKey(m["key"].(string))
				id := envelope.DeviceID(pub)
				send(map[string]any{"type": "welcome", "id": id, "role": "device", "protocol": 1, "ts": time.Now().UnixMilli(), "limits": map[string]any{"frame": 65536, "queue": 200, "ttl": 86400000}})
				f.Mu.Lock()
				online := f.Cur != nil
				f.Mu.Unlock()
				send(map[string]any{"type": "peer", "online": online})
				f.serveDevice(s, sid, id)
				return
			}
			authed = true
			f.Mu.Lock()
			f.Cur = s
			f.Hellos++
			f.Mu.Unlock()
			defer func() {
				f.Mu.Lock()
				gone := f.Cur == s
				if gone {
					f.Cur = nil
				}
				f.Mu.Unlock()
				if gone {
					f.peer(false)
				}
			}()
			f.peer(true)
			send(map[string]any{"type": "welcome", "id": sid, "role": "supervisor", "protocol": 1, "ts": time.Now().UnixMilli(), "limits": map[string]any{"frame": 65536, "queue": 200, "ttl": 86400000}})
			f.emit("welcome")
			continue
		}
		switch typ {
		case "ping":
			send(map[string]any{"type": "pong", "ts": time.Now().UnixMilli()})
			f.emit("ping")
		case "devices":
			var ids []string
			for _, x := range m["ids"].([]any) {
				ids = append(ids, x.(string))
			}
			f.Mu.Lock()
			f.Devices = append(f.Devices, ids)
			f.Mu.Unlock()
			send(map[string]any{"type": "ack", "what": "devices", "count": len(ids)})
			f.emit("devices")
		case "pairing":
			var until int64
			if m["open"] == true {
				until, _ = m["until"].(json.Number).Int64()
			}
			f.Mu.Lock()
			f.Pairing = append(f.Pairing, until)
			f.Mu.Unlock()
			send(map[string]any{"type": "ack", "what": "pairing", "until": until})
			f.emit("pairing")
		case "msg":
			var e relaylink.Envelope
			_ = json.Unmarshal(p, &e)
			f.Mu.Lock()
			code := f.Refuse
			f.Refuse = ""
			if code == "" && e.Exp <= time.Now().UnixMilli() {
				code = "expired"
			}
			if code == "" {
				e.From, e.Seq = sid, int64(len(f.Stored)+1)
				f.Stored = append(f.Stored, e)
			}
			devs := slices.Clone(f.devs[e.To])
			f.Mu.Unlock()
			if code == "" {
				b, _ := json.Marshal(e)
				for _, dev := range devs {
					dev.Text(string(b))
				}
			}
			if code != "" {
				send(map[string]any{"type": "error", "code": code, "id": e.ID, "close": false})
			} else {
				send(map[string]any{"type": "ack", "id": e.ID, "seq": e.Seq})
			}
			f.emit("msg")
		case "ack":
			id, _ := m["id"].(string)
			f.Mu.Lock()
			f.Acks = append(f.Acks, id)
			f.Queue = slices.DeleteFunc(f.Queue, func(e relaylink.Envelope) bool { return e.ID == id })
			f.Mu.Unlock()
			f.emit("ack:" + id)
		case "resume":
			f.Mu.Lock()
			q := slices.Clone(f.Queue)
			f.Mu.Unlock()
			for _, e := range q {
				send(e)
			}
			send(map[string]any{"type": "resumed", "count": len(q)})
			f.emit("resume")
		}
	}
}

// serveDevice is the device side of envelopeFrame, ackFrame and resumeFrame of channel.ts: a pair
// frame needs an open pairing window, a msg a device on the supervisor's last list; an accepted
// frame is acked, queued for the supervisor and forwarded if it is connected.
func (f *Relay) serveDevice(s *Conn, sid, id string) {
	send := func(v any) { b, _ := json.Marshal(v); s.Text(string(b)) }
	f.Mu.Lock()
	f.devs[id] = append(f.devs[id], s)
	f.Mu.Unlock()
	defer func() {
		f.Mu.Lock()
		f.devs[id] = slices.DeleteFunc(f.devs[id], func(c *Conn) bool { return c == s })
		f.Mu.Unlock()
	}()
	for {
		op, p, err := s.Read()
		if err != nil || op == OpClose {
			return
		}
		var fr relaylink.Frame
		if op != OpText || json.Unmarshal(p, &fr) != nil {
			continue
		}
		switch fr.Type {
		case "ping":
			send(map[string]any{"type": "pong", "ts": time.Now().UnixMilli()})
		case "msg", "pair":
			e, now, code := fr.Envelope, time.Now().UnixMilli(), ""
			f.Mu.Lock()
			switch {
			case e.To != sid:
				code = "to_invalid"
			case e.Exp <= now:
				code = "expired"
			case e.Type == "pair" && (len(f.Pairing) == 0 || f.Pairing[len(f.Pairing)-1] <= now):
				code = "pairing_closed"
			case e.Type == "msg" && (len(f.Devices) == 0 || !slices.Contains(f.Devices[len(f.Devices)-1], id)):
				code = "not_trusted"
			}
			var sup *Conn
			if code == "" {
				f.seq++
				e.From, e.Seq = id, f.seq
				if e.Type == "pair" {
					e.Kind = "pair"
				}
				f.Queue = append(f.Queue, e)
				sup = f.Cur
			}
			f.Mu.Unlock()
			if code != "" {
				send(map[string]any{"type": "error", "code": code, "id": e.ID, "close": false})
				continue
			}
			send(map[string]any{"type": "ack", "id": e.ID, "seq": e.Seq})
			if sup != nil {
				b, _ := json.Marshal(e)
				sup.Text(string(b))
			}
		case "ack":
			f.Mu.Lock()
			f.devAcked[fr.ID] = true
			f.Mu.Unlock()
		case "resume":
			f.Mu.Lock()
			var q []relaylink.Envelope
			for _, e := range f.Stored {
				if e.To == id && !f.devAcked[e.ID] {
					q = append(q, e)
				}
			}
			f.Mu.Unlock()
			for _, e := range q {
				send(e)
			}
			send(map[string]any{"type": "resumed", "count": len(q)})
		}
	}
}

// checkHello is the hello() of channel.ts: the id, the nonce, the timestamp, the signature.
func (f *Relay) checkHello(m map[string]any, nonce, sid string) string {
	if m["role"] != "supervisor" && m["role"] != "device" {
		return "role_invalid"
	}
	key, _ := m["key"].(string)
	pub, err := envelope.DecodeKey(key)
	if err != nil {
		return "key_invalid"
	}
	if m["nonce"] != nonce {
		return "challenge_invalid"
	}
	ts, _ := m["ts"].(json.Number).Int64()
	if d := time.Now().UnixMilli() - ts; d > 120_000 || d < -120_000 {
		return "stale_timestamp"
	}
	msg, err := envelope.Canonical(map[string]any{"type": "wardenclaw.relay.hello.v1", "role": m["role"], "key": m["key"], "enc": m["enc"], "ts": m["ts"], "nonce": m["nonce"], "client": m["client"]})
	sig, _ := m["sig"].(string)
	if err != nil || !envelope.VerifySig(pub, msg, sig) {
		return "bad_signature"
	}
	if m["role"] == "supervisor" && envelope.DeviceID(pub) != sid {
		return "not_this_channel"
	}
	return ""
}

// Acked: the supervisor acked the frame with this id.
func (f *Relay) Acked(id string) bool {
	f.Mu.Lock()
	defer f.Mu.Unlock()
	return slices.Contains(f.Acks, id)
}
