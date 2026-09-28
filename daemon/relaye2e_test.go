// SPDX-License-Identifier: AGPL-3.0-or-later

package main

// The relay path over real sockets: a supervisor and a device that both connect to a relay, the
// in-process fake one or (WARDEN_RELAY_LIVE=1) the deployed one. The same scenario runs on both.

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"os"
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/xarvel/WardenClaw/daemon/envelope"
	"github.com/xarvel/WardenClaw/daemon/relaylink"
)

// relayDevConn is a device connected to a relay: a relaylink.Session, the code wardenctl runs,
// and everything that arrived on it in the order of arrival.
type relayDevConn struct {
	t    *testing.T
	sess *relaylink.Session
	done chan struct{}

	mu     sync.Mutex
	frames []relaylink.Message
	taken  []bool
}

// dial connects the device to the channel of supervisor s on the relay at base.
func (d relayDev) dial(t *testing.T, s *supervisor, base string) *relayDevConn {
	t.Helper()
	sess, err := d.link(s).Connect(context.Background(), base)
	if err != nil {
		t.Fatalf("device dial: %v", err)
	}
	c := &relayDevConn{t: t, sess: sess, done: make(chan struct{})}
	go c.collect()
	t.Cleanup(c.close)
	return c
}

func (c *relayDevConn) collect() {
	defer close(c.done)
	for m := range c.sess.Messages() {
		c.mu.Lock()
		c.frames = append(c.frames, m)
		c.taken = append(c.taken, false)
		c.mu.Unlock()
	}
}

func (c *relayDevConn) close() {
	c.sess.Close()
	<-c.done
}

// take waits for the first message not taken yet that ok accepts; it returns the message and
// its position in the order of arrival.
func (c *relayDevConn) take(what string, ok func(relaylink.Message) bool) (relaylink.Message, int) {
	c.t.Helper()
	for i := 0; i < 1000; i++ {
		c.mu.Lock()
		for n, f := range c.frames {
			if !c.taken[n] && ok(f) {
				c.taken[n] = true
				c.mu.Unlock()
				return f, n
			}
		}
		c.mu.Unlock()
		time.Sleep(10 * time.Millisecond)
	}
	c.t.Fatalf("device: timeout waiting for %s", what)
	return relaylink.Message{}, 0
}

// send hands an envelope to the relay and returns its answer as a frame: an ack, or an error
// with the relay's code.
func (c *relayDevConn) send(e relaylink.Envelope) relaylink.Frame {
	c.t.Helper()
	err := c.sess.Send(context.Background(), e)
	var re *relaylink.Error
	switch {
	case err == nil:
		return relaylink.Frame{Envelope: relaylink.Envelope{Type: "ack", ID: e.ID}}
	case errors.As(err, &re):
		return relaylink.Frame{Envelope: relaylink.Envelope{Type: "error"}, Code: re.Code}
	}
	c.t.Fatalf("device: the relay's answer to %s: %v", e.Kind, err)
	return relaylink.Frame{}
}

// msg waits for the next message of this kind from the supervisor.
func (c *relayDevConn) msg(kind string) (map[string]any, int) {
	c.t.Helper()
	m, n := c.take(kind+" from the supervisor", func(m relaylink.Message) bool { return m.Kind == kind })
	var v map[string]any
	if err := json.Unmarshal(m.Body, &v); err != nil {
		c.t.Fatalf("%s plaintext %q: %v", kind, m.Body, err)
	}
	return v, n
}

// relayScenario is the whole relay path with a device on its own socket: the relay's refusals for
// a stranger, pairing, approve, a card and an allow ticket, a card and a deny ticket, a card
// queued while the device is away and delivered with its resume.
func relayScenario(t *testing.T, s *supervisor, base string) {
	sid := s.supervisorID
	d := newRelayDev()

	// a device nobody knows: the relay refuses its frames before the supervisor sees them
	x := newRelayDev()
	xc := x.dial(t, s, base)
	if f := xc.send(x.pairFrame(s, "ABCD2345", "stranger")); f.Type != "error" || f.Code != "pairing_closed" {
		t.Fatalf("pair frame without a window: %+v", f)
	}
	if f := xc.send(x.frame(s, "status.req", []byte(`{}`))); f.Type != "error" || f.Code != "not_trusted" {
		t.Fatalf("msg of an untrusted device: %+v", f)
	}
	t.Logf("stranger %s: pair → pairing_closed, msg → not_trusted", x.id[:8])

	// pairing
	ps, err := s.pairOpenRelay(0) // the fake relay is ws://127.0.0.1: pairStart gives no link for it
	if err != nil {
		t.Fatal(err)
	}
	dc := d.dial(t, s, base)
	if f := dc.send(d.pairFrame(s, ps["code"].(string), "phone")); f.Type != "ack" {
		t.Fatalf("pair frame in the window: %+v", f)
	}
	st, _ := dc.msg("pair.status")
	if st["status"] != "pending" || st["fingerprint"] != envelope.Fingerprint(d.id) {
		t.Fatalf("pair.status: %v", st)
	}
	t.Logf("device %s: pair accepted by the relay, pair.status %v", d.id[:8], st["status"])
	if f := dc.send(d.frame(s, "status.req", []byte(`{}`))); f.Type != "error" || f.Code != "not_trusted" {
		t.Fatalf("msg before approve: %+v", f)
	}
	if _, err := s.pairApprove(st["id"].(string)); err != nil {
		t.Fatal(err)
	}
	if st, _ := dc.msg("pair.status"); st["status"] != "approved" {
		t.Fatalf("pair.status after approve: %v", st)
	}
	// trusted now: the device list reaches the relay a moment after the approval
	for i := 0; ; i++ {
		f := dc.send(d.frame(s, "status.req", []byte(`{}`)))
		if f.Type == "ack" {
			break
		}
		if f.Code != "not_trusted" || i >= 10 {
			t.Fatalf("status.req after approve: %+v", f)
		}
		time.Sleep(200 * time.Millisecond)
	}
	if st, _ := dc.msg("status"); st["supervisorId"] != sid {
		t.Fatalf("status: %v", st)
	}
	t.Logf("approved: the relay takes the device's frames, status answered")

	// a gated command: card, allow ticket, the command goes on
	ch, it := startExec(t, s, 300, "ls", "/tmp")
	if it == nil {
		t.Fatal("the exec did not become pending")
	}
	card, _ := dc.msg("card")
	msg, _ := relaylink.CardSigningString(it.ID, it.Digest, it.CreatedAt, it.ExpiresAt)
	sig, _ := card["supervisorSig"].(string)
	if card["id"] != it.ID || card["digest"] != it.Digest || !envelope.VerifySig(s.key.Public().(ed25519.PublicKey), msg, sig) {
		t.Fatalf("card: %v", card)
	}
	if f := dc.send(d.ticketFrame(s, it, "allow")); f.Type != "ack" {
		t.Fatalf("ticket frame: %+v", f)
	}
	if o := wait(t, ch); !o.allow {
		t.Fatalf("allow ticket: denied, %q", o.rec.Reason)
	}
	if r, _ := dc.msg("ticket.result"); r["ok"] != true || r["decision"] != "allow" {
		t.Fatalf("ticket.result: %v", r)
	}
	if done, _ := dc.msg("card.done"); done["id"] != it.ID || done["outcome"] != "approved" {
		t.Fatalf("card.done: %v", done)
	}
	t.Logf("card %s: allow ticket, the command went on, card.done approved", it.ID)

	// deny
	ch, it = startExec(t, s, 301, "ls", "/")
	if it == nil {
		t.Fatal("the second exec did not become pending")
	}
	if card, _ := dc.msg("card"); card["id"] != it.ID {
		t.Fatalf("second card: %v", card)
	}
	dc.send(d.ticketFrame(s, it, "deny"))
	if o := wait(t, ch); o.allow || o.errno != unix.EPERM {
		t.Fatalf("deny ticket: allow=%v errno=%v", o.allow, o.errno)
	}
	if done, _ := dc.msg("card.done"); done["id"] != it.ID || done["outcome"] != "denied" {
		t.Fatalf("card.done: %v", done)
	}
	t.Logf("card %s: deny ticket, EPERM, card.done denied", it.ID)

	// the device goes away; a card for it waits on the relay and comes with the resume
	time.Sleep(300 * time.Millisecond) // the acks of the last frames
	dc.close()
	// the pairing and two cards used up the supervisor's outgoing budget (pace): wait until a
	// frame goes out at once again, so the card below is on the relay before the device is back
	began := time.Now()
	for {
		r := s.relay
		r.mu.Lock()
		have := min(r.rateBurst, r.tokens+float64(r.now().Sub(r.refilled))/float64(r.rateEvery))
		r.mu.Unlock()
		if have >= 2 {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Logf("outgoing budget back after %v", time.Since(began).Round(100*time.Millisecond))
	ch, it = startExec(t, s, 302, "ls", "/var")
	if it == nil {
		t.Fatal("the third exec did not become pending")
	}
	time.Sleep(time.Second) // the card is on the relay, nobody to deliver it to
	dc = d.dial(t, s, base)
	if err := dc.sess.Resume(); err != nil {
		t.Fatal(err)
	}
	at := -1
	for at < 0 {
		card, n := dc.msg("card")
		if card["id"] == it.ID {
			at = n
		}
	}
	res, n := dc.take("resumed", func(m relaylink.Message) bool { return m.Frame.Type == "resumed" })
	if at > n || res.Frame.Count < 1 {
		t.Fatalf("the queued card came at %d, resumed (count %d) at %d", at, res.Frame.Count, n)
	}
	dc.send(d.ticketFrame(s, it, "deny"))
	if o := wait(t, ch); o.allow {
		t.Fatal("deny ticket after the resume: allowed")
	}
	t.Logf("card %s: queued while the device was offline, delivered by resume (%d queued), denied", it.ID, res.Frame.Count)
}

// The scenario over two real sockets and the in-process relay, which routes like relay/src.
func TestRelayEndToEndSockets(t *testing.T) {
	s, relay := newRelaySupervisor(t)
	relayScenario(t, s, relay.URL())
}

// The scenario through the deployed relay: WARDEN_RELAY_LIVE=1 go test -run TestRelayLiveEndToEnd.
// Fresh random keys on both sides, a handful of connections and frames.
func TestRelayLiveEndToEnd(t *testing.T) {
	if os.Getenv("WARDEN_RELAY_LIVE") != "1" {
		t.Skip("set WARDEN_RELAY_LIVE=1 to run through the live relay")
	}
	base := os.Getenv("WARDEN_RELAY_URL")
	if base == "" {
		base = "wss://relay.wardenclaw.dev"
	}
	s := startRelaySupervisor(t, base, nil)
	t.Logf("supervisor %s connected to %s", s.supervisorID, base)
	relayScenario(t, s, base)
}
