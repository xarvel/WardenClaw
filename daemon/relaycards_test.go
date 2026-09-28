// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"crypto/ed25519"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/xarvel/WardenClaw/daemon/envelope"
	"github.com/xarvel/WardenClaw/daemon/relaylink"
)

func (d relayDev) ticketFrame(s *supervisor, it *pendingItem, decision string) relaylink.Envelope {
	pt, _ := json.Marshal(ticket(d.device, it, decision, -1))
	return d.frame(s, "ticket", pt)
}

func pendingStays(t *testing.T, ch chan execOutcome) {
	t.Helper()
	select {
	case o := <-ch:
		t.Fatalf("the exec was decided: allow=%v reason=%q", o.allow, o.rec.Reason)
	case <-time.After(150 * time.Millisecond):
	}
}

// The whole path in one process: a supervisor on a (fake) relay and a device played by the test.
// The device pairs, is approved on the supervisor, gets a card, answers with a
// signed ticket; allow lets the gated command go, deny refuses it, a tampered box is no decision.
func TestRelayEndToEnd(t *testing.T) {
	s, relay := newRelaySupervisor(t)
	d := newRelayDev()

	// pairing
	ps, err := s.pairOpenRelay(0)
	if err != nil {
		t.Fatal(err)
	}
	relay.Send(d.pairFrame(s, ps["code"].(string), "phone"))
	st := d.next(t, s, relay, "pair.status", 0)
	if _, err := s.pairApprove(st["id"].(string)); err != nil {
		t.Fatal(err)
	}
	if st := d.next(t, s, relay, "pair.status", 1); st["status"] != "approved" {
		t.Fatalf("pair.status: %v", st)
	}

	// status.req → status with the (empty) pending list
	relay.Send(d.frame(s, "status.req", []byte(`{}`)))
	if st := d.next(t, s, relay, "status", 0); st["supervisorId"] != s.supervisorID || len(st["pending"].([]any)) != 0 || st["journal"] != nil {
		t.Fatalf("status: %v", st)
	}

	// a gated command: the card arrives, signed by the supervisor
	ch, it := startExec(t, s, 300, "ls", "/tmp")
	if it == nil {
		t.Fatal("the exec did not become pending")
	}
	card := d.next(t, s, relay, "card", 0)
	msg, _ := relaylink.CardSigningString(it.ID, it.Digest, it.CreatedAt, it.ExpiresAt)
	sig, _ := card["supervisorSig"].(string)
	if card["id"] != it.ID || card["digest"] != it.Digest || !envelope.VerifySig(s.key.Public().(ed25519.PublicKey), msg, sig) {
		t.Fatalf("card: %v", card)
	}

	// a tampered box (one flipped byte of the ciphertext): journaled, not acked, no decision
	bad := d.ticketFrame(s, it, "allow")
	raw, _ := envelope.DecodeB64URL(bad.Body)
	raw[len(raw)-1] ^= 1
	bad.Body = envelope.B64URL(raw)
	relay.Send(bad)
	waitFor(t, "relay_tamper in the journal", func() bool { return journalHas(s, "relay_tamper", bad.ID) })
	// an allow ticket of a device that is not trusted, and one device carrying another's ticket
	stranger := newRelayDev()
	relay.Send(stranger.ticketFrame(s, it, "allow"))
	waitFor(t, "relay_dropped in the journal", func() bool { return journalHas(s, "relay_dropped", stranger.id) })
	pt, _ := json.Marshal(ticket(stranger.device, it, "allow", -1))
	relay.Send(d.frame(s, "ticket", pt))
	if r := d.next(t, s, relay, "ticket.result", 0); r["ok"] != false || r["reason"] != "device_mismatch" {
		t.Fatalf("another device's ticket: %v", r)
	}
	// an expired frame
	old := d.ticketFrame(s, it, "allow")
	old.Exp = time.Now().Add(-time.Second).UnixMilli()
	relay.Send(old)
	pendingStays(t, ch)
	if relay.Acked(bad.ID) || relay.Acked(old.ID) {
		t.Fatal("a refused frame was acked")
	}

	// the signed allow ticket: the command goes on
	allow := d.ticketFrame(s, it, "allow")
	relay.Send(allow)
	if r := d.next(t, s, relay, "ticket.result", 1); r["ok"] != true || r["id"] != it.ID || r["decision"] != "allow" {
		t.Fatalf("ticket.result: %v", r)
	}
	if o := wait(t, ch); !o.allow {
		t.Fatalf("allow ticket: denied, %q", o.rec.Reason)
	}
	if done := d.next(t, s, relay, "card.done", 0); done["id"] != it.ID || done["outcome"] != "approved" {
		t.Fatalf("card.done: %v", done)
	}
	// the relay delivers the same frame again: acked again, handled once
	relay.Send(allow)
	// the same ticket in a new frame: the nonce is used up
	var again relaylink.Envelope
	{
		key, _ := relaylink.BoxKey(d.enc, s.relay.enc.PublicKey(), s.supervisorID, d.id)
		aad, _ := relaylink.AAD(allow.ID, allow.From, allow.To, allow.Kind, allow.Exp)
		tpt, _ := relaylink.Open(key, allow.Body, aad)
		again = d.frame(s, "ticket", tpt)
	}
	relay.Send(again)
	if r := d.next(t, s, relay, "ticket.result", 2); r["ok"] != false || r["reason"] != "nonce_reused" {
		t.Fatalf("a replayed ticket: %v (a second result for the redelivered frame?)", r)
	}

	// deny
	ch, it = startExec(t, s, 301, "ls", "/")
	if it == nil {
		t.Fatal("the second exec did not become pending")
	}
	if card := d.next(t, s, relay, "card", 1); card["id"] != it.ID {
		t.Fatalf("second card: %v", card)
	}
	relay.Send(d.ticketFrame(s, it, "deny"))
	if o := wait(t, ch); o.allow || o.errno != unix.EPERM {
		t.Fatalf("deny ticket: allow=%v errno=%v", o.allow, o.errno)
	}
	if done := d.next(t, s, relay, "card.done", 1); done["id"] != it.ID || done["outcome"] != "denied" {
		t.Fatalf("card.done: %v", done)
	}
	if r := d.next(t, s, relay, "ticket.result", 3); r["ok"] != true || r["decision"] != "deny" {
		t.Fatalf("ticket.result of the deny: %v", r)
	}
	// four tickets were handled (another device's, allow, the replay, deny): the redelivered
	// frame was acked twice and answered once
	relay.Mu.Lock()
	defer relay.Mu.Unlock()
	results, acks := 0, 0
	for _, e := range relay.Stored {
		if e.Kind == "ticket.result" {
			results++
		}
	}
	for _, id := range relay.Acks {
		if id == allow.ID {
			acks++
		}
	}
	if results != 4 || acks != 2 {
		t.Fatalf("%d ticket results, %d acks of the redelivered frame", results, acks)
	}
}

// A status with a long queue of large cards still fits a relay frame: the list is cut, the count
// is not, and the cards left out follow as frames of their own.
func TestRelayStatusFitsFrame(t *testing.T) {
	d := newRelayDev()
	s, relay := newRelaySupervisor(t, d)
	const n = 12
	long := strings.Repeat("a", 6000)
	for i := 0; i < n; i++ {
		if _, it := startExec(t, s, 400+i, "ls", long); it == nil {
			t.Fatal("the exec did not become pending")
		}
	}
	countCards := func() int {
		relay.Mu.Lock()
		defer relay.Mu.Unlock()
		c := 0
		for _, e := range relay.Stored {
			if e.Kind == "card" {
				c++
			}
		}
		return c
	}
	waitFor(t, "the cards on the relay", func() bool { return countCards() == n })
	s.relayStatus(d.id)
	st := d.next(t, s, relay, "status", 1) // 0 was sent after the connect
	listed := len(st["pending"].([]any))
	if st["pendingCount"] != float64(n) || st["pendingTruncated"] != true || listed == 0 || listed >= n {
		t.Fatalf("status: pendingCount %v, truncated %v, %d cards listed", st["pendingCount"], st["pendingTruncated"], listed)
	}
	waitFor(t, "the cards left out, as frames", func() bool { return countCards() == n+n-listed })
	relay.Mu.Lock()
	for _, e := range relay.Stored {
		if b, _ := json.Marshal(e); len(b) > relaylink.FrameMax {
			t.Errorf("a %s frame of %d bytes", e.Kind, len(b))
		} else if e.Kind == "status" {
			t.Logf("status frame: %d bytes, %d of %d cards listed", len(b), listed, n)
		}
	}
	relay.Mu.Unlock()
	_, items := s.q.snapshot()
	for _, it := range items {
		s.q.resolve(it.ID, ticketResult{Reason: "test over"})
	}
}

// A ticket frame the relay delivers again after wardend restarted (the ack was lost; the nonce
// cache and the dedupe set of the old process are gone) is not a second decision: the card it
// names is not pending in the new process, and the same command asked again is another card.
func TestRelayTicketRedeliveredAfterRestart(t *testing.T) {
	d := newRelayDev()
	s1, relay1 := newRelaySupervisor(t, d)
	// after every connect the device gets the state without asking
	if st := d.next(t, s1, relay1, "status", 0); st["supervisorId"] != s1.supervisorID || st["pendingCount"] != float64(0) {
		t.Fatalf("status after connect: %v", st)
	}
	ch, it := startExec(t, s1, 300, "ls", "/tmp")
	if it == nil {
		t.Fatal("the exec did not become pending")
	}
	pt, _ := json.Marshal(ticket(d.device, it, "allow", -1))
	relay1.Send(d.frame(s1, "ticket", pt))
	if o := wait(t, ch); !o.allow {
		t.Fatalf("allow ticket: denied, %q", o.rec.Reason)
	}

	// "restart": a new supervisor process state with the same keys and the same trusted device
	s2, relay2 := newRelaySupervisorWith(t, func(s *supervisor) {
		s.key, s.supervisorID = s1.key, s1.supervisorID
		k, _ := os.ReadFile(s1.cfg.RelayKeyFile)
		if err := os.WriteFile(s.cfg.RelayKeyFile, k, 0o600); err != nil {
			t.Fatal(err)
		}
	}, d)
	ch2, it2 := startExec(t, s2, 300, "ls", "/tmp") // the agent asks for the same command again
	if it2 == nil {
		t.Fatal("the exec did not become pending")
	}
	if it2.ID == it.ID || it2.Digest == it.Digest {
		t.Fatal("the same command got the same card after a restart")
	}
	relay2.Send(d.frame(s2, "ticket", pt)) // the old ticket, delivered again
	waitFor(t, "the redelivered ticket refused", func() bool { return journalHas(s2, "decide_reject", "unknown_pending") })
	pendingStays(t, ch2)
	if n := s2.m.ticketsOK.Load(); n != 0 {
		t.Fatalf("ticketsOK = %d after a redelivered ticket", n)
	}
	s2.q.resolve(it2.ID, ticketResult{Reason: "test over"})
	wait(t, ch2)
}

// wardend answers a status.req of a trusted device only: a device takes a status as the proof
// that its pairing was approved. A relay that forwards the frame of a stranger, or of a device
// whose request is still pending, gets nothing back for it.
func TestRelayStatusOnlyForTrusted(t *testing.T) {
	s, relay := newRelaySupervisor(t)
	stranger, waiting := newRelayDev(), newRelayDev()
	ps, err := s.pairOpenRelay(0)
	if err != nil {
		t.Fatal(err)
	}
	relay.Send(waiting.pairFrame(s, ps["code"].(string), "phone"))
	if st := waiting.next(t, s, relay, "pair.status", 0); st["status"] != "pending" {
		t.Fatalf("pair.status: %v", st)
	}
	relay.Send(stranger.frame(s, "status.req", []byte(`{}`)))
	relay.Send(waiting.frame(s, "status.req", []byte(`{}`)))
	time.Sleep(300 * time.Millisecond)
	relay.Mu.Lock()
	defer relay.Mu.Unlock()
	for _, e := range relay.Stored {
		if e.To == stranger.id || e.Kind != "pair.status" {
			t.Fatalf("an untrusted device got a %s frame", e.Kind)
		}
	}
}
