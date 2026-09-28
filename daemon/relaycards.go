// SPDX-License-Identifier: AGPL-3.0-or-later

package main

// Cards and tickets over the relay (protocol/README.md section 11).
//
//	supervisor → device: card (a pending item with supervisorSig), card.done {id, outcome},
//	                     status (the state plus the full pending list), ticket.result
//	device → supervisor: ticket (the signed decision), status.req {}
//
// A ticket from the relay goes through decideTicket, the same verification as on the unix
// socket: device signature, timestamp window, one-time nonce, the pending id and its
// digest. The relay adds no trust: it only has to deliver. Whatever does not arrive, does not
// open or does not verify is no decision, and the card expires on the daemon as it always did.
//
// Replay. The relay may deliver a ticket twice. Inside one process the frame id is deduped by
// the client (relay.go, seen) and the ticket nonce by s.nonces. After a restart of wardend both
// are empty, and what protects is the card state: a ticket names a pending id and its digest
// (envelope.Verify: unknown_pending, digest_mismatch), the pending queue does not survive a
// restart, and a repeated exec of the same command gets a new envelope nonce, hence a new id and
// digest. An old ticket can never match a card of the new process.

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"time"

	"github.com/xarvel/WardenClaw/daemon/envelope"
	"github.com/xarvel/WardenClaw/daemon/relaylink"
)

const (
	relayReplyTTL  = 10 * time.Minute // how long a status, ticket.result or card.done may wait on the relay
	relayDoneAllow = "approved"
	relayDoneDeny  = "denied"
	relayDoneTTL   = "expired"
	relayDoneOther = "superseded" // closed without a decision of a device (client gone, shutdown)
)

// relayCardOf: a pending item as a device gets it, with the supervisor's signature over its
// identity, so the card can be shown and journaled with a signature that does not depend on the
// channel.
func (s *supervisor) relayCardOf(it *pendingItem) map[string]any {
	msg, _ := relaylink.CardSigningString(it.ID, it.Digest, it.CreatedAt, it.ExpiresAt)
	return map[string]any{"id": it.ID, "kind": it.Kind, "digest": it.Digest, "envelope": it.Envelope, "meta": it.Meta,
		"createdAt": it.CreatedAt, "expiresAt": it.ExpiresAt, "supervisorSig": envelope.B64URL(ed25519.Sign(s.key, msg))}
}

// relaySend boxes v for one device, from its own goroutine (it waits for the relay's ack, and
// the callers are the exec path and the relay's reading goroutine). A failure is logged, never a
// decision: the device learns the state with its next status.
func (s *supervisor) relaySend(deviceID, kind string, v any, exp time.Time) {
	if s.relay == nil {
		return
	}
	b, err := json.Marshal(v)
	if err != nil {
		s.logf("wardend: relay: %s: %v\n", kind, err)
		return
	}
	end := s.relay.begin()
	s.goSafe("relay-"+kind, func() {
		defer end()
		if _, err := s.relay.send(context.Background(), deviceID, kind, b, exp); err != nil && err != errRelayOffline {
			s.logf("wardend: relay: %s to %s: %v\n", kind, shortID(deviceID), err)
		}
	})
}

// relayCard sends a new pending item to every device on the relay.
func (s *supervisor) relayCard(it *pendingItem) {
	if s.relay == nil {
		return
	}
	card := s.relayCardOf(it)
	for _, id := range s.relayDevices() {
		s.relaySend(id, "card", card, time.UnixMilli(it.ExpiresAt))
	}
}

// relayCardDone tells the devices that a card is closed.
func (s *supervisor) relayCardDone(it *pendingItem, res ticketResult) {
	if s.relay == nil {
		return
	}
	outcome := relayDoneOther
	switch {
	case res.Allow:
		outcome = relayDoneAllow
	case res.Body != nil:
		outcome = relayDoneDeny
	case res.Reason == "ttl expired":
		outcome = relayDoneTTL
	}
	for _, id := range s.relayDevices() {
		s.relaySend(id, "card.done", map[string]any{"id": it.ID, "outcome": outcome}, time.Now().Add(relayReplyTTL))
	}
}

// relayStatus sends the state to a device: status without the local paths, with `pending` as the
// full list of cards (and `pendingCount`, `seq`), so nothing depends on the relay's replay alone.
func (s *supervisor) relayStatus(deviceID string) {
	st := s.status()
	delete(st, "journal")
	seq, items := s.q.snapshot()
	// One frame holds 64 KiB after the box and base64. Cards that do not fit are left out of the
	// list (`pendingTruncated`; `pendingCount` stays the real number) and follow as card frames
	// of their own, so a long queue costs more frames, never the status.
	base, _ := json.Marshal(st)
	size := len(base)
	cards := make([]map[string]any, 0, len(items))
	var rest []*pendingItem
	for _, it := range items {
		c := s.relayCardOf(it)
		b, _ := json.Marshal(c)
		if size+len(b)+1 > relayStatusMax {
			rest = append(rest, it)
			continue
		}
		size += len(b) + 1
		cards = append(cards, c)
	}
	st["pendingCount"], st["pending"], st["seq"] = len(items), cards, seq
	if len(rest) > 0 {
		st["pendingTruncated"] = true
	}
	s.relaySend(deviceID, "status", st, time.Now().Add(relayReplyTTL))
	for _, it := range rest {
		s.relaySend(deviceID, "card", s.relayCardOf(it), time.UnixMilli(it.ExpiresAt))
	}
}

// relayStatusMax bounds the plaintext of a status frame: 40 KiB is 54 KiB as base64, which with
// the routing members stays under the relay's 64 KiB.
const relayStatusMax = 40 << 10

// relayConnected: after every (re)connect each device gets the current state.
func (s *supervisor) relayConnected() {
	for _, id := range s.relayDevices() {
		s.relayStatus(id)
	}
}

// relayMessage handles an opened msg frame of a trusted device. It returns true (ack) once the
// frame was handled or definitively refused: a refused ticket does not get better when the relay
// sends it again.
func (s *supervisor) relayMessage(from, kind string, pt []byte, e relaylink.Envelope) bool {
	switch kind {
	case "ticket":
		s.relaySend(from, "ticket.result", s.relayTicket(from, pt), time.Now().Add(relayReplyTTL))
	case "status.req":
		s.relayStatus(from)
	default: // a kind of a later protocol (protocol/README.md 5.5): acked so it does not wait in the queue, never acted on
		s.journal("relay_unhandled", map[string]any{"id": e.ID, "from": from, "kind": kind})
	}
	return true
}

// relayTicket decides a ticket that came over the relay. The ticket is self-signed, and it must
// be the ticket of the device the relay authenticated for this frame (and the box opened with
// that device's key): one device does not carry another one's decision.
func (s *supervisor) relayTicket(from string, pt []byte) map[string]any {
	if b, err := envelope.ParseDecision(pt); err == nil && b.DeviceID != from {
		s.m.decideRejects.Add(1)
		s.journal("decide_reject", map[string]any{"reason": "device_mismatch", "from": from, "body": b})
		return map[string]any{"ok": false, "reason": "device_mismatch", "id": b.Payload.ID}
	}
	res, _ := s.decideTicket(pt)
	return res
}
