// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"

	"github.com/xarvel/WardenClaw/daemon/envelope"
	"github.com/xarvel/WardenClaw/daemon/relaylink"
	"github.com/xarvel/WardenClaw/daemon/relaylink/relaytest"
)

// TestOneShotAcksQueuedFrames: a frame the relay queued while wardenctl was away (a card.done of
// a card decided elsewhere) is acked by the next one-shot command, not left in the queue to be
// delivered again on every connection until it expires. Status asks the relay for its queue
// first and waits for the end of the replay; the session acks what opened.
func TestOneShotAcksQueuedFrames(t *testing.T) {
	relay := relaytest.NewRelay(t)
	supPub, supKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	supEnc, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	devPub, devKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	devEnc, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sid, did := envelope.DeviceID(supPub), envelope.DeviceID(devPub)
	_ = supKey

	// the supervisor sealed a card.done for the device and left; the device is on its list
	now := time.Now()
	e := relaylink.Envelope{Type: "msg", ID: relaylink.MsgID(), To: did, From: sid, Seq: 1, Ts: now.UnixMilli(), Exp: now.Add(time.Hour).UnixMilli(), Kind: "card.done"}
	key, err := relaylink.BoxKey(supEnc, devEnc.PublicKey(), sid, did)
	if err != nil {
		t.Fatal(err)
	}
	aad, err := relaylink.AAD(e.ID, e.From, e.To, e.Kind, e.Exp)
	if err != nil {
		t.Fatal(err)
	}
	if e.Body, err = relaylink.Seal(key, nil, []byte(`{"id":"abc","decision":"deny"}`), aad); err != nil {
		t.Fatal(err)
	}
	relay.Mu.Lock()
	relay.Stored = append(relay.Stored, e)
	relay.Devices = append(relay.Devices, []string{did})
	relay.Mu.Unlock()

	cl := newClient(relay.URL(), sid, supEnc.PublicKey(), devKey, devEnc)
	defer cl.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	// no supervisor is connected: the status.req gets no answer, which is the one-shot's
	// error; the queued frame must have been acked by then
	if _, err := cl.Status(ctx); err == nil {
		t.Fatal("a status without a supervisor")
	}
	if !relay.DevAcked(e.ID) {
		t.Fatal("the frame queued while wardenctl was away was not acked")
	}
	// the second status of the same connection does not resume again
	cl.mu.Lock()
	up := cl.caughtUp
	cl.mu.Unlock()
	if !up {
		t.Fatal("caughtUp not set")
	}
}
