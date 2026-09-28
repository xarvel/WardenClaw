// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"slices"
	"testing"
	"time"

	"github.com/xarvel/WardenClaw/daemon/envelope"
	"github.com/xarvel/WardenClaw/daemon/relaylink"
	"github.com/xarvel/WardenClaw/daemon/relaylink/relaytest"
)

// The supervisor with relay_url: connects, lists only the devices that have an encryption key,
// re-sends the list when it changes, and journals a frame of a kind it does not know.
func TestSupervisorRelay(t *testing.T) {
	relay := relaytest.NewRelay(t)
	d := newDevice()
	s := newHWSupervisor(t, `{}`, d) // d is trusted, without an encryption key
	s.supervisorID = envelope.DeviceID(s.key.Public().(ed25519.PublicKey))
	s.cfg.RelayURL = relay.URL()
	if info := s.relayInfo(); info["enabled"] != false {
		t.Fatalf("before start: %v", info)
	}
	ctx, cancel := context.WithCancel(context.Background())
	if err := s.startRelay(ctx); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cancel()
		waitFor(t, "relay client stopped", func() bool { return !s.relay.connected() })
	})
	relay.Wait("resume")
	relay.Mu.Lock()
	first := slices.Clone(relay.Devices[0])
	relay.Mu.Unlock()
	if len(first) != 0 {
		t.Fatalf("a device without enc was listed: %v", first)
	}
	if info := s.relayInfo(); info["connected"] != true || info["devices"] != 0 || info["encKey"] == "" {
		t.Fatalf("status: %v", info)
	}

	devEnc, _ := ecdh.X25519().GenerateKey(rand.Reader)
	td := d.trusted()
	td.Enc = envelope.B64URL(devEnc.PublicKey().Bytes())
	s.devices.Add(td)
	s.relayDevicesChanged()
	waitFor(t, "devices re-sent", func() bool {
		relay.Mu.Lock()
		defer relay.Mu.Unlock()
		return len(relay.Devices) == 2 && slices.Equal(relay.Devices[1], []string{d.id})
	})

	// a kind this wardend does not know: opened, journaled as unhandled, acked (it would not get
	// better with another delivery)
	e := relaylink.Envelope{Type: "msg", ID: relaylink.MsgID(), To: s.supervisorID, From: d.id, Seq: 1, Ts: time.Now().UnixMilli(), Exp: time.Now().Add(time.Minute).UnixMilli(), Kind: "later.kind"}
	key, _ := relaylink.BoxKey(devEnc, s.relay.enc.PublicKey(), s.supervisorID, d.id)
	aad, _ := relaylink.AAD(e.ID, e.From, e.To, e.Kind, e.Exp)
	e.Body, _ = relaylink.Seal(key, nil, []byte(`{}`), aad)
	relay.Send(e)
	waitFor(t, "relay_unhandled in the journal", func() bool {
		recs, _ := tailJournal(s.cfg.Journal, 20)
		return slices.ContainsFunc(recs, func(r json.RawMessage) bool {
			return bytes.Contains(r, []byte("relay_unhandled")) && bytes.Contains(r, []byte(e.ID))
		})
	})
	waitFor(t, "the frame acked", func() bool { return relay.Acked(e.ID) })
}
