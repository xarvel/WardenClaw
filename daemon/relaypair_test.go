// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/xarvel/WardenClaw/daemon/envelope"
)

// `wardend pair start` with the relay on: a relay link, the pairing window open on the relay until
// the code expires, closed as soon as the code is used.
func TestRelayPairStart(t *testing.T) {
	s, relay := newRelaySupervisor(t)
	// the fake relay is ws://127.0.0.1, and a link names a wss:// relay only: pair start refuses,
	// issues no code and opens no window
	if _, err := s.pairStart(0); err == nil || !strings.Contains(err.Error(), "wss://") || s.pair.activeCodes() != 0 {
		t.Fatalf("pair start with a ws:// relay: %v, %d codes", err, s.pair.activeCodes())
	}
	relay.Mu.Lock()
	windows := len(relay.Pairing)
	relay.Mu.Unlock()
	if windows != 0 {
		t.Fatalf("a refused pair start opened %d windows", windows)
	}
	if _, err := envelope.ParsePairLink((envelope.PairLink{Relay: relay.URL() + "/v1/ws", SID: s.supervisorID, Key: s.jr.PublicKey(), Enc: s.relay.encPublic(), Code: "ABCD2345"}).String()); err == nil {
		t.Fatal("a link with a ws:// relay was parsed")
	}

	// the rest of pair start, as with a wss:// relay
	res, err := s.pairOpenRelay(0)
	if err != nil {
		t.Fatal(err)
	}
	wssLink := strings.Replace(res["link"].(string), "relay=ws%3A", "relay=wss%3A", 1)
	link, err := envelope.ParsePairLink(wssLink)
	if err != nil {
		t.Fatalf("link %v: %v", res["link"], err)
	}
	if link.Relay != "wss"+strings.TrimPrefix(relay.URL(), "ws")+"/v1/ws" || link.SID != s.supervisorID || link.Enc != s.relay.encPublic() ||
		link.Key != s.jr.PublicKey() || link.Code != res["code"] {
		t.Fatalf("link: %+v", link)
	}
	lastWindow := func() int64 {
		relay.Mu.Lock()
		defer relay.Mu.Unlock()
		if len(relay.Pairing) == 0 {
			return -1
		}
		return relay.Pairing[len(relay.Pairing)-1]
	}
	if got := lastWindow(); got != res["expiresAt"] {
		t.Fatalf("window until %d, code expires %v", got, res["expiresAt"])
	}

	d := newRelayDev()
	relay.Send(d.pairFrame(s, link.Code, "phone"))
	if st := d.next(t, s, relay, "pair.status", 0); st["status"] != "pending" {
		t.Fatalf("pair.status: %v", st)
	}
	waitFor(t, "window closed after the code was used", func() bool { return lastWindow() == 0 })

}

// The relay is unreachable: no code is left behind, the error says why.
func TestRelayPairStartOffline(t *testing.T) {
	s := newHWSupervisor(t, `{}`, newDevice())
	s.cfg.RelayURL = "ws://127.0.0.1:1"
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := s.startRelay(ctx); err != nil {
		t.Fatal(err)
	}
	s.relay.backoff = func(int) time.Duration { return time.Hour }
	if _, err := s.pairOpenRelay(0); err == nil || s.pair.activeCodes() != 0 {
		t.Fatalf("err %v, active codes %d", err, s.pair.activeCodes())
	}
}
