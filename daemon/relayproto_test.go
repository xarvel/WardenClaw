// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/xarvel/WardenClaw/daemon/relaylink/relaytest"
)

// TestRelayProtocolErrorText: the words for a protocol mismatch name the side that is older.
func TestRelayProtocolErrorText(t *testing.T) {
	for _, c := range []struct {
		relay int
		want  string
	}{
		{0, "its version could not be read"},
		{relayProtocol + 1, "wardend is older, update wardend"},
		{relayProtocol, "the relay is older, update the relay"}, // equal cannot happen on this path; the branch is "not newer"
	} {
		if got := (&relayProtocolError{Relay: c.relay}).Error(); !strings.Contains(got, c.want) || !strings.Contains(got, "protocol mismatch") {
			t.Fatalf("relay %d: %q lacks %q", c.relay, got, c.want)
		}
	}
}

// TestRelayProtocolMismatch: the relay refuses the hello with protocol_mismatch (an error frame
// that does not say which protocol it speaks). wardend asks GET /v1/ping, journals one
// relay_disconnected with both numbers and a sentence naming the older side, and wardend status
// shows the same sentence as relay.error; the welcome of another protocol says the same.
func TestRelayProtocolMismatch(t *testing.T) {
	relay := relaytest.NewRelay(t)
	relay.Mu.Lock()
	relay.HelloErr = "protocol_mismatch"
	relay.Protocol = relayProtocol + 1
	relay.Mu.Unlock()
	if got := relayPingProtocol(context.Background(), relay.URL()); got != relayProtocol+1 {
		t.Fatalf("ping protocol %d", got)
	}
	if got := relayPingProtocol(context.Background(), "ws://127.0.0.1:1"); got != 0 {
		t.Fatalf("unreachable relay: protocol %d", got)
	}

	_, key, _ := ed25519.GenerateKey(nil)
	enc, _ := ecdh.X25519().GenerateKey(rand.Reader)
	var mu sync.Mutex
	var events []map[string]any
	c := newRelayClient(relay.URL(), key, enc, relayHandlers{
		Event: func(ev string, fields map[string]any) {
			if ev != "relay_disconnected" {
				return
			}
			mu.Lock()
			defer mu.Unlock()
			events = append(events, fields)
		},
	})
	c.backoff = func(int) time.Duration { return 10 * time.Millisecond }
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { c.run(ctx); close(done) }()
	t.Cleanup(func() { cancel(); <-done })

	waitFor(t, "relay_disconnected", func() bool { mu.Lock(); defer mu.Unlock(); return len(events) > 0 })
	mu.Lock()
	f := events[0]
	mu.Unlock()
	msg, _ := f["error"].(string)
	if f["relayProtocol"] != relayProtocol+1 || f["protocol"] != relayProtocol || !strings.Contains(msg, "wardend is older, update wardend") {
		t.Fatalf("event: %v", f)
	}
	if e := c.lastError(); !strings.Contains(e, "update wardend") {
		t.Fatalf("status relay.error: %q", e)
	}
	// the first refusal is accepted by the fake (HelloErr is one-shot): after the welcome the
	// error is gone, and so is relay.error
	relay.Wait("resume")
	waitFor(t, "relay.error cleared", func() bool { return c.lastError() == "" })
	var pe *relayProtocolError
	if err := error(&relayProtocolError{Relay: 3}); !errors.As(err, &pe) {
		t.Fatal("errors.As")
	}
}
