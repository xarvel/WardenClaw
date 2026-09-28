// SPDX-License-Identifier: AGPL-3.0-or-later

package main

// A fake device for the relay tests: Go code that plays the app. It builds frames the way the
// relay would forward them (from set to its id) and opens what the supervisor stored for it.

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/xarvel/WardenClaw/daemon/envelope"
	"github.com/xarvel/WardenClaw/daemon/relaylink"
	"github.com/xarvel/WardenClaw/daemon/relaylink/relaytest"
)

// pairFrameBody turns a plain box into the body of a pair frame: the sender's X25519 key in front.
func pairFrameBody(pub *ecdh.PublicKey, body string) string {
	raw, _ := envelope.DecodeB64URL(body)
	return envelope.B64URL(append(pub.Bytes(), raw...))
}

type relayDev struct {
	device
	enc *ecdh.PrivateKey
}

func newRelayDev() relayDev {
	enc, _ := ecdh.X25519().GenerateKey(rand.Reader)
	return relayDev{device: newDevice(), enc: enc}
}

func (d relayDev) encPub() string { return envelope.B64URL(d.enc.PublicKey().Bytes()) }

// link is this device as the production code of a device (relaylink.Device) sees it, talking to
// supervisor s.
func (d relayDev) link(s *supervisor) *relaylink.Device {
	return &relaylink.Device{Key: d.priv, Enc: d.enc, SupervisorID: s.supervisorID, SupervisorEnc: s.relay.enc.PublicKey(),
		Client: "wardenclaw-test", Version: version}
}

// frame boxes plaintext for the supervisor as a msg of this device.
func (d relayDev) frame(s *supervisor, kind string, pt []byte) relaylink.Envelope {
	e, _ := d.link(s).Seal(kind, pt)
	return e
}

// pairFrame is a pairing request with this code: the signed payload names the device's
// encryption key, and so does the front of the body.
func (d relayDev) pairFrame(s *supervisor, code, name string) relaylink.Envelope {
	e, _ := d.link(s).SealPair(d.pairPlaintext(s, code, name))
	return e
}

// open decrypts a frame the supervisor sent to this device.
func (d relayDev) open(t *testing.T, s *supervisor, e relaylink.Envelope) map[string]any {
	t.Helper()
	pt, err := d.link(s).Open(e)
	if err != nil {
		t.Fatalf("device cannot open a %s frame: %v", e.Kind, err)
	}
	var m map[string]any
	if err := json.Unmarshal(pt, &m); err != nil {
		t.Fatalf("%s plaintext %q: %v", e.Kind, pt, err)
	}
	return m
}

// next waits for the n-th (from 0) frame of this kind the supervisor sent to the device and
// opens it.
func (d relayDev) next(t *testing.T, s *supervisor, relay *relaytest.Relay, kind string, n int) map[string]any {
	t.Helper()
	var e relaylink.Envelope
	waitFor(t, kind+" for the device", func() bool {
		relay.Mu.Lock()
		defer relay.Mu.Unlock()
		i := 0
		for _, x := range relay.Stored {
			if x.To == d.id && x.Kind == kind {
				if i == n {
					e = x
					return true
				}
				i++
			}
		}
		return false
	})
	return d.open(t, s, e)
}

// newRelaySupervisor: a supervisor connected to a fake relay, with a config file pair approve can
// write. The devices are trusted with their encryption keys.
func newRelaySupervisor(t *testing.T, devs ...relayDev) (*supervisor, *relaytest.Relay) {
	t.Helper()
	return newRelaySupervisorWith(t, nil, devs...)
}

// newRelaySupervisorWith: prep changes the supervisor before it connects (the keys of another one:
// a restart).
func newRelaySupervisorWith(t *testing.T, prep func(*supervisor), devs ...relayDev) (*supervisor, *relaytest.Relay) {
	t.Helper()
	relay := relaytest.NewRelay(t)
	s := startRelaySupervisor(t, relay.URL(), prep, devs...)
	relay.Wait("resume")
	s.relay.mu.Lock()
	s.relay.rateEvery = time.Millisecond // the pacing has its own test
	s.relay.mu.Unlock()
	return s, relay
}

// startRelaySupervisor: a supervisor with fresh keys whose relay client is connected to the relay
// at url.
func startRelaySupervisor(t *testing.T, url string, prep func(*supervisor), devs ...relayDev) *supervisor {
	t.Helper()
	s := newHWSupervisor(t, `{}`, newDevice())
	s.supervisorID = envelope.DeviceID(s.key.Public().(ed25519.PublicKey))
	if prep != nil {
		prep(s)
	}
	s.host = "h"
	s.cfg.RelayURL = url
	s.cfg.path = filepath.Join(s.cfg.StateDir, "config.json")
	if err := os.WriteFile(s.cfg.path, []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, d := range devs {
		td := d.trusted()
		td.Enc = d.encPub()
		s.devices.Add(td)
	}
	ctx, cancel := context.WithCancel(context.Background())
	if err := s.startRelay(ctx); err != nil {
		t.Fatal(err)
	}
	// the in-process relay is retried at once; a relay on the network keeps the real backoff, so a
	// failing test never hammers it
	local := strings.HasPrefix(url, "ws://127.0.0.1")
	if local {
		s.relay.backoff = func(int) time.Duration { return 10 * time.Millisecond }
	}
	t.Cleanup(func() {
		cancel()
		waitFor(t, "relay client stopped", func() bool { return !s.relay.connected() })
	})
	for i := 0; !s.relay.connected(); i++ {
		if (local && i >= 500) || i >= 2000 {
			recs, _ := tailJournal(s.cfg.Journal, 20)
			for _, r := range recs {
				t.Logf("journal: %s", r)
			}
			t.Fatal("timeout: relay client connected")
		}
		time.Sleep(10 * time.Millisecond)
	}
	return s
}

func journalHas(s *supervisor, parts ...string) bool {
	recs, _ := tailJournal(s.cfg.Journal, 50)
	return slices.ContainsFunc(recs, func(r json.RawMessage) bool {
		for _, p := range parts {
			if !bytes.Contains(r, []byte(p)) {
				return false
			}
		}
		return true
	})
}

// Pairing over the relay: a request is opened with the key in front of the body, checked like
// pairing.submit, answered with pair.status; approve records enc and lists the device to the relay.
func TestRelayPairing(t *testing.T) {
	s, relay := newRelaySupervisor(t)
	d := newRelayDev()

	// no code: refused, and the device is told so
	e := d.pairFrame(s, "ABCD2345", "phone")
	relay.Send(e)
	if st := d.next(t, s, relay, "pair.status", 0); st["status"] != "refused" || st["reason"] != "pairing_not_active" {
		t.Fatalf("without a code: %v", st)
	}

	code, _ := s.pair.start(time.Minute)

	// the key in front of the body is another one than the signed payload names: tamper, no ack,
	// no request, the code is not used up
	other := newRelayDev()
	bad := d.pairFrame(s, code, "phone")
	forged := relayDev{device: d.device, enc: other.enc} // boxes with another key, payload still names d's
	fe := forged.frame(s, "pair", d.pairPlaintext(s, code, "phone"))
	fe.Type, fe.Body = "pair", pairFrameBody(other.enc.PublicKey(), fe.Body)
	relay.Send(fe)
	waitFor(t, "relay_tamper in the journal", func() bool { return journalHas(s, "relay_tamper", fe.ID) })
	if relay.Acked(fe.ID) || len(s.pair.list()) != 0 || s.pair.activeCodes() != 1 {
		t.Fatalf("a forged pair frame was accepted: acked %v, requests %v", relay.Acked(fe.ID), s.pair.list())
	}

	relay.Send(bad)
	st := d.next(t, s, relay, "pair.status", 1)
	if st["status"] != "pending" || st["fingerprint"] != envelope.Fingerprint(d.id) || st["host"] != "h" || st["re"] != bad.ID {
		t.Fatalf("pair.status: %v", st)
	}
	waitFor(t, "pair frame acked", func() bool { return relay.Acked(bad.ID) })
	if s.trustedDevice(d.id) {
		t.Fatal("trusted before approve")
	}
	id, _ := st["id"].(string)
	if _, err := s.pairApprove(id); err != nil {
		t.Fatal(err)
	}
	if k, ok := s.relayPeerKey(d.id); !ok || !bytes.Equal(k.Bytes(), d.enc.PublicKey().Bytes()) {
		t.Fatal("enc was not recorded for the approved device")
	}
	cfg, _ := os.ReadFile(s.cfg.path)
	if !bytes.Contains(cfg, []byte(d.encPub())) {
		t.Fatalf("enc is not in the config: %s", cfg)
	}
	// the status of the approval names the frame that carried the request
	if st := d.next(t, s, relay, "pair.status", 2); st["status"] != "approved" || st["re"] != bad.ID {
		t.Fatalf("after approve: %v", st)
	}
	waitFor(t, "the device listed to the relay", func() bool {
		relay.Mu.Lock()
		defer relay.Mu.Unlock()
		return slices.Contains(relay.Devices[len(relay.Devices)-1], d.id)
	})
}

// pairPlaintext: {payload, signature} of a pairing request.
func (d relayDev) pairPlaintext(s *supervisor, code, name string) []byte {
	pt, _ := d.link(s).PairRequest(code, name)
	return pt
}
