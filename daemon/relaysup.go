// SPDX-License-Identifier: AGPL-3.0-or-later

package main

// The relay client inside the supervisor: started unless relay_url is off, fed with the trusted
// devices that have an encryption key (trusted_devices[].enc, recorded at pairing).
//
// Pairing travels over the relay (relayPair), and so do cards and tickets (relaycards.go).

import (
	"context"
	"crypto/ecdh"
	"encoding/json"
	"fmt"
	"time"

	"github.com/xarvel/WardenClaw/daemon/envelope"
	"github.com/xarvel/WardenClaw/daemon/relaylink"
)

// startRelay connects wardend to the relay. An error (the key file) leaves the relay off: the
// supervisor runs on, the reason is shown in status.
func (s *supervisor) startRelay(ctx context.Context) error {
	enc, err := loadOrCreateRelayKey(s.cfg.RelayKeyFile)
	if err != nil {
		return err
	}
	s.relay = newRelayClient(s.cfg.RelayURL, s.key, enc, relayHandlers{
		Devices:   s.relayDevices,
		PeerKey:   s.relayPeerKey,
		Message:   s.relayMessage,
		Pair:      s.relayPair,
		Connected: s.relayConnected,
		Event:     func(event string, fields map[string]any) { s.journal(event, fields) },
	})
	s.goSafe("relay", func() { s.relay.run(ctx) })
	return nil
}

// relayPair handles a pairing request (protocol/README.md, "Pairing"): the checks of
// pairing.submit, plus the binding of the frame to the request: the
// box was opened with the key the frame named, so the signed payload must name the same key and
// the device the relay authenticated. A mismatch is journaled as tamper and never acked.
// Approval stays on the unix socket (wardend pair approve).
func (s *supervisor) relayPair(pt []byte, enc string, e relaylink.Envelope) bool {
	var body struct {
		Payload   envelope.PairPayload `json:"payload"`
		Signature string               `json:"signature"`
	}
	if err := json.Unmarshal(pt, &body); err != nil {
		s.journal("pair_reject_request", map[string]any{"reason": "body_invalid_json", "deviceId": e.From, "remote": "relay"})
		return true // it will not get better with another delivery
	}
	pp := body.Payload
	if pp.Enc != enc || pp.DeviceID != e.From {
		s.journal("relay_tamper", map[string]any{"id": e.ID, "from": e.From, "kind": "pair", "reason": "the signed payload names another key or device than the frame"})
		return false
	}
	peer, err := relaylink.ParseEncKey(enc)
	if err != nil {
		return false
	}
	req, reason := s.pair.submit(pp, body.Signature, s.supervisorID, "relay", s.cfg.TsWindow.Duration, s.trustedDevice)
	st := map[string]any{"re": e.ID, "status": "refused", "reason": reason, "fingerprint": envelope.Fingerprint(e.From), "supervisorId": s.supervisorID, "host": s.host}
	exp := time.Now().Add(pairReqTTL)
	if reason != "" {
		if reason != "pairing_not_active" {
			s.journal("pair_reject_request", map[string]any{"reason": reason, "deviceId": pp.DeviceID, "remote": "relay"})
		}
	} else {
		s.journal("pair_request", map[string]any{"id": req.ID, "deviceId": req.DeviceID, "name": req.Name, "remote": req.Remote, "status": req.Status})
		if !s.quiet && !s.wrap { // wardend wrap asks about the request on the terminal
			s.logf("wardend: pairing request %s: \"%s\", fingerprint %s (wardend pair approve %s)\n", req.ID, req.Name, req.Fingerprint, req.ID)
		}
		s.relayPairingSync() // the code is used up
		s.pair.bind(req.ID, e.ID)
		st = map[string]any{"re": e.ID, "id": req.ID, "status": req.Status, "fingerprint": req.Fingerprint, "supervisorId": s.supervisorID, "host": s.host, "expiresAt": req.ExpiresAt}
	}
	// answered from another goroutine: a handler must not wait for the relay's ack itself
	end := s.relay.begin()
	s.goSafe("relay-pair-status", func() {
		defer end()
		b, _ := json.Marshal(st)
		if _, err := s.relay.sendTo(context.Background(), e.From, peer, "pair.status", b, exp); err != nil {
			s.logf("wardend: relay: pair.status: %v\n", err)
		}
	})
	return true
}

// relayPairWindowMax: the relay refuses a pairing window longer than 15 minutes (protocol/README.md 13).
const relayPairWindowMax = 15 * time.Minute

// relayPairingSync closes the pairing window on the relay when no code is active any more (the
// code was used or expired). The relay closes it at `until` anyway; this is the early close.
func (s *supervisor) relayPairingSync() {
	if s.relay == nil || s.pair.activeCodes() > 0 {
		return
	}
	s.relay.mu.Lock()
	open := s.relay.pairing != 0
	s.relay.mu.Unlock()
	if !open {
		return
	}
	end := s.relay.begin()
	s.goSafe("relay-pairing", func() {
		defer end()
		if err := s.relay.setPairing(context.Background(), time.Time{}); err != nil && err != errRelayOffline {
			s.logf("wardend: relay: pairing: %v\n", err)
		}
	})
}

// relayPairStatus tells the device of a decided request the outcome (approved, rejected). The
// box is for the key of the request: a rejected device is not in trusted_devices.
func (s *supervisor) relayPairStatus(r pairReq) {
	if s.relay == nil || r.Enc == "" {
		return
	}
	peer, err := relaylink.ParseEncKey(r.Enc)
	if err != nil {
		return
	}
	b, _ := json.Marshal(map[string]any{"re": r.Re, "id": r.ID, "status": r.Status, "fingerprint": r.Fingerprint, "supervisorId": s.supervisorID, "host": s.host, "expiresAt": r.ExpiresAt})
	end := s.relay.begin()
	s.goSafe("relay-pair-status", func() {
		defer end()
		if _, err := s.relay.sendTo(context.Background(), r.DeviceID, peer, "pair.status", b, time.Now().Add(pairReqTTL)); err != nil && err != errRelayOffline {
			s.logf("wardend: relay: pair.status: %v\n", err)
		}
	})
}

// relayDevices: the trusted devices the relay may route for, those with an encryption key.
func (s *supervisor) relayDevices() []string {
	ids := []string{}
	for _, d := range s.devices.List() {
		if _, err := relaylink.ParseEncKey(d.Enc); d.Enc != "" && err == nil {
			ids = append(ids, d.ID)
		}
	}
	return ids
}

func (s *supervisor) relayPeerKey(deviceID string) (*ecdh.PublicKey, bool) {
	for _, d := range s.devices.List() {
		if d.ID == deviceID && d.Enc != "" {
			k, err := relaylink.ParseEncKey(d.Enc)
			return k, err == nil
		}
	}
	return nil, false
}

// relayDevicesChanged re-sends the trusted list after pair approve and revoke. Offline is fine:
// the list goes out with the next hello.
func (s *supervisor) relayDevicesChanged() {
	if s.relay == nil {
		return
	}
	end := s.relay.begin()
	s.goSafe("relay-devices", func() {
		defer end()
		if err := s.relay.sendDevices(context.Background()); err != nil && err != errRelayOffline {
			s.logf("wardend: relay: devices: %v\n", err)
		}
	})
}

func (s *supervisor) relayInfo() map[string]any {
	m := map[string]any{"url": s.cfg.RelayURL, "enabled": s.relay != nil}
	if s.relayErr != "" {
		m["error"] = s.relayErr
	}
	if s.relay != nil {
		m["connected"] = s.relay.connected()
		m["encKey"] = s.relay.encPublic()
		m["encFingerprint"] = envelope.Fingerprint(envelope.SHA256Hex(s.relay.enc.PublicKey().Bytes()))
		m["devices"] = len(s.relayDevices())
		m["endpoint"] = fmt.Sprintf("%s/v1/ws/%s", s.cfg.RelayURL, s.supervisorID)
	}
	return m
}
