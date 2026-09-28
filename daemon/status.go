// SPDX-License-Identifier: AGPL-3.0-or-later

package main

// A signed decision from a phone or wardenctl, and the status those clients read.

import (
	"encoding/json"
	"fmt"
	"io"
	"time"

	"github.com/xarvel/WardenClaw/daemon/envelope"
	"github.com/xarvel/WardenClaw/daemon/hwkey"
	"github.com/xarvel/WardenClaw/daemon/journal"
)

// decide (RPC): a signed decision from a device.
func (s *supervisor) decide(params json.RawMessage) map[string]any {
	res, _ := s.decideTicket(params)
	return res
}

// decideTicket is decide for HTTP: the second value is the ticket if its signature is valid and
// the nonce is claimed by it (envelope.Claimed), otherwise nil (the response to such a request is
// not bound to the request).
func (s *supervisor) decideTicket(params json.RawMessage) (map[string]any, *envelope.DecisionBody) {
	b, err := envelope.ParseDecision(params)
	if err != nil {
		s.m.decideRejects.Add(1)
		return map[string]any{"ok": false, "reason": err.Error()}, nil
	}
	reason := envelope.Verify(b, envelope.VerifyCtx{Now: time.Now(), TsWindow: s.cfg.TsWindow.Duration, SupervisorID: s.supervisorID, Devices: s.devices,
		Nonces: s.nonces, Pending: s.q.digestOf})
	claimed := b
	if !envelope.Claimed(reason) {
		claimed = nil
	}
	if reason != "" {
		s.m.decideRejects.Add(1)
		s.journal("decide_reject", map[string]any{"reason": reason, "body": b})
		return map[string]any{"ok": false, "reason": reason, "id": b.Payload.ID}, claimed
	}
	allow := b.Payload.Decision == "allow"
	why := "denied by device " + b.DeviceID[:12]
	res := ticketResult{Allow: allow, Body: b}
	if allow {
		why = "ticket " + b.Payload.Digest[:12] + " by " + b.DeviceID[:12]
		hwRes, rule, reason := s.checkHardware(b)
		if reason != "" {
			s.m.decideRejects.Add(1)
			s.journal("decide_reject", map[string]any{"reason": reason, "hardwareRule": rule, "body": b})
			return map[string]any{"ok": false, "reason": reason, "id": b.Payload.ID, "hardwareRule": rule}, b
		}
		res.Hardware, res.HWRule = hwRes, rule
		if hwRes != nil {
			why += " + hardware key " + shortID(hwRes.CredentialID)
		}
	}
	res.Reason = why
	if !s.q.resolve(b.Payload.ID, res) {
		return map[string]any{"ok": false, "reason": "already_decided", "id": b.Payload.ID}, b
	}
	return map[string]any{"ok": true, "id": b.Payload.ID, "decision": b.Payload.Decision}, b
}

// checkHardware: the second factor for allow. Required if the record has a static
// require_hardware rule or a score rule matched on the signed payload.risk. If an assertion
// arrived although it was not required, it is still verified (an invalid one means denial), and
// the root counts as approved with a key (its descendants pass require_hardware rules by
// inheritance). Returns the verification result, the rule id and the denial reason ("" is ok).
func (s *supervisor) checkHardware(b *envelope.DecisionBody) (*hwkey.Result, string, string) {
	it := s.q.get(b.Payload.ID)
	if it == nil {
		return nil, "", "already_decided"
	}
	rule := ""
	if it.hwRule != nil {
		rule = it.hwRule.ID
	} else if score, ok := b.Payload.RiskScore(); ok && it.pe != nil {
		if r := s.pol.HardwareByScoreCat(it.pe, it.class, it.category, score); r != nil {
			rule = r.ID
		}
	}
	if rule == "" && b.HW == nil {
		return nil, "", ""
	}
	if b.HW == nil {
		return nil, rule, "hardware_required"
	}
	if s.hw == nil || s.hw.Len() == 0 {
		return nil, rule, "hardware_not_configured"
	}
	ch, err := envelope.HWChallenge(b.DeviceID, b.Payload)
	if err != nil {
		return nil, rule, "hw_challenge: " + err.Error()
	}
	r, reason := s.hw.VerifyAssertion(b.HW, ch)
	return r, rule, reason
}

// hardwareMeta: what the app needs to know about the second factor for the card (nil if not
// needed).
func (s *supervisor) hardwareMeta(h *hwRecord) map[string]any {
	if h == nil {
		return nil
	}
	m := map[string]any{"required": h.Required, "challenge": envelope.HWType, "origin": hwkey.Origin}
	if h.Rule != "" {
		m["rule"] = h.Rule
	}
	if h.Escalated {
		m["escalated"] = true
	}
	if h.MinScore != nil {
		m["minScore"] = *h.MinScore
	}
	creds := []map[string]string{}
	if s.hw != nil {
		creds = s.hw.Public()
	}
	m["credentials"] = creds
	return m
}

func shortID(s string) string {
	if len(s) > 12 {
		return s[:12]
	}
	return s
}

func (s *supervisor) status() map[string]any {
	ids := s.devices.IDs()
	return hwStatus(map[string]any{
		"ok": true, "protocol": envelope.Protocol, "minClient": envelope.MinClient, "warnings": s.statusWarnings(ids),
		"mode": s.cfg.Mode, "policyMode": s.cfg.PolicyMode, "packs": s.pol.PackNames(), "pid": s.supPid, "supervisorId": s.supervisorID, "host": s.host,
		"journal": s.cfg.Journal, "journalKey": s.jr.PublicKey(), "journalHead": s.jr.Head(), "trustedDeviceIds": ids, "trustedDevices": s.deviceSummary(),
		"pending": s.q.len(), "maxPending": s.cfg.MaxPending, "ticketTtlMs": s.cfg.TicketTTL.Milliseconds(),
		"tracker": s.tracker.Stats(), "metrics": s.m.snapshot(), "startedAt": s.started.UnixMilli(), "now": time.Now().UnixMilli(),
		"toctou": map[string]string{"roots": s.cfg.ToctouRoots, "service": s.cfg.ToctouService},
		"http":   s.httpInfo(), "ntfy": s.ntfy != nil, "pairing": s.pairingInfo(), "push": s.push.info(),
	}, s.hw.Public(), len(s.pol.RequireHardware), s.pol.HardwareRulesInfo())
}

// statusWarnings: status warnings as machine codes, always a list (empty if everything is fine).
// Words for humans: statusWarningText.
func (s *supervisor) statusWarnings(trusted []string) []string {
	w := []string{}
	if s.cfg.Mode == "ticket" && len(trusted) == 0 {
		w = append(w, "no_trusted_devices")
	}
	return w
}

// statusWarningText: a status warning in words (wardend status prints them to stderr after the
// JSON).
func statusWarningText(code string) string {
	switch code {
	case "no_trusted_devices":
		return "ticket mode and no trusted devices: pending roots wait for a ticket nobody can sign and are denied after the TTL. Pair a phone: wardend pair start"
	}
	return code
}

// printStatusWarnings: warnings from the status response in words, one line each.
func printStatusWarnings(w io.Writer, raw []byte) {
	var st struct {
		Warnings []string `json:"warnings"`
	}
	if json.Unmarshal(raw, &st) != nil {
		return
	}
	for _, c := range st.Warnings {
		fmt.Fprintln(w, "wardend: warning:", statusWarningText(c))
	}
}

// deviceSummary: trusted devices with the key type (for status: ed25519 phone, es256 watch).
func (s *supervisor) deviceSummary() []map[string]any {
	out := []map[string]any{}
	for _, d := range s.devices.List() {
		alg, err := envelope.NormalizeAlg(d.Alg)
		if err != nil {
			alg = "invalid:" + d.Alg
		}
		out = append(out, map[string]any{"id": d.ID, "alg": alg, "name": d.Name, "fingerprint": envelope.Fingerprint(d.ID)})
	}
	return out
}

// trustedDevice: the device has a usable trusted key right now (paired and not revoked).
func (s *supervisor) trustedDevice(id string) bool {
	_, why := s.devices.Key(id)
	return why == ""
}

// pendingSnapshot: the pending response (RPC and HTTP).
func (s *supervisor) pendingSnapshot() map[string]any {
	seq, items := s.q.snapshot()
	return map[string]any{"ok": true, "seq": seq, "mode": s.cfg.Mode, "supervisorId": s.supervisorID, "host": s.host,
		"pending": items, "now": time.Now().UnixMilli()}
}

func (s *supervisor) pairingInfo() map[string]any {
	if s.pair == nil {
		return nil
	}
	pending := 0
	for _, r := range s.pair.list() {
		if r.Status == "pending" {
			pending++
		}
	}
	return map[string]any{"activeCodes": s.pair.activeCodes(), "pendingRequests": pending}
}

func (s *supervisor) httpInfo() map[string]any {
	m := map[string]any{"listen": s.cfg.HTTPListen, "publicUrl": s.cfg.PublicURL, "up": s.http != nil}
	if s.http != nil {
		m["addr"] = s.http.addr()
	}
	if s.httpErr != "" {
		m["error"] = s.httpErr
	}
	return m
}

func tailJournal(path string, n int) ([]json.RawMessage, error) { return journal.Tail(path, n) }
