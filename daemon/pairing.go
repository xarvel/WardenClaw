// SPDX-License-Identifier: AGPL-3.0-or-later

package main

// wardend's own pairing (without the OpenClaw gateway). Everything between the device and wardend
// travels over the relay (protocol/README.md, "Pairing").
//
//  1. Owner on the server: `wardend pair start` opens the pairing window on the relay and prints a
//     one-time code (5 min) and a QR with the link
//     wardenclaw://pair?v=1&relay=…&sid=…&key=…&enc=…&code=… (pairStart).
//  2. App: a `pair` frame boxed for the supervisor's X25519 key, with {code, deviceId, pubkey, enc,
//     name, supervisorId, ts, nonce} signed with the new device's key (envelope.PairSigningString;
//     relaysup.go relayPair → submit). The code is used up by the first valid request; 10 wrong
//     codes in a row clear all active codes. The answer is a `pair.status` frame.
//  3. Owner: `wardend pair list` (key fingerprint, name) → `wardend pair approve <id>`: the device
//     with its public keys is appended to trusted_devices in the config and becomes trusted in
//     the running supervisor at once. Approval works only over the unix socket and only from
//     outside wardend's own seccomp filter (the agent can't approve a device for itself, see
//     peerSupervised).
//  4. The device gets `pair.status` approved and from then on cards, and sends tickets.

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/xarvel/WardenClaw/daemon/envelope"
	"github.com/xarvel/WardenClaw/daemon/relaylink"
)

const (
	pairReqTTL   = 10 * time.Minute // how long an unapproved request waits
	pairKeepDone = 10 * time.Minute // how long to keep a decided one (pair list)
	maxPairReqs  = 8                // pending requests at a time
	maxPairFails = 10               // wrong codes in a row that clear all active codes

	codeAlphabet = "ABCDEFGHJKMNPQRSTVWXYZ23456789" // no 0/O, 1/I/L, U
	codeLen      = 8                                // shown as XXXX-XXXX (formatCode)
	idAlphabet   = "abcdefghjkmnpqrstvwxyz23456789"
	idLen        = 6 // request id: "p-" followed by idLen characters

	maxNameRunes = 64
	minNonceLen  = 8
	maxNonceLen  = 128
	maxAncestors = 128 // parent links peerSupervised follows up from the client process
)

type pairReq struct {
	ID          string `json:"id"`
	DeviceID    string `json:"deviceId"`
	Pubkey      string `json:"pubkey"`
	Alg         string `json:"alg"`          // ed25519 | es256
	Enc         string `json:"enc"`          // X25519 key of the device
	Re          string `json:"re,omitempty"` // id of the pair frame that carried the request: every pair.status names it
	Name        string `json:"name"`
	Fingerprint string `json:"fingerprint"`
	Remote      string `json:"remote"`
	CreatedAt   int64  `json:"createdAt"`
	ExpiresAt   int64  `json:"expiresAt"`
	Status      string `json:"status"` // pending | approved | rejected
	DecidedAt   int64  `json:"decidedAt,omitempty"`
}

type pairing struct {
	mu    sync.Mutex
	codes map[string]time.Time // code → expiry
	reqs  map[string]*pairReq
	fails int
	now   func() time.Time
}

func newPairing() *pairing {
	return &pairing{codes: map[string]time.Time{}, reqs: map[string]*pairReq{}, now: time.Now}
}

func randString(alphabet string, n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	for i := range b {
		b[i] = alphabet[int(b[i])%len(alphabet)] // 256 % 30 biases < 1 bit per character: tolerable for a 5-minute code
	}
	return string(b)
}

// formatCode formats the code for humans: K7Q4-M2XD.
func formatCode(c string) string {
	if len(c) == codeLen {
		return c[:codeLen/2] + "-" + c[codeLen/2:]
	}
	return c
}

// gcLocked drops expired codes and requests; the caller holds p.mu.
func (p *pairing) gcLocked() {
	now := p.now()
	for c, exp := range p.codes {
		if !now.Before(exp) {
			delete(p.codes, c)
		}
	}
	for id, r := range p.reqs {
		if r.Status == "pending" && now.UnixMilli() >= r.ExpiresAt {
			delete(p.reqs, id)
		}
		if r.Status != "pending" && now.UnixMilli()-r.DecidedAt > pairKeepDone.Milliseconds() {
			delete(p.reqs, id)
		}
	}
}

// start issues a new one-time code (earlier active codes stay until they expire).
func (p *pairing) start(ttl time.Duration) (string, time.Time) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.gcLocked()
	code := randString(codeAlphabet, codeLen)
	exp := p.now().Add(ttl)
	p.codes[code] = exp
	p.fails = 0
	return code, exp
}

// drop withdraws a code that was never shown (the relay refused the pairing window).
func (p *pairing) drop(code string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	delete(p.codes, code)
}

func (p *pairing) activeCodes() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.gcLocked()
	return len(p.codes)
}

// submit handles a device request. trusted reports an already trusted device (approved at once).
// Returns the request, or a machine-readable refusal reason.
func (p *pairing) submit(pp envelope.PairPayload, sig, supervisorID, remote string, window time.Duration, trusted func(id string) bool) (*pairReq, string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.gcLocked()
	if len(p.codes) == 0 {
		return nil, "pairing_not_active"
	}
	code := envelope.NormalizeCode(pp.Code)
	if _, ok := p.codes[code]; !ok || code != pp.Code {
		p.fails++
		if p.fails >= maxPairFails {
			p.codes = map[string]time.Time{}
			p.fails = 0
		}
		return nil, "bad_code"
	}
	if !hex64re(pp.DeviceID) {
		return nil, "device_id_invalid"
	}
	alg, err := envelope.NormalizeAlg(pp.Alg)
	if err != nil || (pp.Alg != "" && pp.Alg != alg) {
		return nil, "alg_unsupported"
	}
	pub, err := envelope.ParseDeviceKey(alg, pp.Pubkey)
	if err != nil {
		return nil, "pubkey_invalid"
	}
	if pub.ID() != pp.DeviceID {
		return nil, "device_id_mismatch"
	}
	if _, err := relaylink.ParseEncKey(pp.Enc); err != nil { // the key is under the signature below
		return nil, "enc_invalid"
	}
	if pp.SupervisorID != supervisorID {
		return nil, "wrong_supervisor"
	}
	if d := p.now().Sub(time.UnixMilli(pp.Ts)); d > window || d < -window {
		return nil, "stale_timestamp"
	}
	if len(pp.Nonce) < minNonceLen || len(pp.Nonce) > maxNonceLen {
		return nil, "nonce_invalid"
	}
	name := cleanName(pp.Name)
	if name != pp.Name {
		return nil, "name_invalid"
	}
	msg, err := envelope.PairSigningString(pp)
	if err != nil || !pub.Verify(msg, sig) {
		return nil, "bad_signature"
	}
	delete(p.codes, code) // one-time
	now := p.now()
	for _, r := range p.reqs { // a retry from the same device gets the same request
		if r.DeviceID == pp.DeviceID && r.Status == "pending" {
			r.Enc = pp.Enc
			return r, ""
		}
	}
	r := &pairReq{ID: "p-" + randString(idAlphabet, idLen), DeviceID: pp.DeviceID, Pubkey: pub.B64(), Alg: alg, Enc: pp.Enc, Name: name,
		Fingerprint: envelope.Fingerprint(pp.DeviceID), Remote: remote, CreatedAt: now.UnixMilli(), ExpiresAt: now.Add(pairReqTTL).UnixMilli(), Status: "pending"}
	if trusted != nil && trusted(pp.DeviceID) {
		r.Status, r.DecidedAt = "approved", now.UnixMilli()
	} else if p.pendingLocked() >= maxPairReqs {
		return nil, "too_many_requests"
	}
	p.reqs[r.ID] = r
	return r, ""
}

// bind records the pair frame that carried request id (a retry of the device replaces it): the
// pair.status frames about the request name that frame.
func (p *pairing) bind(id, re string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if r := p.reqs[id]; r != nil {
		r.Re = re
	}
}

func (p *pairing) pendingLocked() (n int) {
	for _, r := range p.reqs {
		if r.Status == "pending" {
			n++
		}
	}
	return
}

// cleanName makes a device name for humans: at most maxNameRunes characters, no control
// characters and no line or paragraph separators.
func cleanName(s string) string {
	s = strings.TrimSpace(s)
	s = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) || r == '\u2028' || r == '\u2029' {
			return -1
		}
		return r
	}, s)
	if r := []rune(s); len(r) > maxNameRunes {
		s = string(r[:maxNameRunes])
	}
	return s
}

func hex64re(s string) bool {
	if len(s) != 64 {
		return false
	}
	for _, c := range s {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

func (p *pairing) get(id string) *pairReq {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.gcLocked()
	if r := p.reqs[id]; r != nil {
		c := *r
		return &c
	}
	return nil
}

func (p *pairing) list() []pairReq {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.gcLocked()
	out := make([]pairReq, 0, len(p.reqs))
	for _, r := range p.reqs {
		out = append(out, *r)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt < out[j].CreatedAt })
	return out
}

// decide moves a pending request to approved/rejected; commit is called under the lock before the
// status changes (the config write): on error the request stays pending.
func (p *pairing) decide(id, status string, commit func(r pairReq) error) (pairReq, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.gcLocked()
	r := p.reqs[id]
	if r == nil {
		return pairReq{}, fmt.Errorf("no request %s (expired or never existed; wardend pair list)", id)
	}
	if r.Status != "pending" {
		return *r, fmt.Errorf("request %s is already %s", id, r.Status)
	}
	if commit != nil {
		if err := commit(*r); err != nil {
			return *r, err
		}
	}
	r.Status, r.DecidedAt = status, p.now().UnixMilli()
	return *r, nil
}

// ---------- supervisor actions (RPC pair.*) ----------

var errPeerSupervised = errors.New("refused: called from under the wardend filter (the agent can't manage pairing itself); run the command in your own terminal on the server")

// pairStart issues a one-time code: the pairing window is opened on the relay before the link is
// returned, so the phone can send at once. No window (the relay is off, unreachable or refused it)
// means no code: the link would lead nowhere.
func (s *supervisor) pairStart(ttl time.Duration) (map[string]any, error) {
	if s.relay == nil {
		reason := "relay_url is off"
		if s.relayErr != "" {
			reason = "the relay link did not start: " + s.relayErr
		}
		return nil, errors.New(reason + ", so a device has no way to reach this wardend")
	}
	// the link names a wss:// relay and nothing else (the app refuses any other): relay_url may
	// be ws:// for a loopback relay, and then there is no link to print
	if !strings.HasPrefix(s.cfg.RelayURL, "wss://") && !s.pairWS {
		return nil, fmt.Errorf("relay_url %s is not wss://: a pair link can only name a wss:// relay", s.cfg.RelayURL)
	}
	return s.pairOpenRelay(ttl)
}

// pairOpenRelay is pairStart after the check of the relay's address: the code, the window on
// the relay, the link.
func (s *supervisor) pairOpenRelay(ttl time.Duration) (map[string]any, error) {
	if ttl <= 0 || ttl > relayPairWindowMax {
		ttl = min(s.cfg.PairCodeTTL.Duration, relayPairWindowMax)
	}
	code, exp := s.pair.start(ttl)
	if err := s.relay.setPairing(context.Background(), exp); err != nil {
		s.pair.drop(code)
		s.relayPairingSync()
		return nil, fmt.Errorf("relay %s: cannot open the pairing window: %w (wardend status shows the relay state)", s.cfg.RelayURL, err)
	}
	time.AfterFunc(time.Until(exp)+time.Second, s.relayPairingSync) // the code expired unused: close the window
	u := s.cfg.RelayURL + "/v1/ws"
	link := envelope.PairLink{Relay: u, SID: s.supervisorID, Key: s.jr.PublicKey(), Enc: s.relay.encPublic(), Code: code, Host: s.host}
	s.journal("pair_start", map[string]any{"expiresAt": exp.UnixMilli(), "relay": u})
	return map[string]any{"ok": true, "code": code, "codeDisplay": formatCode(code), "expiresAt": exp.UnixMilli(), "relay": u,
		"link": link.String(), "supervisorKey": link.Key, "supervisorId": s.supervisorID, "supervisorFingerprint": envelope.Fingerprint(s.supervisorID), "host": s.host}, nil
}

func (s *supervisor) pairList() map[string]any {
	devs := []map[string]any{}
	for _, d := range s.devices.List() {
		alg, _ := envelope.NormalizeAlg(d.Alg)
		devs = append(devs, map[string]any{"id": d.ID, "alg": alg, "name": d.Name, "fingerprint": envelope.Fingerprint(d.ID), "addedAt": d.AddedAt, "hasPubkey": d.Pubkey != "", "valid": hex64re(d.ID)})
	}
	return map[string]any{"ok": true, "requests": s.pair.list(), "devices": devs, "activeCodes": s.pair.activeCodes(), "relay": s.relayInfo(), "config": s.cfg.path}
}

func (s *supervisor) pairApprove(id string) (map[string]any, error) {
	r, err := s.pair.decide(id, "approved", func(r pairReq) error {
		td := envelope.TrustedDevice{ID: r.DeviceID, Pubkey: r.Pubkey, Enc: r.Enc, Name: r.Name, AddedAt: time.Now().UTC().Format(time.RFC3339)}
		if r.Alg != envelope.AlgEd25519 {
			td.Alg = r.Alg // ed25519 is not written: the config stays readable by older versions
		}
		if err := editTrustedDevices(s.cfg.path, func(list []envelope.TrustedDevice) ([]envelope.TrustedDevice, error) {
			return append(withoutDevice(list, td.ID), td), nil
		}); err != nil {
			return fmt.Errorf("write %s: %w", s.cfg.path, err)
		}
		s.devices.Add(td)
		return nil
	})
	if err != nil {
		return nil, err
	}
	s.relayDevicesChanged()
	s.relayPairStatus(r)
	s.journal("pair_approved", map[string]any{"id": r.ID, "deviceId": r.DeviceID, "pubkey": r.Pubkey, "alg": r.Alg, "name": r.Name, "remote": r.Remote})
	return map[string]any{"ok": true, "request": r, "config": s.cfg.path}, nil
}

func (s *supervisor) pairReject(id string) (map[string]any, error) {
	r, err := s.pair.decide(id, "rejected", nil)
	if err != nil {
		return nil, err
	}
	s.relayPairStatus(r)
	s.journal("pair_rejected", map[string]any{"id": r.ID, "deviceId": r.DeviceID, "name": r.Name, "remote": r.Remote})
	return map[string]any{"ok": true, "request": r}, nil
}

// pairRevoke removes a device from trusted_devices (id or a unique prefix of ≥ 8 hex).
func (s *supervisor) pairRevoke(ref string) (map[string]any, error) {
	ref = strings.ToLower(strings.ReplaceAll(strings.TrimSpace(ref), " ", ""))
	if len(ref) < 8 {
		return nil, errors.New("specify a deviceId or its prefix (at least 8 characters)")
	}
	var match []envelope.TrustedDevice
	for _, d := range s.devices.List() {
		if strings.HasPrefix(d.ID, ref) {
			match = append(match, d)
		}
	}
	if len(match) != 1 {
		return nil, fmt.Errorf("prefix %q matches %d devices", ref, len(match))
	}
	id := match[0].ID
	if err := editTrustedDevices(s.cfg.path, func(list []envelope.TrustedDevice) ([]envelope.TrustedDevice, error) {
		return withoutDevice(list, id), nil
	}); err != nil {
		return nil, fmt.Errorf("write %s: %w", s.cfg.path, err)
	}
	s.devices.Remove(id)
	s.relayDevicesChanged()
	s.journal("device_revoked", map[string]any{"deviceId": id, "name": match[0].Name})
	return map[string]any{"ok": true, "deviceId": id, "name": match[0].Name, "config": s.cfg.path}, nil
}

// withoutDevice drops the entries of device id (lower case) from the trusted_devices of the
// config file. Their ids may be written by hand, so they are compared the way the config loader
// normalizes them (case and surrounding spaces): approve and revoke match the same entries.
func withoutDevice(list []envelope.TrustedDevice, id string) []envelope.TrustedDevice {
	out := list[:0]
	for _, d := range list {
		if strings.ToLower(strings.TrimSpace(d.ID)) != id {
			out = append(out, d)
		}
	}
	return out
}

// peerSupervised reports whether the socket's client process runs under this wardend's seccomp
// filter (the agent, the gateway and their descendants): it has more filters than the supervisor
// itself, or it descends from the supervisor's child. A /proc read error counts as "under the
// filter" (fail-closed).
func (s *supervisor) peerSupervised(pid int) bool {
	if pid <= 0 {
		return true
	}
	own, ok1 := seccompFilters(os.Getpid())
	peer, ok2 := seccompFilters(pid)
	if !ok1 || !ok2 || peer > own {
		return true
	}
	return underChild(pid, s.childPid, ppidOf)
}

// underChild reports whether pid is the process child or its descendant, following parentOf up
// to init. Like a /proc read error, a chain that does not reach init within maxAncestors links
// counts as "under the child" (fail-closed).
func underChild(pid, child int, parentOf func(int) (int, bool)) bool {
	cur := pid
	for i := 0; i < maxAncestors && cur > 1; i++ {
		if child > 0 && cur == child {
			return true
		}
		pp, ok := parentOf(cur)
		if !ok {
			return true
		}
		cur = pp
	}
	return cur > 1 // the walk ran out of links before init
}

func seccompFilters(pid int) (int, bool) {
	n, err := procStatusInt(pid, "Seccomp_filters:")
	if errors.Is(err, errNoStatusField) {
		return 0, true // an old kernel without the field: no filters visible
	}
	return n, err == nil
}

func ppidOf(pid int) (int, bool) {
	n, err := procStatusInt(pid, "PPid:")
	return n, err == nil
}

var errNoStatusField = errors.New("no such field in /proc/<pid>/status")

// procStatusInt reads the integer value of a field ("PPid:") of /proc/<pid>/status.
func procStatusInt(pid int, field string) (int, error) {
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid))
	if err != nil {
		return 0, err
	}
	for _, l := range strings.Split(string(b), "\n") {
		if v, ok := strings.CutPrefix(l, field); ok {
			var n int
			_, err := fmt.Sscan(strings.TrimSpace(v), &n)
			return n, err
		}
	}
	return 0, errNoStatusField
}
