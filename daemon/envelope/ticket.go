// SPDX-License-Identifier: AGPL-3.0-or-later

package envelope

// A ticket is a signed decision from a WardenClaw device. Same envelope as the
// wardenclaw-gate plugin (POST /wardenclaw/decide), but the signing string carries the ticket
// type so that a plugin tool-call decision cannot be presented as a wardend exec decision
// (crypto review 2026-09-28, finding 1):
//
//	{deviceId, payload:{type, supervisorId, id, digest, decision, ts, nonce}, signature}
//	signature = Ed25519(device key, canonicalJson({type,supervisorId,deviceId,id,digest,decision,ts,nonce})) base64url
//	            (for es256 devices: ECDSA P-256/SHA-256 over the same bytes, raw r||s or DER)
//
// type = TicketExec ("wardenclaw.ticket.exec.v1") for wardend entries; supervisorId = id of
// the supervisor key that queued the entry (requester.supervisorId of the envelope). wardend
// accepts only TicketExec with its own supervisorId. TicketTool ("wardenclaw.ticket.tool.v1")
// is for plugin tool-call decisions, without supervisorId; wardend rejects it (ticket_type_mismatch).
//
// id = PendingID(digest) ("wd-..."); digest = sha256 of canonical envelope.
//
// Optional fields:
//
//	payload.risk  integer 0..100: risk score from the app judge; when present it is included
//	              in the signing string ({..., "risk":N}) and in the second-factor challenge.
//	              Policy require_hardware.min_score is compared against it (only tightens,
//	              see docs/CLI.md).
//	hw            second signature by hardware key (FIDO2 assertion, YubiKey); see HWChallenge
//	              and protocol/HARDWARE.md. Not part of the device signing string: it is
//	              bound to the ticket via the challenge.

import (
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/xarvel/WardenClaw/daemon/hwkey"
)

// Ticket types (signing string domain).
const (
	TicketExec = "wardenclaw.ticket.exec.v1" // wardend entry, carries supervisorId
	TicketTool = "wardenclaw.ticket.tool.v1" // wardenclaw-gate plugin tool-call, no supervisorId
)

// Bounds checked by ParseDecision.
const (
	minNonceLen = 8
	maxNonceLen = 128
	maxRisk     = 100 // payload.risk is 0..maxRisk
)

// DecisionPayload is the device-signed part of a ticket.
type DecisionPayload struct {
	Type         string       `json:"type"`                   // TicketExec | TicketTool
	SupervisorID string       `json:"supervisorId,omitempty"` // TicketExec only
	ID           string       `json:"id"`
	Digest       string       `json:"digest"`
	Decision     string       `json:"decision"` // allow | deny
	Ts           json.Number  `json:"ts"`
	Nonce        string       `json:"nonce"`
	Risk         *json.Number `json:"risk,omitempty"` // 0..100, optional
}

// DecisionBody is a ticket as the device sends it: payload, device signature and an optional
// hardware-key assertion.
type DecisionBody struct {
	DeviceID  string           `json:"deviceId"`
	Payload   DecisionPayload  `json:"payload"`
	Signature string           `json:"signature"`
	HW        *hwkey.Assertion `json:"hw,omitempty"` // second signature (YubiKey), optional
}

// RiskScore returns the risk score from the signed payload (ok=false if not present).
func (p DecisionPayload) RiskScore() (int, bool) {
	if p.Risk == nil {
		return 0, false
	}
	n, err := p.Risk.Int64()
	if err != nil {
		return 0, false
	}
	return int(n), true
}

var hex64 = regexp.MustCompile(`^[0-9a-f]{64}$`)

// SigningString returns the bytes the device signs (matches decisionSigningString).
func SigningString(deviceID string, p DecisionPayload) ([]byte, error) {
	return Canonical(signingMap(deviceID, p))
}

func signingMap(deviceID string, p DecisionPayload) map[string]any {
	m := map[string]any{"type": p.Type, "deviceId": deviceID, "id": p.ID, "digest": p.Digest, "decision": p.Decision, "ts": p.Ts, "nonce": p.Nonce}
	if p.SupervisorID != "" {
		m["supervisorId"] = p.SupervisorID
	}
	if p.Risk != nil {
		m["risk"] = *p.Risk
	}
	return m
}

// HWType is the domain for the second-factor challenge.
const HWType = "wardenclaw.hw.v1"

// HWChallenge returns the challenge for the FIDO2 assertion (what the app puts in
// clientDataJSON.challenge):
//
//	sha256(canonicalJson({type:"wardenclaw.hw.v1", ticket, supervisorId, deviceId, id, digest, decision, ts, nonce[, risk]}))
//
// Same fields as the device signing string, plus a domain: type is the second-factor domain,
// and the ticket type moves to the "ticket" field. An assertion is valid for exactly one ticket
// (this type and supervisor, this digest, this decision, this nonce) and cannot be reused for
// another exec or as a device signature. clientDataHash = sha256(clientDataJSON) is what
// the key actually signs.
func HWChallenge(deviceID string, p DecisionPayload) ([]byte, error) {
	m := signingMap(deviceID, p)
	m["ticket"] = p.Type
	m["type"] = HWType
	b, err := Canonical(m)
	if err != nil {
		return nil, err
	}
	h := sha256.Sum256(b)
	return h[:], nil
}

// ParseDecision parses without trusting types (like parseDecisionBody in the plugin).
func ParseDecision(raw []byte) (*DecisionBody, error) {
	var b DecisionBody
	d := json.NewDecoder(strings.NewReader(string(raw)))
	d.UseNumber()
	if err := d.Decode(&b); err != nil {
		return nil, errors.New("body_invalid_json")
	}
	switch {
	case !hex64.MatchString(b.DeviceID):
		return nil, errors.New("device_id_invalid")
	case b.Payload.Type != TicketExec && b.Payload.Type != TicketTool:
		return nil, errors.New("type_invalid")
	case b.Payload.Type == TicketExec && !hex64.MatchString(b.Payload.SupervisorID),
		b.Payload.Type == TicketTool && b.Payload.SupervisorID != "":
		return nil, errors.New("supervisor_id_invalid")
	case b.Signature == "":
		return nil, errors.New("signature_missing")
	case b.Payload.ID == "":
		return nil, errors.New("id_missing")
	case !hex64.MatchString(b.Payload.Digest):
		return nil, errors.New("digest_invalid")
	case b.Payload.Decision != "allow" && b.Payload.Decision != "deny":
		return nil, errors.New("decision_invalid")
	case len(b.Payload.Nonce) < minNonceLen || len(b.Payload.Nonce) > maxNonceLen:
		return nil, errors.New("nonce_invalid")
	}
	// ts is Date.now(): an integer literal within the JS safe range, so a journal entry that
	// carries the ticket never meets a number it would have to round or refuse.
	if n, err := b.Payload.Ts.Int64(); err != nil || n < 0 || n > MaxSafeInt || b.Payload.Ts.String() != fmt.Sprint(n) {
		return nil, errors.New("ts_invalid")
	}
	if b.Payload.Risk != nil {
		n, err := b.Payload.Risk.Int64()
		if err != nil || n < 0 || n > maxRisk || b.Payload.Risk.String() != fmt.Sprint(n) {
			return nil, errors.New("risk_invalid")
		}
	}
	if h := b.HW; h != nil && (h.CredentialID == "" || h.ClientDataJSON == "" || h.AuthenticatorData == "" || h.Signature == "") {
		return nil, errors.New("hw_invalid")
	}
	return &b, nil
}

// ed25519SmallOrder are the eight points of order dividing 8, in every 32-byte encoding
// crypto/ed25519.Verify accepts: the canonical point, the non-canonical x=0 sign bit, and
// y+p when that still fits in 255 bits. Verify accepts a forged signature under these keys
// (for the identity, under every message). Pairing and config load both go through DecodeKey.
var ed25519SmallOrder = decodeSmallOrder([]string{
	"0100000000000000000000000000000000000000000000000000000000000000",
	"0100000000000000000000000000000000000000000000000000000000000080",
	"0000000000000000000000000000000000000000000000000000000000000000",
	"0000000000000000000000000000000000000000000000000000000000000080",
	"ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
	"ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
	"26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
	"26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85",
	"c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
	"c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa",
	"edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
	"edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
	"eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
	"eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
})

func decodeSmallOrder(hexes []string) [][]byte {
	out := make([][]byte, len(hexes))
	for i, h := range hexes {
		b, err := hex.DecodeString(h)
		if err != nil || len(b) != ed25519.PublicKeySize {
			panic("ed25519 small-order table")
		}
		out[i] = b
	}
	return out
}

func smallOrderEd25519(b []byte) bool {
	if len(b) != ed25519.PublicKeySize {
		return false
	}
	for _, p := range ed25519SmallOrder {
		if subtle.ConstantTimeCompare(b, p) == 1 {
			return true
		}
	}
	return false
}

// DecodeKey parses an Ed25519 public key: base64url raw 32 bytes (as stored in the gateway) or hex.
func DecodeKey(s string) (ed25519.PublicKey, error) {
	s = strings.TrimSpace(s)
	var b []byte
	if len(s) == 64 {
		if h, err := hex.DecodeString(s); err == nil {
			b = h
		}
	}
	if b == nil {
		var err error
		b, err = DecodeB64URL(s)
		if err != nil {
			return nil, err
		}
	}
	if len(b) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("public key must be 32 bytes, got %d", len(b))
	}
	if smallOrderEd25519(b) {
		return nil, errors.New("ed25519 public key has small order")
	}
	return ed25519.PublicKey(b), nil
}

// DecodeB64URL decodes base64url without padding, the one form every producer emits (the app,
// the watch, the plugin, wardenctl, wardend itself). Padding, the standard alphabet, whitespace
// and non-zero trailing bits are rejected: a key or a signature then has exactly one spelling,
// so nothing addressed by its encoded bytes can be reached under a variant spelling.
func DecodeB64URL(s string) ([]byte, error) {
	b, err := base64.RawURLEncoding.Strict().DecodeString(s)
	if err != nil {
		return nil, err
	}
	if B64URL(b) != s {
		return nil, errors.New("base64url: not the canonical unpadded form")
	}
	return b, nil
}

// B64URL encodes b as base64url without padding.
func B64URL(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// DeviceID returns sha256(raw pubkey) as hex (OpenClaw convention).
func DeviceID(pub ed25519.PublicKey) string { return SHA256Hex(pub) }

// Sign creates a signed exec ticket for supervisor supervisorID (used by `wardend approve`
// and tests; the app does the same in gate.ts).
func Sign(priv ed25519.PrivateKey, supervisorID, id, digest, decision string, tsMs int64, nonce string) DecisionBody {
	return SignPayload(priv, ExecPayload(supervisorID, id, digest, decision, tsMs, nonce))
}

// ExecPayload builds the payload for a wardend exec ticket (without risk).
func ExecPayload(supervisorID, id, digest, decision string, tsMs int64, nonce string) DecisionPayload {
	return DecisionPayload{Type: TicketExec, SupervisorID: supervisorID, ID: id, Digest: digest, Decision: decision, Ts: json.Number(fmt.Sprint(tsMs)), Nonce: nonce}
}

// SignPayload signs an arbitrary payload (including payloads with risk).
func SignPayload(priv ed25519.PrivateKey, p DecisionPayload) DecisionBody {
	pub := priv.Public().(ed25519.PublicKey)
	did := DeviceID(pub)
	msg, _ := SigningString(did, p)
	return DecisionBody{DeviceID: did, Payload: p, Signature: B64URL(ed25519.Sign(priv, msg))}
}

// NonceCache ensures nonce uniqueness within a 2×window per device (like NonceCache in the plugin).
type NonceCache struct {
	mu     sync.Mutex
	window time.Duration
	seen   map[string]time.Time
}

// nonceSweepSize is the cache size above which Claim drops expired entries; below it Claim
// does not scan the map.
const nonceSweepSize = 5000

// NewNonceCache returns an empty cache that remembers each nonce for 2×window.
func NewNonceCache(window time.Duration) *NonceCache {
	return &NonceCache{window: window, seen: map[string]time.Time{}}
}

// Claim records the nonce of deviceID and reports whether it was not seen in the last 2×window.
func (c *NonceCache) Claim(deviceID, nonce string, now time.Time) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.seen) > nonceSweepSize {
		for k, exp := range c.seen {
			if !exp.After(now) {
				delete(c.seen, k)
			}
		}
	}
	k := deviceID + "\n" + nonce
	if exp, ok := c.seen[k]; ok && exp.After(now) {
		return false
	}
	c.seen[k] = now.Add(2 * c.window)
	return true
}

// VerifyCtx holds everything needed to verify a ticket.
type VerifyCtx struct {
	Now          time.Time
	TsWindow     time.Duration
	SupervisorID string // this supervisor's id: exec ticket for another supervisor is rejected
	Devices      *Devices
	Nonces       *NonceCache
	// Pending returns the digest of the pending entry by id ("" if not found).
	Pending func(id string) string
}

// Claimed reports whether Verify returns this reason only after a valid device signature and
// a claimed nonce (or accepted the ticket): wardend signs its response to such a ticket with a
// request binding (ResponseSigningString); all other reasons use UnauthSigningString.
func Claimed(reason string) bool {
	return reason == "" || reason == "unknown_pending" || reason == "digest_mismatch"
}

// Verify performs a full ticket check. Order matches the plugin: nonce is claimed only
// after a successful signature check (otherwise an unauthenticated request could "burn"
// someone else's nonce). Only an exec ticket for this supervisor is accepted: a plugin
// tool-call ticket or a ticket for another wardend is rejected before signature verification.
// Returns a machine-readable rejection reason ("" means ok).
func Verify(b *DecisionBody, c VerifyCtx) string {
	if b.Payload.Type != TicketExec {
		return "ticket_type_mismatch"
	}
	if c.SupervisorID == "" || b.Payload.SupervisorID != c.SupervisorID {
		return "supervisor_mismatch"
	}
	pub, reason := c.Devices.Key(b.DeviceID)
	if reason != "" {
		return reason
	}
	tsf, _ := b.Payload.Ts.Float64()
	ts := time.UnixMilli(int64(tsf))
	if d := c.Now.Sub(ts); d > c.TsWindow || d < -c.TsWindow {
		return "stale_timestamp"
	}
	msg, err := SigningString(b.DeviceID, b.Payload)
	if err != nil {
		return "signing_string: " + err.Error()
	}
	if !pub.Verify(msg, b.Signature) { // Ed25519 or ES256, based on algorithm from trusted_devices
		return "bad_signature"
	}
	if !c.Nonces.Claim(b.DeviceID, b.Payload.Nonce, c.Now) {
		return "nonce_reused"
	}
	want := c.Pending(b.Payload.ID)
	if want == "" {
		return "unknown_pending"
	}
	if want != b.Payload.Digest {
		return "digest_mismatch"
	}
	return ""
}
