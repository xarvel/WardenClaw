// SPDX-License-Identifier: AGPL-3.0-or-later

package envelope

// Pairing: the signed request of a new device and the link in the QR code. Both are built
// byte-for-byte as the app builds them (cross-fixture protocol/vectors/relay_vectors.json).
//
// The pairing request (a `pair` frame on the relay) is signed by the NEW device key together with
// the one-time code and the supervisor id from the QR: another supervisor cannot replay the
// request against itself. Decisions are self-signed tickets (ticket.go).

import (
	"crypto/ed25519"
	"errors"
	"net/url"
	"strings"
)

// PairType is the signing string type of a pairing request.
const PairType = "wardenclaw.pair.v1"

// PairPayload is the signed part of a pairing request.
type PairPayload struct {
	Code         string `json:"code"`
	DeviceID     string `json:"deviceId"`
	Pubkey       string `json:"pubkey"`        // ed25519: base64url raw 32 bytes; es256: base64url SEC1 65 bytes
	Alg          string `json:"alg,omitempty"` // "ed25519" (default) | "es256"; when present it is included in the signature
	Enc          string `json:"enc"`           // X25519 key of the device, base64url 32 bytes
	Name         string `json:"name"`
	SupervisorID string `json:"supervisorId"`
	Ts           int64  `json:"ts"`
	Nonce        string `json:"nonce"`
}

// PairSigningString returns
// canonicalJson({type:"wardenclaw.pair.v1", code, deviceId, pubkey, enc, name, supervisorId, ts, nonce[, alg]}).
// enc puts the device's encryption key under the signature of its identity key. alg is included
// when present in the body (es256 must send it): the algorithm cannot be replaced without
// breaking the new key's signature.
func PairSigningString(p PairPayload) ([]byte, error) {
	m := map[string]any{"type": PairType, "code": p.Code, "deviceId": p.DeviceID, "pubkey": p.Pubkey, "enc": p.Enc,
		"name": p.Name, "supervisorId": p.SupervisorID, "ts": p.Ts, "nonce": p.Nonce}
	if p.Alg != "" {
		m["alg"] = p.Alg
	}
	return Canonical(m)
}

// VerifySig verifies a base64url signature over msg.
func VerifySig(pub ed25519.PublicKey, msg []byte, sig string) bool {
	b, err := DecodeB64URL(sig)
	return err == nil && len(b) == ed25519.SignatureSize && len(pub) == ed25519.PublicKeySize && ed25519.Verify(pub, msg, b)
}

// NormalizeCode strips dashes and spaces from a pairing code and uppercases it.
func NormalizeCode(s string) string {
	return strings.ToUpper(strings.NewReplacer("-", "", " ", "").Replace(strings.TrimSpace(s)))
}

// Fingerprint returns a human-readable device fingerprint: first 16 hex chars of deviceId in groups of 4.
func Fingerprint(deviceID string) string {
	if len(deviceID) < 16 {
		return deviceID
	}
	d := deviceID[:16]
	return d[0:4] + " " + d[4:8] + " " + d[8:12] + " " + d[12:16]
}

// PairLink is the QR content:
// wardenclaw://pair?code=***&enc=...&host=...&key=***&relay=wss://…/v1/ws&sid=...&v=1
// (relay: the relay endpoint without the channel; sid: supervisorId, the channel; key: supervisor
// public key base64url; enc: the supervisor's X25519 key, base64url; code: one-time code; host:
// display-only hostname).
type PairLink struct {
	Relay string
	SID   string
	Key   string
	Enc   string
	Code  string
	Host  string
}

// String returns the link as encoded in the QR code.
func (l PairLink) String() string {
	q := url.Values{}
	q.Set("v", "1")
	q.Set("relay", l.Relay)
	q.Set("sid", l.SID)
	q.Set("enc", l.Enc)
	q.Set("key", l.Key)
	q.Set("code", l.Code)
	if l.Host != "" {
		q.Set("host", l.Host)
	}
	return "wardenclaw://pair?" + q.Encode()
}

// ParsePairLink parses a wardenclaw://pair link (wardenctl pair, tests).
func ParsePairLink(s string) (PairLink, error) {
	u, err := url.Parse(strings.TrimSpace(s))
	if err != nil || u.Scheme != "wardenclaw" || u.Host != "pair" {
		return PairLink{}, errors.New("not a wardenclaw://pair link")
	}
	q := u.Query()
	if q.Get("v") != "1" {
		return PairLink{}, errors.New("unsupported link version")
	}
	l := PairLink{Relay: q.Get("relay"), SID: q.Get("sid"), Key: q.Get("key"), Enc: q.Get("enc"), Code: q.Get("code"), Host: q.Get("host")}
	if l.Relay == "" || l.SID == "" || l.Enc == "" || l.Key == "" || l.Code == "" {
		return PairLink{}, errors.New("link: relay, sid, key, enc and code are required")
	}
	if !strings.HasPrefix(l.Relay, "wss://") {
		return PairLink{}, errors.New("link: relay must be wss://")
	}
	if enc, err := DecodeB64URL(l.Enc); err != nil || len(enc) != 32 {
		return PairLink{}, errors.New("link: enc is not a 32-byte key")
	}
	pub, err := DecodeKey(l.Key)
	if err != nil {
		return PairLink{}, err
	}
	if DeviceID(pub) != l.SID { // the channel is the id of the key in the same link
		return PairLink{}, errors.New("link: sid is not the id of key")
	}
	return l, nil
}
