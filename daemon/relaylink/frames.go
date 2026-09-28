// SPDX-License-Identifier: AGPL-3.0-or-later

// Package relaylink is the wire of the relay transport (protocol/README.md) shared by its two
// ends: the WebSocket client (ws.go), the frames and the signed hello (this file), the AEAD box
// (box.go) and the device side of a channel (device.go). wardend builds its supervisor client on
// it, wardenctl is a device.
package relaylink

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"time"

	"github.com/xarvel/WardenClaw/daemon/envelope"
)

const (
	HelloType = "wardenclaw.relay.hello.v1"
	CardType  = "wardenclaw.card.v1"

	FrameMax     = 64 << 10 // a larger frame is refused by the relay (close 1009)
	HelloTimeout = 15 * time.Second
)

// Error is an error frame of the relay ({type:"error", code}).
type Error struct{ Code string }

func (e *Error) Error() string { return "relay: " + e.Code }

// Envelope is an envelope frame (msg, pair) as the relay forwards it.
type Envelope struct {
	Type string `json:"type"`
	ID   string `json:"id"`
	To   string `json:"to"`
	From string `json:"from,omitempty"`
	Seq  int64  `json:"seq,omitempty"`
	Ts   int64  `json:"ts"`
	Exp  int64  `json:"exp"`
	Body string `json:"body"`
	Kind string `json:"kind,omitempty"`
}

// Frame is the union of the relay frames a client reads.
type Frame struct {
	Envelope
	Nonce    string `json:"nonce"`
	Code     string `json:"code"`
	Close    bool   `json:"close"`
	What     string `json:"what"`
	Role     string `json:"role"`
	Online   bool   `json:"online"` // peer: the supervisor is connected to the relay
	Protocol int    `json:"protocol"`
	Count    int    `json:"count"`
	Until    int64  `json:"until"`
	Limits   struct {
		Frame int   `json:"frame"`
		Queue int   `json:"queue"`
		TTL   int64 `json:"ttl"`
	} `json:"limits"`
}

// Hello builds the signed hello frame of section 3 for a role (supervisor, device): key is the
// Ed25519 identity, enc the X25519 public key (base64url), nonce the relay's challenge. name and
// version describe the program.
func Hello(role, name, version string, key ed25519.PrivateKey, enc, nonce string, ts int64) (map[string]any, error) {
	client := map[string]any{"name": name, "version": version, "protocol": envelope.Protocol}
	pub := envelope.B64URL(key.Public().(ed25519.PublicKey))
	msg, err := envelope.Canonical(map[string]any{"type": HelloType, "role": role, "key": pub, "enc": enc, "ts": ts, "nonce": nonce, "client": client})
	if err != nil {
		return nil, err
	}
	return map[string]any{"type": "hello", "role": role, "key": pub, "enc": enc, "ts": ts, "nonce": nonce, "client": client,
		"sig": envelope.B64URL(ed25519.Sign(key, msg))}, nil
}

// MsgID is a fresh id of an envelope frame.
func MsgID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// CardSigningString returns canonicalJson({type:"wardenclaw.card.v1", id, digest, createdAt,
// expiresAt}): what the supervisor signs in every card it sends (supervisorSig).
func CardSigningString(id, digest string, createdAt, expiresAt int64) ([]byte, error) {
	return envelope.Canonical(map[string]any{"type": CardType, "id": id, "digest": digest, "createdAt": createdAt, "expiresAt": expiresAt})
}
