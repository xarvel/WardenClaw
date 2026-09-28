// SPDX-License-Identifier: AGPL-3.0-or-later

package relaylink

// Payload encryption of the relay transport (protocol/README.md section 11): one AEAD box between
// the supervisor and a device. The relay carries the box and cannot open it.
//
//	shared = X25519(my enc private, their enc public)
//	key    = HKDF-SHA256(ikm = shared, salt = sha256(supervisorId || deviceId), info = "wardenclaw.relay.v1")
//	body   = b64url(nonce(24) || XChaCha20-Poly1305(key, nonce, plaintext, aad))
//	aad    = canonicalJson({type:"wardenclaw.relay.aad.v1", id, from, to, kind, exp})
//
// The encryption key is separate from the Ed25519 identity key and is bound to it by the pairing
// link (the supervisor) or by the signed pairing request (a device).

import (
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"errors"

	"golang.org/x/crypto/chacha20poly1305"

	"github.com/xarvel/WardenClaw/daemon/envelope"
)

const (
	BoxInfo = "wardenclaw.relay.v1"
	AADType = "wardenclaw.relay.aad.v1"
)

// ErrBox: a body that does not decrypt, whatever the cause.
var ErrBox = errors.New("relay: box does not open")

// ParseEncKey decodes a party's X25519 public key (base64url, 32 bytes).
func ParseEncKey(s string) (*ecdh.PublicKey, error) {
	raw, err := envelope.DecodeB64URL(s)
	if err != nil {
		return nil, err
	}
	return ecdh.X25519().NewPublicKey(raw)
}

// BoxKey derives the symmetric key of a (supervisor, device) pair. X25519 refuses a
// low-order peer key (all-zero shared secret), so a hostile key cannot fix the result.
func BoxKey(priv *ecdh.PrivateKey, peer *ecdh.PublicKey, supervisorID, deviceID string) ([]byte, error) {
	shared, err := priv.ECDH(peer)
	if err != nil {
		return nil, err
	}
	salt := sha256.Sum256([]byte(supervisorID + deviceID))
	return hkdf.Key(sha256.New, shared, salt[:], BoxInfo, chacha20poly1305.KeySize)
}

// AAD binds a box to the routing members of its frame: a relay that rewrites any of them
// produces a box that does not open.
func AAD(id, from, to, kind string, exp int64) ([]byte, error) {
	return envelope.Canonical(map[string]any{"type": AADType, "id": id, "from": from, "to": to, "kind": kind, "exp": exp})
}

// Seal encrypts plaintext; nonce nil means a random one (tests and vectors pass a fixed one).
func Seal(key, nonce, plaintext, aad []byte) (string, error) {
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return "", err
	}
	if nonce == nil {
		nonce = make([]byte, chacha20poly1305.NonceSizeX)
		if _, err := rand.Read(nonce); err != nil {
			return "", err
		}
	}
	if len(nonce) != chacha20poly1305.NonceSizeX {
		return "", errors.New("relay: nonce must be 24 bytes")
	}
	return envelope.B64URL(aead.Seal(append([]byte{}, nonce...), nonce, plaintext, aad)), nil
}

// Open decrypts a body; any failure (encoding, length, tag) is ErrBox.
func Open(key []byte, body string, aad []byte) ([]byte, error) {
	raw, err := envelope.DecodeB64URL(body)
	if err != nil || len(raw) < chacha20poly1305.NonceSizeX+chacha20poly1305.Overhead {
		return nil, ErrBox
	}
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}
	pt, err := aead.Open(nil, raw[:chacha20poly1305.NonceSizeX], raw[chacha20poly1305.NonceSizeX:], aad)
	if err != nil {
		return nil, ErrBox
	}
	return pt, nil
}
