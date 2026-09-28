// SPDX-License-Identifier: AGPL-3.0-or-later

package envelope

// Device key: one algorithm.
//
//	ed25519  Ed25519 (RFC 8032), raw public key 32 bytes, signature 64 bytes. Phone,
//	         wardenctl. Entries and requests without alg use this one.
//
// deviceId = hex(sha256(raw public key)).
// The device algorithm is fixed at pairing time (alg, when sent, is included in the pairing
// signing string) and stored in trusted_devices; tickets and requests are verified against it;
// alg is not in the tickets themselves. Any other value of alg is refused (alg_unsupported).

import (
	"crypto/ed25519"
	"fmt"
	"strings"
)

// Device key algorithms (the alg of trusted_devices and of the pairing request).
const (
	AlgEd25519 = "ed25519"
)

// NormalizeAlg normalizes the algorithm name: "" and "ed25519" -> ed25519, error otherwise.
func NormalizeAlg(s string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", AlgEd25519:
		return AlgEd25519, nil
	}
	return "", fmt.Errorf("unsupported device key alg %q (ed25519)", s)
}

// DeviceKey is the public key of a trusted device.
type DeviceKey struct {
	Alg string
	Raw []byte // ed25519: 32 bytes
	ed  ed25519.PublicKey
}

// ParseDeviceKey parses a public key for the given algorithm from base64url (with or without
// padding) or hex.
func ParseDeviceKey(alg, s string) (DeviceKey, error) {
	a, err := NormalizeAlg(alg)
	if err != nil {
		return DeviceKey{}, err
	}
	k, err := DecodeKey(s)
	if err != nil {
		return DeviceKey{}, err
	}
	return DeviceKey{Alg: a, Raw: []byte(k), ed: k}, nil
}

// Ed25519Key returns a DeviceKey from an ed25519.PublicKey.
func Ed25519Key(pub ed25519.PublicKey) DeviceKey {
	return DeviceKey{Alg: AlgEd25519, Raw: []byte(pub), ed: pub}
}

// Valid reports whether k holds a parsed key; the zero DeviceKey is not valid.
func (k DeviceKey) Valid() bool { return k.ed != nil }

// ID returns the deviceId: hex(sha256(raw)).
func (k DeviceKey) ID() string { return SHA256Hex(k.Raw) }

// B64 returns the public key as base64url without padding (as used in trusted_devices and pairing).
func (k DeviceKey) B64() string { return B64URL(k.Raw) }

// Equal reports whether k and o are the same key of the same algorithm.
func (k DeviceKey) Equal(o DeviceKey) bool {
	return k.Alg == o.Alg && string(k.Raw) == string(o.Raw)
}

// Verify checks a base64url signature over msg using the key's algorithm.
func (k DeviceKey) Verify(msg []byte, sigB64 string) bool {
	sig, err := DecodeB64URL(sigB64)
	if err != nil {
		return false
	}
	if k.ed == nil {
		return false
	}
	return len(sig) == ed25519.SignatureSize && ed25519.Verify(k.ed, msg, sig)
}
