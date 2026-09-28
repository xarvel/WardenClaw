// SPDX-License-Identifier: AGPL-3.0-or-later

package envelope

// Device key: two algorithms.
//
//	ed25519  Ed25519 (RFC 8032), raw public key 32 bytes, signature 64 bytes. Phone,
//	         wardenctl. Default algorithm: entries and requests without alg use this one.
//	es256    ECDSA P-256 + SHA-256, public key SEC1 uncompressed (0x04||X||Y, 65 bytes),
//	         key lives in Secure Enclave (Apple Watch). Signature raw r||s (64 bytes) or DER.
//
// deviceId = hex(sha256(raw public key)) for both: 32 and 65 bytes cannot be confused.
// Device algorithm is fixed at pairing time (alg is included in the pairing signing string)
// and stored in trusted_devices; tickets and requests are verified against it; alg is not
// in the tickets themselves.
//
// Low-S for ECDSA is not required: Secure Enclave does not normalize S, and nothing in the
// protocol is addressed by signature bytes (nonce prevents replay), so (r, n-s) gains nothing.

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/sha256"
	"errors"
	"fmt"
	"math/big"
	"strings"
)

// Device key algorithms (the alg of trusted_devices and of the pairing request).
const (
	AlgEd25519 = "ed25519"
	AlgES256   = "es256"
)

// ES256 encodings.
const (
	es256KeyLen    = 65   // SEC1 uncompressed point: 0x04 || X || Y
	es256RawSigLen = 64   // r || s
	es256MaxDERLen = 72   // SEQUENCE of two INTEGERs of up to 33 bytes each
	derSequence    = 0x30 // ASN.1 tags
	derInteger     = 0x02
)

var errBadDERSig = errors.New("bad DER ECDSA signature")

// NormalizeAlg normalizes the algorithm name: "" and "ed25519" -> ed25519, "es256" -> es256, error otherwise.
func NormalizeAlg(s string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", AlgEd25519:
		return AlgEd25519, nil
	case AlgES256:
		return AlgES256, nil
	}
	return "", fmt.Errorf("unsupported device key alg %q (ed25519|es256)", s)
}

// DeviceKey is the public key of a trusted device.
type DeviceKey struct {
	Alg string
	Raw []byte // ed25519: 32 bytes; es256: 65-byte SEC1 uncompressed
	ed  ed25519.PublicKey
	ec  *ecdsa.PublicKey
}

// ParseDeviceKey parses a public key for the given algorithm from base64url (with or without
// padding); for ed25519, hex is also accepted.
func ParseDeviceKey(alg, s string) (DeviceKey, error) {
	a, err := NormalizeAlg(alg)
	if err != nil {
		return DeviceKey{}, err
	}
	if a == AlgEd25519 {
		k, err := DecodeKey(s)
		if err != nil {
			return DeviceKey{}, err
		}
		return DeviceKey{Alg: a, Raw: []byte(k), ed: k}, nil
	}
	b, err := DecodeB64URL(s)
	if err != nil {
		return DeviceKey{}, err
	}
	return ES256KeyFromBytes(b)
}

// ES256KeyFromBytes parses a P-256 key from a 65-byte SEC1 uncompressed point; the point is
// validated on the curve.
func ES256KeyFromBytes(b []byte) (DeviceKey, error) {
	if len(b) != es256KeyLen || b[0] != 4 {
		return DeviceKey{}, fmt.Errorf("es256 public key must be 65-byte SEC1 uncompressed, got %d bytes", len(b))
	}
	pub, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), b)
	if err != nil {
		return DeviceKey{}, err
	}
	return DeviceKey{Alg: AlgES256, Raw: append([]byte(nil), b...), ec: pub}, nil
}

// ES256Key returns a DeviceKey from an *ecdsa.PublicKey (for tests and vector generators).
func ES256Key(pub *ecdsa.PublicKey) DeviceKey {
	b, _ := pub.Bytes()
	k, _ := ES256KeyFromBytes(b)
	return k
}

// Ed25519Key returns a DeviceKey from an ed25519.PublicKey.
func Ed25519Key(pub ed25519.PublicKey) DeviceKey {
	return DeviceKey{Alg: AlgEd25519, Raw: []byte(pub), ed: pub}
}

// Valid reports whether k holds a parsed key; the zero DeviceKey is not valid.
func (k DeviceKey) Valid() bool { return k.ed != nil || k.ec != nil }

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
	switch {
	case k.ed != nil:
		return len(sig) == ed25519.SignatureSize && ed25519.Verify(k.ed, msg, sig)
	case k.ec != nil:
		return VerifyES256(k.ec, msg, sig)
	}
	return false
}

// VerifyES256 verifies an ECDSA P-256/SHA-256 signature; accepts raw r||s (64 bytes) or DER
// (ASN.1 SEQUENCE). Both high-S and low-S are accepted, see file comment.
func VerifyES256(pub *ecdsa.PublicKey, msg, sig []byte) bool {
	if pub == nil || len(sig) == 0 || len(sig) > es256MaxDERLen {
		return false
	}
	h := sha256.Sum256(msg)
	if len(sig) == es256RawSigLen {
		r := new(big.Int).SetBytes(sig[:32])
		s := new(big.Int).SetBytes(sig[32:])
		if ecdsa.Verify(pub, h[:], r, s) {
			return true
		}
	}
	if sig[0] != derSequence {
		return false
	}
	return ecdsa.VerifyASN1(pub, h[:], sig) // strict DER parsing inside
}

// RawES256 converts a DER ECDSA P-256 signature to raw r||s (64 bytes).
func RawES256(der []byte) ([]byte, error) {
	r, s, err := parseDERSig(der)
	if err != nil {
		return nil, err
	}
	out := make([]byte, es256RawSigLen)
	r.FillBytes(out[:32])
	s.FillBytes(out[32:])
	return out, nil
}

// SignES256 returns a raw r||s base64url signature (for tests and vector generators). Deterministic
// (RFC 6979: PrivateKey.Sign with rand == nil), so vectors are reproducible byte-for-byte.
func SignES256(priv *ecdsa.PrivateKey, msg []byte) string {
	der, err := SignES256DER(priv, msg)
	if err != nil {
		return ""
	}
	raw, err := RawES256(der)
	if err != nil {
		return ""
	}
	return B64URL(raw)
}

// SignES256DER returns a deterministic (RFC 6979) DER signature, as produced by Secure Enclave.
func SignES256DER(priv *ecdsa.PrivateKey, msg []byte) ([]byte, error) {
	h := sha256.Sum256(msg)
	return priv.Sign(nil, h[:], crypto.SHA256)
}

// parseDERSig parses SEQUENCE { INTEGER r, INTEGER s } in short DER (P-256 signature < 128 bytes).
func parseDERSig(b []byte) (*big.Int, *big.Int, error) {
	if len(b) < 8 || b[0] != derSequence || int(b[1]) != len(b)-2 || b[1] >= 0x80 {
		return nil, nil, errBadDERSig
	}
	rest := b[2:]
	var ints [2]*big.Int
	for i := range ints {
		if len(rest) < 2 || rest[0] != derInteger || rest[1] >= 0x80 || int(rest[1]) > len(rest)-2 || rest[1] == 0 {
			return nil, nil, errBadDERSig
		}
		n := int(rest[1])
		v := rest[2 : 2+n]
		if v[0]&0x80 != 0 || (n > 1 && v[0] == 0 && v[1]&0x80 == 0) || n > 33 {
			return nil, nil, errBadDERSig
		}
		ints[i] = new(big.Int).SetBytes(v)
		rest = rest[2+n:]
	}
	if len(rest) != 0 {
		return nil, nil, errBadDERSig
	}
	return ints[0], ints[1], nil
}

// SignPayloadES256 builds an es256-device ticket (for tests and vectors; Watch does the same in Swift).
func SignPayloadES256(priv *ecdsa.PrivateKey, p DecisionPayload) DecisionBody {
	did := ES256Key(&priv.PublicKey).ID()
	msg, _ := SigningString(did, p)
	return DecisionBody{DeviceID: did, Payload: p, Signature: SignES256(priv, msg)}
}
