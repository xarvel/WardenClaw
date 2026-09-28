// SPDX-License-Identifier: AGPL-3.0-or-later

package hwkey

// COSE_Key (RFC 9052/9053) for the two algorithms supported by YubiKey 5 (FIDO2, firmware 5.2+):
//
//	EdDSA  alg -8, kty 1 (OKP), crv 6 (Ed25519), x (-2) = 32 bytes
//	ES256  alg -7, kty 2 (EC2), crv 1 (P-256),  x (-2), y (-3) = 32 bytes each
//
// Assertion signature: EdDSA: raw 64 bytes; ES256: DER (ASN.1 SEQUENCE r,s), as returned by CTAP2.

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"errors"
	"fmt"
)

// COSE algorithm identifiers accepted for hardware keys.
const (
	AlgEdDSA int64 = -8
	AlgES256 int64 = -7
)

// COSE_Key labels and values (RFC 9052 section 7, RFC 9053).
const (
	coseKty int64 = 1 // key type
	coseAlg int64 = 3
	coseCrv int64 = -1 // curve
	coseX   int64 = -2
	coseY   int64 = -3

	ktyOKP     int64 = 1
	ktyEC2     int64 = 2
	crvP256    int64 = 1
	crvEd25519 int64 = 6
)

// AlgName returns a human-readable name for a COSE algorithm.
func AlgName(alg int64) string {
	switch alg {
	case AlgEdDSA:
		return "EdDSA"
	case AlgES256:
		return "ES256"
	}
	return fmt.Sprintf("cose:%d", alg)
}

// COSEKey is a parsed COSE_Key public key.
type COSEKey struct {
	Alg int64
	Ed  ed25519.PublicKey
	EC  *ecdsa.PublicKey
	Raw []byte // original CBOR bytes
}

func mapInt(m map[any]any, k int64) (int64, bool) {
	v, ok := m[k].(int64)
	return v, ok
}

func mapBytes(m map[any]any, k int64) ([]byte, bool) {
	v, ok := m[k].([]byte)
	return v, ok
}

// ParseCOSEKey parses a COSE key that must consume the entire buffer.
func ParseCOSEKey(b []byte) (*COSEKey, error) {
	v, err := cborDecodeAll(b)
	if err != nil {
		return nil, err
	}
	return coseFromValue(v, b)
}

func coseFromValue(v any, raw []byte) (*COSEKey, error) {
	m, ok := v.(map[any]any)
	if !ok {
		return nil, errors.New("cose: not a map")
	}
	kty, _ := mapInt(m, coseKty)
	alg, ok := mapInt(m, coseAlg)
	if !ok {
		return nil, errors.New("cose: alg missing")
	}
	crv, _ := mapInt(m, coseCrv)
	x, _ := mapBytes(m, coseX)
	k := &COSEKey{Alg: alg, Raw: append([]byte(nil), raw...)}
	switch alg {
	case AlgEdDSA:
		if kty != ktyOKP || crv != crvEd25519 || len(x) != ed25519.PublicKeySize {
			return nil, errors.New("cose: EdDSA key must be OKP/Ed25519 with 32-byte x")
		}
		k.Ed = ed25519.PublicKey(append([]byte(nil), x...))
	case AlgES256:
		y, _ := mapBytes(m, coseY)
		if kty != ktyEC2 || crv != crvP256 || len(x) != 32 || len(y) != 32 {
			return nil, errors.New("cose: ES256 key must be EC2/P-256 with 32-byte x,y")
		}
		pt := append(append([]byte{4}, x...), y...)
		pub, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), pt)
		if err != nil {
			return nil, fmt.Errorf("cose: ES256 point: %w", err)
		}
		k.EC = pub
	default:
		return nil, fmt.Errorf("cose: unsupported alg %d (need -8 EdDSA or -7 ES256)", alg)
	}
	return k, nil
}

// Verify checks a signature over msg (for assertion: authenticatorData || clientDataHash).
func (k *COSEKey) Verify(msg, sig []byte) bool {
	switch k.Alg {
	case AlgEdDSA:
		return len(sig) == ed25519.SignatureSize && ed25519.Verify(k.Ed, msg, sig)
	case AlgES256:
		h := sha256Sum(msg)
		return ecdsa.VerifyASN1(k.EC, h[:], sig)
	}
	return false
}

// EncodeCOSEEd25519 returns the COSE_Key of an Ed25519 public key (tests, `hw-register --cose-key`).
func EncodeCOSEEd25519(pub ed25519.PublicKey) []byte {
	return cborEncode(map[any]any{coseKty: ktyOKP, coseAlg: AlgEdDSA, coseCrv: crvEd25519, coseX: []byte(pub)})
}

// EncodeCOSEES256 returns the COSE_Key of a P-256 public key (tests, `hw-register --cose-key`).
func EncodeCOSEES256(pub *ecdsa.PublicKey) []byte {
	b, err := pub.Bytes() // 0x04 || X || Y
	if err != nil || len(b) != 65 {
		panic("EncodeCOSEES256: not a P-256 key")
	}
	return cborEncode(map[any]any{coseKty: ktyEC2, coseAlg: AlgES256, coseCrv: crvP256, coseX: b[1:33], coseY: b[33:]})
}
