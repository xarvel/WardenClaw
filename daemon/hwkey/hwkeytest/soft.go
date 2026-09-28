// SPDX-License-Identifier: AGPL-3.0-or-later

// Package hwkeytest is a software FIDO2 authenticator for tests (EdDSA and ES256):
// makeCredential (attestation none / packed self / packed x5c) and getAssertion, behaving
// the same as YubiKey over CTAP2: signature over authenticatorData || sha256(clientDataJSON).
package hwkeytest

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"time"

	"github.com/xarvel/WardenClaw/daemon/hwkey"
)

type Authenticator struct {
	RPID   string
	Alg    int64
	Ed     ed25519.PrivateKey
	EC     *ecdsa.PrivateKey
	CredID []byte
	Count  uint32
	AAGUID []byte
}

func newBase(rpID string, alg int64) *Authenticator {
	id := make([]byte, 48)
	rand.Read(id)
	aa := []byte{0xee, 0x88, 0x28, 0x79, 0x72, 0x1c, 0x49, 0x13, 0x97, 0x75, 0x3d, 0xfc, 0xce, 0x97, 0x07, 0x2a} // AAGUID YubiKey 5 NFC
	return &Authenticator{RPID: rpID, Alg: alg, CredID: id, AAGUID: aa}
}

func NewEd25519(rpID string) *Authenticator {
	a := newBase(rpID, hwkey.AlgEdDSA)
	_, a.Ed, _ = ed25519.GenerateKey(rand.Reader)
	return a
}

func NewES256(rpID string) *Authenticator {
	a := newBase(rpID, hwkey.AlgES256)
	a.EC, _ = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	return a
}

func (a *Authenticator) COSE() []byte {
	if a.Alg == hwkey.AlgEdDSA {
		return hwkey.EncodeCOSEEd25519(a.Ed.Public().(ed25519.PublicKey))
	}
	return hwkey.EncodeCOSEES256(&a.EC.PublicKey)
}

func (a *Authenticator) sign(msg []byte) []byte {
	if a.Alg == hwkey.AlgEdDSA {
		return ed25519.Sign(a.Ed, msg)
	}
	h := sha256.Sum256(msg)
	s, _ := ecdsa.SignASN1(rand.Reader, a.EC, h[:])
	return s
}

// Key returns a config entry as `wardend hw-register` would produce.
func (a *Authenticator) Key() hwkey.Key {
	return hwkey.Key{ID: hwkey.B64(a.CredID), RPID: a.RPID, Alg: hwkey.AlgName(a.Alg), PublicKey: hwkey.B64(a.COSE()), Name: "soft"}
}

// MakeCredential returns an attestationObject. format: "none" | "packed-self" | "packed-x5c".
func (a *Authenticator) MakeCredential(clientDataJSON []byte, format string) []byte {
	a.Count++
	auth := hwkey.BuildAuthData(a.RPID, hwkey.FlagUP|hwkey.FlagAT, a.Count, a.AAGUID, a.CredID, a.COSE())
	cdh := sha256.Sum256(clientDataJSON)
	signed := append(append([]byte{}, auth...), cdh[:]...)
	obj := map[any]any{"authData": auth}
	switch format {
	case "none":
		obj["fmt"] = "none"
		obj["attStmt"] = map[any]any{}
	case "packed-self":
		obj["fmt"] = "packed"
		obj["attStmt"] = map[any]any{"alg": a.Alg, "sig": a.sign(signed)}
	case "packed-x5c":
		ak, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		ext, _ := asn1.Marshal(a.AAGUID)
		tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Soft FIDO EE Serial 1", Organization: []string{"hwkeytest"}},
			NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
			ExtraExtensions: []pkix.Extension{{Id: asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 45724, 1, 1, 4}, Value: ext}}}
		der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &ak.PublicKey, ak)
		h := sha256.Sum256(signed)
		sig, _ := ecdsa.SignASN1(rand.Reader, ak, h[:])
		obj["fmt"] = "packed"
		obj["attStmt"] = map[any]any{"alg": hwkey.AlgES256, "sig": sig, "x5c": []any{der}}
	default:
		panic("format")
	}
	return hwkey.EncodeCBOR(obj)
}

// Assert returns an assertion over challenge (clientDataJSON built as in the app), counter +1, UP flag.
func (a *Authenticator) Assert(challenge []byte) *hwkey.Assertion {
	a.Count++
	return a.AssertRaw(hwkey.ClientDataJSON("webauthn.get", challenge), hwkey.FlagUP, a.Count)
}

// AssertRaw returns an assertion with arbitrary clientDataJSON/flags/counter (for negative tests).
func (a *Authenticator) AssertRaw(clientDataJSON []byte, flags byte, count uint32) *hwkey.Assertion {
	auth := hwkey.BuildAuthData(a.RPID, flags, count, nil, nil, nil)
	cdh := sha256.Sum256(clientDataJSON)
	sig := a.sign(append(append([]byte{}, auth...), cdh[:]...))
	return &hwkey.Assertion{CredentialID: hwkey.B64(a.CredID), ClientDataJSON: hwkey.B64(clientDataJSON), AuthenticatorData: hwkey.B64(auth), Signature: hwkey.B64(sig)}
}
