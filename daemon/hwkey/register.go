// SPDX-License-Identifier: AGPL-3.0-or-later

package hwkey

// Key registration: attestationObject (CTAP2 makeCredential) -> hardware_keys entry.
//
// Verified: rpIdHash == sha256(rpId), UP and AT flags, EdDSA/ES256 COSE key, clientDataJSON
// (when provided: type "webauthn.create", origin == Origin), and the attestation signature:
//   - fmt "packed" with x5c: signature by the attestation certificate (YubiKey: Yubico FIDO
//     Attestation), AAGUID in the certificate extension must match authData;
//   - fmt "packed" without x5c (self): signature by the credential key itself;
//   - fmt "none": no signature (key accepted as-is; owner's choice).
// The chain up to the Yubico root is NOT verified: trust comes from the fact that the owner
// pasted the blob from their own phone into their own host config. Reflected in the
// attestation field of the entry.
//
// App blob ("Mode" -> "Hardware Key" screen):
//   wchw1:<base64url(JSON {"credentialId","attestationObject","clientDataJSON","rpId","name"})>

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/asn1"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// BlobPrefix starts the registration blob that the app shows.
const BlobPrefix = "wchw1:"

// Blob is the decoded registration blob.
type Blob struct {
	CredentialID      string `json:"credentialId"`
	AttestationObject string `json:"attestationObject"`
	ClientDataJSON    string `json:"clientDataJSON"`
	RPID              string `json:"rpId"`
	Name              string `json:"name,omitempty"`
}

// ParseBlob decodes a BlobPrefix blob; the fields are not verified here (ParseRegistration).
func ParseBlob(s string) (*Blob, error) {
	s = strings.TrimSpace(s)
	if !strings.HasPrefix(s, BlobPrefix) {
		return nil, fmt.Errorf("blob must start with %q", BlobPrefix)
	}
	raw, err := b64url(strings.TrimPrefix(s, BlobPrefix))
	if err != nil {
		return nil, fmt.Errorf("blob: %w", err)
	}
	var b Blob
	if err := json.Unmarshal(raw, &b); err != nil {
		return nil, fmt.Errorf("blob: %w", err)
	}
	return &b, nil
}

// Encode returns the blob as the app shows it.
func (b *Blob) Encode() string {
	j, _ := json.Marshal(b)
	return BlobPrefix + B64(j)
}

// oidAAGUID is the FIDO certificate extension id-fido-gen-ce-aaguid.
var oidAAGUID = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 45724, 1, 1, 4}

// Registration holds the result of attestation parsing.
type Registration struct {
	Key         Key
	Format      string
	CertSubject string
}

// ParseRegistration parses attObj and clientDataJSON as raw bytes (clientDataJSON may be nil
// only for fmt "none").
func ParseRegistration(attObj, clientDataJSON []byte, rpID string, now time.Time) (*Registration, error) {
	if rpID == "" {
		rpID = DefaultRPID
	}
	v, err := cborDecodeAll(attObj)
	if err != nil {
		return nil, fmt.Errorf("attestationObject: %w", err)
	}
	m, ok := v.(map[any]any)
	if !ok {
		return nil, errors.New("attestationObject: not a map")
	}
	format, _ := m["fmt"].(string)
	authRaw, _ := m["authData"].([]byte)
	stmt, _ := m["attStmt"].(map[any]any)
	if format == "" || authRaw == nil || stmt == nil {
		return nil, errors.New("attestationObject: fmt/authData/attStmt missing")
	}
	a, err := ParseAuthData(authRaw)
	if err != nil {
		return nil, err
	}
	if a.RPIDHash != sha256Sum([]byte(rpID)) {
		return nil, fmt.Errorf("rpIdHash does not match rp_id %q", rpID)
	}
	if a.Flags&FlagUP == 0 {
		return nil, errors.New("user presence flag not set")
	}
	if a.Flags&FlagAT == 0 || a.CredKey == nil {
		return nil, errors.New("no attested credential data")
	}
	var cdh [32]byte
	if clientDataJSON != nil {
		if reason, err := parseClientData(clientDataJSON, "webauthn.create", nil); reason != "" {
			return nil, fmt.Errorf("clientDataJSON: %s: %v", reason, err)
		}
		cdh = sha256Sum(clientDataJSON)
	}
	r := &Registration{Format: format}
	signed := append(append([]byte{}, authRaw...), cdh[:]...)
	switch format {
	case "none":
		r.Key.Attestation = "none"
	case "packed":
		if clientDataJSON == nil {
			return nil, errors.New("packed attestation needs clientDataJSON")
		}
		note, subject, err := verifyPacked(stmt, a, signed)
		if err != nil {
			return nil, err
		}
		r.Key.Attestation, r.CertSubject = note, subject
	default:
		return nil, fmt.Errorf("attestation format %q not supported (use --cose-key)", format)
	}
	r.Key.ID = B64(a.CredentialID)
	r.Key.RPID = rpID
	r.Key.Alg = AlgName(a.CredKey.Alg)
	r.Key.PublicKey = B64(a.CredKey.Raw)
	r.Key.AAGUID = fmt.Sprintf("%x", a.AAGUID)
	r.Key.AddedAt = now.UTC().Format(time.RFC3339)
	return r, nil
}

// verifyPacked checks a "packed" attestation statement over signed (authData || clientDataHash)
// and returns the attestation note for the key entry and, with x5c, the certificate subject.
func verifyPacked(stmt map[any]any, a *AuthData, signed []byte) (note, subject string, err error) {
	alg, _ := stmt["alg"].(int64)
	sig, _ := stmt["sig"].([]byte)
	if sig == nil {
		return "", "", errors.New("packed: sig missing")
	}
	x5c, ok := stmt["x5c"].([]any)
	if !ok || len(x5c) == 0 {
		// Self attestation: signed by the credential key itself.
		if alg != a.CredKey.Alg {
			return "", "", errors.New("packed self: alg mismatch")
		}
		if !a.CredKey.Verify(signed, sig) {
			return "", "", errors.New("packed self: bad signature")
		}
		return "packed-self", "", nil
	}
	der, _ := x5c[0].([]byte)
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return "", "", fmt.Errorf("packed: x5c: %w", err)
	}
	if err := verifyCertSig(cert, alg, signed, sig); err != nil {
		return "", "", err
	}
	for _, ext := range cert.Extensions {
		if ext.Id.Equal(oidAAGUID) {
			var got []byte
			if _, err := asn1.Unmarshal(ext.Value, &got); err != nil || string(got) != string(a.AAGUID) {
				return "", "", errors.New("packed: AAGUID in certificate does not match authData")
			}
		}
	}
	subject = cert.Subject.String()
	return "packed-x5c (chain not verified): " + subject, subject, nil
}

func verifyCertSig(cert *x509.Certificate, alg int64, msg, sig []byte) error {
	switch pub := cert.PublicKey.(type) {
	case *ecdsa.PublicKey:
		if alg != AlgES256 {
			return fmt.Errorf("packed: alg %d with EC certificate", alg)
		}
		h := sha256Sum(msg)
		if !ecdsa.VerifyASN1(pub, h[:], sig) {
			return errors.New("packed: bad attestation signature")
		}
	case ed25519.PublicKey:
		if alg != AlgEdDSA || !ed25519.Verify(pub, msg, sig) {
			return errors.New("packed: bad attestation signature")
		}
	default:
		return fmt.Errorf("packed: certificate key %T not supported", pub)
	}
	return nil
}

// KeyFromCOSE registers a key without attestation: raw COSE public key and credentialId.
func KeyFromCOSE(coseB64, credIDB64, rpID string, now time.Time) (*Key, error) {
	raw, err := b64url(coseB64)
	if err != nil {
		return nil, err
	}
	c, err := ParseCOSEKey(raw)
	if err != nil {
		return nil, err
	}
	id, err := b64url(credIDB64)
	if err != nil || len(id) == 0 {
		return nil, errors.New("credential id: bad base64url")
	}
	if rpID == "" {
		rpID = DefaultRPID
	}
	return &Key{ID: B64(id), RPID: rpID, Alg: AlgName(c.Alg), PublicKey: B64(raw), Attestation: "cose (no attestation)", AddedAt: now.UTC().Format(time.RFC3339)}, nil
}
