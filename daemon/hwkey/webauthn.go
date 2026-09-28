// SPDX-License-Identifier: AGPL-3.0-or-later

package hwkey

// WebAuthn/CTAP2 structures: authenticatorData and clientDataJSON.
//
// authenticatorData = rpIdHash(32) || flags(1) || signCount(4, BE)
//                     [ || aaguid(16) || credIdLen(2, BE) || credId || COSE_Key ]   if AT
//                     [ || extensions (CBOR map) ]                                   if ED
//
// clientDataJSON (built by the app; sha256 = clientDataHash signed by the key):
//
//	{"type":"webauthn.get","challenge":"<base64url without padding>","origin":"wardenclaw:app"}

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

const (
	FlagUP byte = 0x01 // user present (touch)
	FlagUV byte = 0x04 // user verified (PIN/biometrics)
	FlagAT byte = 0x40 // attested credential data
	FlagED byte = 0x80 // extensions

	// Origin is the origin value in clientDataJSON that the WardenClaw app sends.
	// A browser will not produce an assertion for rpId "wardenclaw" (not a site domain),
	// so a phishing page cannot obtain a signature for our rpId; origin is checked strictly.
	Origin = "wardenclaw:app"

	// DefaultRPID is the rpId under which the app registers the key (no browser, direct CTAP2 over NFC).
	DefaultRPID = "wardenclaw"
)

// authenticatorData layout.
const (
	authDataMinLen     = 37 // rpIdHash(32) || flags(1) || signCount(4)
	aaguidLen          = 16
	maxCredentialIDLen = 1023 // WebAuthn limit
)

func sha256Sum(b []byte) [32]byte { return sha256.Sum256(b) }

// AuthData is a parsed authenticatorData.
type AuthData struct {
	RPIDHash     [32]byte
	Flags        byte
	SignCount    uint32
	AAGUID       []byte
	CredentialID []byte
	CredKey      *COSEKey
}

// ParseAuthData parses authenticatorData; any bytes left after the parsed parts are an error.
func ParseAuthData(b []byte) (*AuthData, error) {
	if len(b) < authDataMinLen {
		return nil, errors.New("authData: too short")
	}
	a := &AuthData{Flags: b[32], SignCount: binary.BigEndian.Uint32(b[33:authDataMinLen])}
	copy(a.RPIDHash[:], b[:32])
	rest := b[authDataMinLen:]
	if a.Flags&FlagAT != 0 {
		if len(rest) < aaguidLen+2 {
			return nil, errors.New("authData: attested data too short")
		}
		a.AAGUID = append([]byte(nil), rest[:aaguidLen]...)
		n := int(binary.BigEndian.Uint16(rest[aaguidLen : aaguidLen+2]))
		rest = rest[aaguidLen+2:]
		if n == 0 || n > maxCredentialIDLen || len(rest) < n {
			return nil, errors.New("authData: bad credentialId length")
		}
		a.CredentialID = append([]byte(nil), rest[:n]...)
		rest = rest[n:]
		v, used, err := cborDecode(rest)
		if err != nil {
			return nil, fmt.Errorf("authData: credential key: %w", err)
		}
		k, err := coseFromValue(v, rest[:used])
		if err != nil {
			return nil, err
		}
		a.CredKey = k
		rest = rest[used:]
	}
	if a.Flags&FlagED != 0 {
		v, used, err := cborDecode(rest)
		if err != nil {
			return nil, fmt.Errorf("authData: extensions: %w", err)
		}
		if _, ok := v.(map[any]any); !ok {
			return nil, errors.New("authData: extensions not a map")
		}
		rest = rest[used:]
	}
	if len(rest) != 0 {
		return nil, errors.New("authData: trailing bytes")
	}
	return a, nil
}

// BuildAuthData builds authenticatorData for tests and the software authenticator.
func BuildAuthData(rpID string, flags byte, signCount uint32, aaguid, credID, coseKey []byte) []byte {
	h := sha256.Sum256([]byte(rpID))
	b := append([]byte{}, h[:]...)
	b = append(b, flags)
	b = binary.BigEndian.AppendUint32(b, signCount)
	if flags&FlagAT != 0 {
		if len(aaguid) != aaguidLen {
			aaguid = make([]byte, aaguidLen)
		}
		b = append(b, aaguid...)
		b = binary.BigEndian.AppendUint16(b, uint16(len(credID)))
		b = append(b, credID...)
		b = append(b, coseKey...)
	}
	return b
}

// ClientData holds the clientDataJSON fields that are checked.
type ClientData struct {
	Type        string `json:"type"`
	Challenge   string `json:"challenge"`
	Origin      string `json:"origin"`
	CrossOrigin bool   `json:"crossOrigin"`
}

// ClientDataJSON returns the clientDataJSON bytes as built by the app (key order is fixed:
// type, challenge, origin as in the spec; the server parses JSON rather than comparing the string).
func ClientDataJSON(typ string, challenge []byte) []byte {
	b, _ := json.Marshal(struct {
		Type      string `json:"type"`
		Challenge string `json:"challenge"`
		Origin    string `json:"origin"`
	}{typ, base64.RawURLEncoding.EncodeToString(challenge), Origin})
	return b
}

// parseClientData checks clientDataJSON and returns a rejection reason ("" means ok) and the
// detail for logs. wantChallenge nil skips the challenge check (registration).
func parseClientData(raw []byte, wantType string, wantChallenge []byte) (string, error) {
	var cd ClientData
	if err := json.Unmarshal(raw, &cd); err != nil {
		return "hw_client_data_invalid", err
	}
	if cd.Type != wantType {
		return "hw_client_data_type", fmt.Errorf("type %q, want %q", cd.Type, wantType)
	}
	if cd.Origin != Origin || cd.CrossOrigin {
		return "hw_origin", fmt.Errorf("origin %q", cd.Origin)
	}
	if wantChallenge != nil {
		got, err := b64url(cd.Challenge)
		if err != nil || len(got) != len(wantChallenge) || string(got) != string(wantChallenge) {
			return "hw_challenge_mismatch", errors.New("challenge does not match ticket")
		}
	}
	return "", nil
}

// b64url accepts base64url with or without padding (and standard base64).
func b64url(s string) ([]byte, error) {
	s = strings.TrimRight(strings.TrimSpace(s), "=")
	s = strings.NewReplacer("+", "-", "/", "_").Replace(s)
	return base64.RawURLEncoding.DecodeString(s)
}

// B64 encodes b as base64url without padding.
func B64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// DecodeB64 decodes base64url (with or without padding, standard base64 also accepted).
func DecodeB64(s string) ([]byte, error) { return b64url(s) }
