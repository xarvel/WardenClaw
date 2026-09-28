// SPDX-License-Identifier: AGPL-3.0-or-later

package hwkey

// Trusted hardware keys (wardend config, hardware_keys) and assertion verification.
//
// VerifyAssertion checks in order:
//  1. credentialId is known (otherwise hw_unknown_credential);
//  2. clientDataJSON: type "webauthn.get", origin == Origin, challenge == expected
//     (sha256 of the ticket signing string, see envelope.HWChallenge): bound to digest
//     and decision;
//  3. authenticatorData: rpIdHash == sha256(rp_id of key); UP flag required, UV required
//     if require_uv is set on the key; AT must not be set in an assertion;
//  4. COSE-key signature over authenticatorData || sha256(clientDataJSON);
//  5. signCount strictly greater than the stored value (0/0: key without counter, allowed);
//     the new counter is written to disk BEFORE the "ok" response (fail-closed: write
//     failure = rejection).

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

// Key is a hardware_keys entry in ~/.wardend/config.json.
type Key struct {
	ID          string `json:"id"` // credentialId, base64url
	Name        string `json:"name,omitempty"`
	RPID        string `json:"rp_id"`      // "wardenclaw"
	Alg         string `json:"alg"`        // EdDSA | ES256 (informational; truth is in public_key)
	PublicKey   string `json:"public_key"` // COSE_Key, base64url
	AAGUID      string `json:"aaguid,omitempty"`
	RequireUV   bool   `json:"require_uv,omitempty"` // require UV flag (PIN on the key)
	Attestation string `json:"attestation,omitempty"`
	AddedAt     string `json:"added_at,omitempty"`
}

// Assertion is the second signature in a ticket ("hw" field of the decision body). All fields are base64url.
type Assertion struct {
	CredentialID      string `json:"credentialId"`
	ClientDataJSON    string `json:"clientDataJSON"`
	AuthenticatorData string `json:"authenticatorData"`
	Signature         string `json:"signature"`
}

// Size limits for the base64url-decoded assertion fields.
const (
	maxClientDataLen = 4096
	maxAuthDataLen   = 4096
	maxSignatureLen  = 512
)

type parsedKey struct {
	Key
	cose     *COSEKey
	rpIDHash [32]byte
}

// Store holds the trusted hardware keys and their last seen signCount.
type Store struct {
	mu          sync.Mutex
	keys        map[string]*parsedKey
	counterPath string
	counters    map[string]uint32
}

// NewStore parses config keys and loads counters. An error in any key or in the counter file
// is a startup error (not a silent "no second factor").
func NewStore(keys []Key, counterPath string) (*Store, error) {
	s := &Store{keys: map[string]*parsedKey{}, counterPath: counterPath, counters: map[string]uint32{}}
	for _, k := range keys {
		id, err := b64url(k.ID)
		if err != nil || len(id) == 0 {
			return nil, fmt.Errorf("hardware key %q: bad id", k.ID)
		}
		raw, err := b64url(k.PublicKey)
		if err != nil {
			return nil, fmt.Errorf("hardware key %q: public_key: %w", k.ID, err)
		}
		c, err := ParseCOSEKey(raw)
		if err != nil {
			return nil, fmt.Errorf("hardware key %q: %w", k.ID, err)
		}
		if k.RPID == "" {
			return nil, fmt.Errorf("hardware key %q: rp_id required", k.ID)
		}
		cid := B64(id)
		if _, dup := s.keys[cid]; dup {
			return nil, fmt.Errorf("hardware key %q: duplicate", k.ID)
		}
		pk := &parsedKey{Key: k, cose: c, rpIDHash: sha256Sum([]byte(k.RPID))}
		pk.ID = cid
		s.keys[cid] = pk
	}
	if counterPath != "" {
		b, err := os.ReadFile(counterPath)
		switch {
		case errors.Is(err, os.ErrNotExist):
		case err != nil:
			return nil, fmt.Errorf("hardware counters: %w", err)
		default:
			if err := json.Unmarshal(b, &s.counters); err != nil {
				return nil, fmt.Errorf("hardware counters %s: %w", counterPath, err)
			}
		}
	}
	return s, nil
}

// Len returns the number of trusted keys.
func (s *Store) Len() int { return len(s.keys) }

// Public returns a list for status/pending (without public keys).
func (s *Store) Public() []map[string]string {
	out := make([]map[string]string, 0, len(s.keys))
	for _, k := range s.keys {
		out = append(out, map[string]string{"id": k.ID, "name": k.Name, "alg": k.Alg, "rpId": k.RPID})
	}
	return out
}

// Counter returns the stored signCount (for tests and status).
func (s *Store) Counter(credID string) uint32 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.counters[credID]
}

// Result holds what was verified (for the audit log).
type Result struct {
	CredentialID string `json:"credentialId"`
	Name         string `json:"name,omitempty"`
	SignCount    uint32 `json:"signCount"`
	UV           bool   `json:"uv"`
}

// VerifyAssertion performs a full check; reason "" means ok. challenge is the expected challenge bytes.
func (s *Store) VerifyAssertion(a *Assertion, challenge []byte) (*Result, string) {
	if a == nil {
		return nil, "hardware_required"
	}
	cid, err := b64url(a.CredentialID)
	if err != nil {
		return nil, "hw_bad_encoding"
	}
	k := s.keys[B64(cid)]
	if k == nil {
		return nil, "hw_unknown_credential"
	}
	cdj, err1 := b64url(a.ClientDataJSON)
	ad, err2 := b64url(a.AuthenticatorData)
	sig, err3 := b64url(a.Signature)
	if err1 != nil || err2 != nil || err3 != nil || len(cdj) > maxClientDataLen || len(ad) > maxAuthDataLen || len(sig) > maxSignatureLen {
		return nil, "hw_bad_encoding"
	}
	if reason, _ := parseClientData(cdj, "webauthn.get", challenge); reason != "" {
		return nil, reason
	}
	auth, err := ParseAuthData(ad)
	if err != nil {
		return nil, "hw_auth_data_invalid"
	}
	if auth.RPIDHash != k.rpIDHash {
		return nil, "hw_rpid_mismatch"
	}
	if auth.Flags&FlagAT != 0 {
		return nil, "hw_auth_data_invalid"
	}
	if auth.Flags&FlagUP == 0 {
		return nil, "hw_user_presence"
	}
	if k.RequireUV && auth.Flags&FlagUV == 0 {
		return nil, "hw_user_verification"
	}
	cdh := sha256Sum(cdj)
	msg := append(append([]byte{}, ad...), cdh[:]...)
	if !k.cose.Verify(msg, sig) {
		return nil, "hw_bad_signature"
	}
	// Counter is updated only after signature verification (otherwise a forgery could advance it).
	s.mu.Lock()
	defer s.mu.Unlock()
	prev := s.counters[k.ID]
	if !(auth.SignCount == 0 && prev == 0) && auth.SignCount <= prev {
		return nil, "hw_counter_replay"
	}
	if auth.SignCount != prev {
		s.counters[k.ID] = auth.SignCount
		if err := s.saveLocked(); err != nil {
			s.counters[k.ID] = prev
			return nil, "hw_counter_persist"
		}
	}
	return &Result{CredentialID: k.ID, Name: k.Name, SignCount: auth.SignCount, UV: auth.Flags&FlagUV != 0}, ""
}

// saveLocked writes the counters atomically (temp file, fsync, rename); the caller holds s.mu.
func (s *Store) saveLocked() error {
	if s.counterPath == "" {
		return nil
	}
	b, _ := json.MarshalIndent(s.counters, "", "  ")
	tmp := s.counterPath + ".tmp"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(append(b, '\n')); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp, s.counterPath); err != nil {
		return err
	}
	// Sync the directory so the rename survives a crash; best effort, errors are ignored.
	if d, err := os.Open(filepath.Dir(s.counterPath)); err == nil {
		d.Sync()
		d.Close()
	}
	return nil
}
