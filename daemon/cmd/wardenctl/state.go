// SPDX-License-Identifier: AGPL-3.0-or-later

package main

// Local approver state: ~/.config/wardenctl/ (or $XDG_CONFIG_HOME/wardenctl,
// or --dir / $WARDENCTL_DIR). Directory 0700, files 0600, atomic writes.
//
//	server.json   server (address, the pinned supervisor key from the link), device, YubiKey
//	device.key    Ed25519 seed (hex), only if the key is kept in a file, not in the Keychain
//
// One server per directory: a second server needs a separate --dir.

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

const stateFile = "server.json"

// stateVersion: the format version of server.json.
const stateVersion = 1

func statePath(dir string) string { return filepath.Join(dir, stateFile) }

// revokeRefLen: how much of the deviceId pair and forget print for `wardend pair revoke`.
const revokeRefLen = 16

// revokeRef: the deviceId prefix for `wardend pair revoke`. loadState only checks that the id is
// not empty, so an id shorter than the prefix (a damaged server.json) is printed whole: forget
// must not panic, it is the way out of a broken state.
func revokeRef(id string) string {
	if len(id) > revokeRefLen {
		return id[:revokeRefLen]
	}
	return id
}

// HWCred: the bound YubiKey (public part; the key itself never leaves the YubiKey).
type HWCred struct {
	CredentialID string `json:"credentialId"` // base64url
	RPID         string `json:"rpId"`
	Alg          string `json:"alg"`
	PublicKey    string `json:"publicKey"` // COSE_Key base64url: the assertion is checked before sending
	Name         string `json:"name"`
	RequireUV    bool   `json:"requireUv,omitempty"`
	AddedAt      string `json:"addedAt"`
}

// State: the contents of server.json: the paired server, this device and its YubiKey.
type State struct {
	V             int    `json:"v"`
	URL           string `json:"url"`           // wardend endpoint from the link
	SupervisorKey string `json:"supervisorKey"` // pinned supervisor key, base64url
	SupervisorID  string `json:"supervisorId"`  // sha256(key) hex
	Host          string `json:"host"`          // display only
	DeviceID      string `json:"deviceId"`
	Pubkey        string `json:"pubkey"` // base64url
	Name          string `json:"name"`
	KeyStore      string `json:"keyStore"` // file | keychain
	// keychain: "prompt" is an item without trusted apps (-T ""), every read goes through a system
	// prompt. Empty for items of old versions: open recreates them once (reprotectKeychain).
	KeychainACL string  `json:"keychainAcl,omitempty"`
	PairID      string  `json:"pairId,omitempty"`
	PairStatus  string  `json:"pairStatus"` // pending | approved | rejected
	PairedAt    string  `json:"pairedAt,omitempty"`
	HW          *HWCred `json:"hw,omitempty"`
}

func defaultDir() string {
	if d := os.Getenv("WARDENCTL_DIR"); d != "" {
		return d
	}
	if x := os.Getenv("XDG_CONFIG_HOME"); x != "" {
		return filepath.Join(x, "wardenctl")
	}
	h, _ := os.UserHomeDir()
	return filepath.Join(h, ".config", "wardenctl")
}

var errNotPaired = errors.New("no server configured: first wardenctl pair 'wardenclaw://pair?…'")

func loadState(dir string) (*State, error) {
	path := statePath(dir)
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, errNotPaired
	}
	if err != nil {
		return nil, err
	}
	var s State
	if err := json.Unmarshal(b, &s); err != nil {
		return nil, fmt.Errorf("%s is damaged: %w", path, err)
	}
	if s.V != stateVersion || s.URL == "" || s.SupervisorKey == "" || s.DeviceID == "" {
		return nil, fmt.Errorf("%s: incomplete state (wardenctl forget and pair again)", path)
	}
	return &s, nil
}

func saveState(dir string, s *State) error {
	s.V = stateVersion
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	return writeFileAtomic(statePath(dir), append(b, '\n'))
}

func ensureDir(dir string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	return os.Chmod(dir, 0o700)
}

func writeFileAtomic(path string, data []byte) error {
	if err := ensureDir(filepath.Dir(path)); err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(path), ".tmp-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	if err := f.Chmod(0o600); err != nil {
		f.Close()
		return err
	}
	if _, err := f.Write(data); err != nil {
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
	return os.Rename(tmp, path)
}

// deviceKey: the private device key from the store, checked against deviceId.
func deviceKey(dir string, s *State) (ed25519.PrivateKey, error) {
	ks, err := keyStoreByName(s.KeyStore, dir)
	if err != nil {
		return nil, err
	}
	seed, err := ks.Load(s.DeviceID)
	if err != nil {
		return nil, fmt.Errorf("device key (%s): %w", ks.Name(), err)
	}
	if len(seed) != ed25519.SeedSize {
		return nil, fmt.Errorf("device key (%s): wrong length", ks.Name())
	}
	priv := ed25519.NewKeyFromSeed(seed)
	if got := deviceIDOf(priv); got != s.DeviceID {
		return nil, fmt.Errorf("device key (%s) does not match the deviceId from %s", ks.Name(), stateFile)
	}
	return priv, nil
}
