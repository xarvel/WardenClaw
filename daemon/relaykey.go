// SPDX-License-Identifier: AGPL-3.0-or-later

package main

// The supervisor's X25519 encryption key of the relay transport (relay_key_file): its own file in
// the state directory, bound to the supervisor key by the pairing QR.

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
)

// loadOrCreateRelayKey loads or generates the X25519 encryption key of the supervisor (32 bytes
// hex, mode 0600), the same file format as the supervisor key.
func loadOrCreateRelayKey(path string) (*ecdh.PrivateKey, error) {
	if b, err := os.ReadFile(path); err == nil {
		raw, err := hex.DecodeString(string(bytes.TrimSpace(b)))
		if err != nil || len(raw) != 32 {
			return nil, fmt.Errorf("%s: bad key", path)
		}
		return ecdh.X25519().NewPrivateKey(raw)
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	k, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(path, []byte(hex.EncodeToString(k.Bytes())+"\n"), 0o600); err != nil {
		return nil, err
	}
	return k, nil
}
