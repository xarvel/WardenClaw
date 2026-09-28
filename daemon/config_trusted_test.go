// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"strings"
	"testing"

	"github.com/xarvel/WardenClaw/daemon/envelope"
)

// A trusted_devices entry whose pubkey does not hash to its id (sha256(pubkey) ≠ id) is a start
// error with a clear message, not silent trust.
func TestConfigRejectsTrustedDeviceKeyIDMismatch(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	good := envelope.TrustedDevice{ID: envelope.DeviceID(pub), Pubkey: envelope.B64URL(pub)}
	c := &Config{StateDir: t.TempDir(), TrustedDevices: []envelope.TrustedDevice{good, {ID: envelope.SHA256Hex([]byte("legacy"))}}}
	if err := c.fill(); err != nil {
		t.Fatalf("matching key and a key-less entry: %v", err)
	}
	bad := envelope.TrustedDevice{ID: envelope.SHA256Hex([]byte("someone else")), Pubkey: envelope.B64URL(pub)}
	c = &Config{StateDir: t.TempDir(), TrustedDevices: []envelope.TrustedDevice{good, bad}}
	err := c.fill()
	if err == nil {
		t.Fatal("config with sha256(pubkey) != id accepted")
	}
	for _, want := range []string{"trusted_devices[1]", bad.ID, "not this device's key", "wardend pair start"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q lacks %q", err, want)
		}
	}
}
