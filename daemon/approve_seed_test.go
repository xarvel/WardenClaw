// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/xarvel/WardenClaw/daemon/envelope"
)

func TestReadApproveSeed(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	keygen := filepath.Join(dir, "device.txt")
	body := "seed=" + hex.EncodeToString(priv.Seed()) + "\npubkey=" + envelope.B64URL(pub) + "\ndeviceId=" + envelope.DeviceID(pub) + "\n"
	if err := os.WriteFile(keygen, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := readApproveSeed(keygen)
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(got) != hex.EncodeToString(priv.Seed()) {
		t.Fatal("seed mismatch")
	}
	bare := filepath.Join(dir, "seed.hex")
	if err := os.WriteFile(bare, []byte(hex.EncodeToString(priv.Seed())+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readApproveSeed(bare); err != nil {
		t.Fatal(err)
	}
	loose := filepath.Join(dir, "loose.txt")
	if err := os.WriteFile(loose, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := readApproveSeed(loose); err == nil || !strings.Contains(err.Error(), "0600") {
		t.Fatalf("loose file: %v", err)
	}
}

func TestApproveRejectsSeedOnCommandLine(t *testing.T) {
	if code := cmdApprove([]string{"--key", strings.Repeat("ab", 32)}); code != 2 {
		t.Fatalf("exit %d, want 2", code)
	}
}
