// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"strings"
	"testing"

	"github.com/xarvel/WardenClaw/daemon/envelope"
)

// A damaged server.json can hold a deviceId shorter than the prefix printed for `wardend pair
// revoke` (loadState only checks that it is not empty). pair and forget print it whole instead
// of panicking; forget is the way out of such a state.
func TestShortDeviceIDInState(t *testing.T) {
	if got, want := revokeRef(strings.Repeat("0123456789abcdef", 4)), "0123456789abcdef"; got != want {
		t.Fatalf("revokeRef of a full id: %q, want %q", got, want)
	}
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	link := envelope.PairLink{Relay: "wss://127.0.0.1:1/v1/ws", SID: envelope.DeviceID(pub), Key: envelope.B64URL(pub), Enc: testEnc, Code: "ABCD2345"}.String()
	dir := t.TempDir()
	st := &State{Relay: "wss://127.0.0.1:1", SupervisorKey: "AAAA", SupervisorEnc: testEnc, Host: "h", DeviceID: "abc", KeyStore: "file", PairStatus: "approved"}
	if err := saveState(dir, st); err != nil {
		t.Fatal(err)
	}

	a, out, errb := testApp(dir, "")
	if code := a.run(context.Background(), []string{"pair", link}); code != 1 || !strings.Contains(errb.String(), "wardend pair revoke abc on the server") {
		t.Fatalf("pair: code %d, stdout %q, stderr %q", code, out.String(), errb.String())
	}

	a, out, errb = testApp(dir, "")
	if code := a.run(context.Background(), []string{"forget", "--yes"}); code != 0 || !strings.Contains(out.String(), "wardend pair revoke abc\n") {
		t.Fatalf("forget: code %d, stdout %q, stderr %q", code, out.String(), errb.String())
	}
	if _, err := loadState(dir); !errors.Is(err, errNotPaired) {
		t.Fatalf("state after forget: %v", err)
	}
}
