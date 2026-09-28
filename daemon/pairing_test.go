// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/xarvel/WardenClaw/daemon/envelope"
)

// The ancestor walk of peerSupervised fails closed: a broken link or a chain that does not reach
// init within maxAncestors links counts as "under the child", so the privileged socket commands
// are refused. Only a walk that reaches init without meeting the child counts as outside.
func TestUnderChild(t *testing.T) {
	down := func(n int) (int, bool) { return n - 1, true } // pid n's parent is n-1, down to init
	for _, c := range []struct {
		name       string
		pid, child int
		parentOf   func(int) (int, bool)
		want       bool
	}{
		{"descendant of the child", 10, 5, down, true},
		{"the child itself", 5, 5, down, true},
		{"reaches init, no child running", 10, -1, down, false},
		{"reaches init past the child's pid range", 10, 20, down, false},
		{"parent 0 (pid namespace init)", 10, -1, func(int) (int, bool) { return 0, true }, false},
		{"unreadable parent", 10, 5, func(int) (int, bool) { return 0, false }, true},
		{"exactly maxAncestors links to init", maxAncestors + 1, -1, down, false},
		{"one link more than maxAncestors", maxAncestors + 2, -1, down, true},
		{"endless chain", 10, -1, func(n int) (int, bool) { return n + 1, true }, true},
		{"cycle", 10, -1, func(n int) (int, bool) { return n, true }, true},
	} {
		if got := underChild(c.pid, c.child, c.parentOf); got != c.want {
			t.Errorf("%s: underChild(%d, %d) = %v, want %v", c.name, c.pid, c.child, got, c.want)
		}
	}
}

// approve and revoke drop a device's old trusted_devices entries by one rule, the config loader's
// (case and surrounding spaces). An entry written by hand as " <ID> " while wardend runs was
// left next to the one approve appends.
func TestPairApproveRevokeMatchHandWrittenID(t *testing.T) {
	other, d := newDevice(), newDevice()
	s := newHWSupervisor(t, `{}`, other)
	s.cfg.path = filepath.Join(t.TempDir(), "config.json")
	hand := d.trusted()
	hand.ID = " " + strings.ToUpper(d.id) + " "
	writeTrusted := func(list ...envelope.TrustedDevice) {
		b, _ := json.Marshal(map[string]any{"mode": "ticket", "trusted_devices": list})
		if err := os.WriteFile(s.cfg.path, b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	trustedIDs := func() []string {
		b, err := os.ReadFile(s.cfg.path)
		if err != nil {
			t.Fatal(err)
		}
		var top struct {
			TrustedDevices []envelope.TrustedDevice `json:"trusted_devices"`
		}
		if err := json.Unmarshal(b, &top); err != nil {
			t.Fatal(err)
		}
		var ids []string
		for _, td := range top.TrustedDevices {
			ids = append(ids, td.ID)
		}
		return ids
	}

	writeTrusted(other.trusted(), hand)
	now := time.Now()
	s.pair.reqs["p-test01"] = &pairReq{ID: "p-test01", DeviceID: d.id, Pubkey: d.trusted().Pubkey, Alg: envelope.AlgEd25519, Status: "pending",
		CreatedAt: now.UnixMilli(), ExpiresAt: now.Add(time.Minute).UnixMilli()}
	if _, err := s.pairApprove("p-test01"); err != nil {
		t.Fatal(err)
	}
	if got, want := trustedIDs(), []string{other.id, d.id}; !slices.Equal(got, want) {
		t.Fatalf("after approve: %q, want %q", got, want)
	}

	writeTrusted(other.trusted(), hand)
	if _, err := s.pairRevoke(d.id[:16]); err != nil {
		t.Fatal(err)
	}
	if got, want := trustedIDs(), []string{other.id}; !slices.Equal(got, want) {
		t.Fatalf("after revoke: %q, want %q", got, want)
	}
}
