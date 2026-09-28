// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The "gate" object (macOS: supervisor_darwin.go) is read on every OS: its defaults are auto and
// fail-closed, a wrong value is a start error, a typo in a nested key is an unknown key.
func TestConfigGateDefaultsAndValues(t *testing.T) {
	c := &Config{StateDir: t.TempDir()}
	if err := c.fill(); err != nil {
		t.Fatal(err)
	}
	if c.gateScope() != gateScopeAuto || c.gateDeadlineMiss() != gateMissFailClosed {
		t.Fatalf("defaults: scope %q, deadline_miss %q", c.gateScope(), c.gateDeadlineMiss())
	}
	c = &Config{StateDir: t.TempDir(), Gate: &GateConfig{Scope: "global", DeadlineMiss: "kill"}}
	if err := c.fill(); err != nil {
		t.Fatal(err)
	}
	if c.gateScope() != gateScopeGlobal || c.gateDeadlineMiss() != gateMissKill {
		t.Fatalf("set: scope %q, deadline_miss %q", c.gateScope(), c.gateDeadlineMiss())
	}
	for _, g := range []GateConfig{{Scope: "all"}, {DeadlineMiss: "allow"}} {
		c = &Config{StateDir: t.TempDir(), Gate: &g}
		err := c.fill()
		if err == nil || !strings.Contains(err.Error(), "gate.") {
			t.Errorf("gate %+v: err %v, want a gate.* error", g, err)
		}
	}
}

func TestConfigGateUnknownKey(t *testing.T) {
	p := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(p, []byte(`{"gate": {"scop": "global"}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := loadConfig(p)
	if err == nil || !strings.Contains(err.Error(), `unknown key "gate.scop" (did you mean "scope"?)`) {
		t.Fatalf("err %v, want the unknown nested key with a hint", err)
	}
	if err := os.WriteFile(p, []byte(`{"gate": {"scope": "descendants", "deadline_miss": "fail-closed"}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadConfig(p); err != nil {
		t.Fatalf("valid gate object: %v", err)
	}
}
