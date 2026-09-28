// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"os"
	"path/filepath"
	"testing"
)

func hasFatal(issues []selfIssue) bool {
	for _, is := range issues {
		if is.fatal {
			return true
		}
	}
	return false
}

func TestSelfCheckGroupWritable(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	exe := filepath.Join(dir, "wardend")
	key := filepath.Join(dir, "supervisor.key")
	cfgp := filepath.Join(dir, "config.json")
	for _, p := range []string{exe, key, cfgp} {
		if err := os.WriteFile(p, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	cfg := &Config{StateDir: dir, KeyFile: key, path: cfgp}

	// clean install (0600, 0700): no fatal violations
	if got := checkInstall(cfg, exe, true, false); hasFatal(got) {
		t.Fatalf("clean install gave fatal: %+v", got)
	}

	// group-writable binary → fatal
	if err := os.Chmod(exe, 0o660); err != nil {
		t.Fatal(err)
	}
	if got := checkInstall(cfg, exe, true, false); !hasFatal(got) {
		t.Fatalf("group-writable binary must give fatal: %+v", got)
	}
	_ = os.Chmod(exe, 0o600)

	// state directory wider than 0700 → fatal
	if err := os.Chmod(dir, 0o770); err != nil {
		t.Fatal(err)
	}
	if got := checkInstall(cfg, exe, true, false); !hasFatal(got) {
		t.Fatalf("open state-dir must give fatal: %+v", got)
	}
	_ = os.Chmod(dir, 0o700)
}

func TestSelfCheckRequireHardened(t *testing.T) {
	dir := t.TempDir()
	_ = os.Chmod(dir, 0o700)
	exe := filepath.Join(dir, "wardend")
	if err := os.WriteFile(exe, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := &Config{StateDir: dir, KeyFile: filepath.Join(dir, "k")}

	// without require_hardened a file owned by the current uid is only a warning (not fatal)
	if got := checkInstall(cfg, exe, false, false); hasFatal(got) {
		t.Fatalf("same-uid without hardened must not be fatal: %+v", got)
	}
	// with require_hardened a file not owned by root → fatal (the test does not run as root)
	if os.Getuid() != 0 {
		if got := checkInstall(cfg, exe, true, true); !hasFatal(got) {
			t.Fatalf("require_hardened on a non-root file must give fatal: %+v", got)
		}
	}
}
