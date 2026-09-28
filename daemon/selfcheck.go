// SPDX-License-Identifier: AGPL-3.0-or-later

package main

// selfcheck checks install integrity at startup: a malicious model under the same uid as wardend
// can rewrite the binary, the config or the supervisor key without a single execve (open+write
// is not gated). Only the hardened install (root-owned files, wardend under a separate uid)
// closes this fully. Here we catch what is visible from the process:
//
//   - group/world-writable files and a too-open state directory: always a refusal in the enforce
//     modes (ticket/deny-list), since it is an obvious configuration error and a reason not to
//     trust the state;
//   - files owned by the agent's uid: a warning in the normal mode (unavoidable in a same-uid
//     install, stated as a limitation) and a REFUSAL with require_hardened.
//
// require_hardened requires the binary, the config and the key to be owned by root (uid 0): then
// no unprivileged descendant can rewrite them.

import (
	"fmt"
	"io"
	"os"
	"strings"

	"golang.org/x/sys/unix"
)

const (
	permGroupOtherWrite = 0o022 // write bits of the group and others
	permGroupOtherAny   = 0o077 // any access bits of the group and others
)

type selfIssue struct {
	path  string
	msg   string
	fatal bool // a violation that forbids starting in enforce mode
}

// checkInstall collects install integrity violations.
// enforce means ticket/deny-list mode (in observe we only warn).
func checkInstall(cfg *Config, exePath string, enforce, requireHardened bool) []selfIssue {
	var out []selfIssue
	uid := os.Getuid()

	// Files where a write = control over wardend.
	type target struct {
		path     string
		optional bool // the config may be absent (a flags-only run)
	}
	targets := []target{
		{exePath, false},
		{cfg.KeyFile, true},
	}
	if cfg.path != "" {
		targets = append(targets, target{cfg.path, true})
	}

	for _, t := range targets {
		var st unix.Stat_t
		if err := unix.Stat(t.path, &st); err != nil {
			if t.optional {
				continue
			}
			out = append(out, selfIssue{t.path, "cannot read: " + err.Error(), enforce})
			continue
		}
		mode := os.FileMode(st.Mode).Perm()
		if mode&permGroupOtherWrite != 0 {
			out = append(out, selfIssue{t.path, fmt.Sprintf("group/world-writable (%#o): anyone in the group or everyone can rewrite it", mode), true})
		}
		if requireHardened && st.Uid != 0 {
			out = append(out, selfIssue{t.path, fmt.Sprintf("owner uid=%d, not root: an agent under this uid can rewrite the file", st.Uid), true})
		} else if st.Uid == uint32(uid) && !requireHardened {
			out = append(out, selfIssue{t.path, fmt.Sprintf("owner = the supervisor's uid (%d): in a same-uid install the file can be rewritten without exec (a limitation, see hardened install)", uid), false})
		}
	}

	// The X25519 key of the relay link (relay_key_file): whoever reads it reads the cards and
	// tickets the relay carries (it cannot sign a decision), whoever writes it replaces the key the
	// phone was paired with. Checked unless relay_url is off; absent before the first start.
	if cfg.relayOn() && cfg.RelayKeyFile != "" {
		var st unix.Stat_t
		if err := unix.Stat(cfg.RelayKeyFile, &st); err == nil {
			mode := os.FileMode(st.Mode).Perm()
			if mode&permGroupOtherAny != 0 {
				out = append(out, selfIssue{cfg.RelayKeyFile, fmt.Sprintf("relay key is accessible to the group/everyone (%#o): needs chmod 600", mode), true})
			}
			if requireHardened && st.Uid != 0 {
				out = append(out, selfIssue{cfg.RelayKeyFile, fmt.Sprintf("owner uid=%d, not root: an agent under this uid can read and replace the relay key", st.Uid), true})
			}
		}
	}

	// State directory: no wider than 0700.
	if cfg.StateDir != "" {
		var st unix.Stat_t
		if err := unix.Stat(cfg.StateDir, &st); err == nil {
			if mode := os.FileMode(st.Mode).Perm(); mode&permGroupOtherAny != 0 {
				out = append(out, selfIssue{cfg.StateDir, fmt.Sprintf("state directory wider than 0700 (%#o)", mode), true})
			}
		}
	}
	return out
}

// runSelfCheck prints the violations (fatalOnly: only the fatal ones) and returns an error if
// enforce mode has a fatal one.
func runSelfCheck(cfg *Config, exePath string, w io.Writer, fatalOnly bool) error {
	// Explicit opt-out for CI/tests (group-writable build artifacts, temp directories 0775).
	// Ignored with require_hardened: an environment variable can't turn off a strong guarantee.
	if os.Getenv("WARDEND_SELFCHECK") == "off" && !cfg.RequireHardened {
		fmt.Fprintln(w, "wardend: selfcheck disabled (WARDEND_SELFCHECK=off)")
		return nil
	}
	enforce := cfg.Mode == "ticket" || cfg.Mode == "deny-list"
	issues := checkInstall(cfg, exePath, enforce, cfg.RequireHardened)
	var fatal []string
	for _, is := range issues {
		tag := "warning"
		if is.fatal && (enforce || cfg.RequireHardened) {
			tag = "FATAL"
			fatal = append(fatal, is.path+": "+is.msg)
		} else if fatalOnly {
			continue
		}
		fmt.Fprintf(w, "wardend: selfcheck %s: %s: %s\n", tag, is.path, is.msg)
	}
	if len(fatal) > 0 {
		return fmt.Errorf("selfcheck: unsafe install (enforce): %s", strings.Join(fatal, "; "))
	}
	return nil
}
