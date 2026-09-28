// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"bytes"
	"os"
	"os/exec"
	"strings"
	"testing"
)

// unitDirectives returns the [Service] directives of a unit template without comments and
// line continuations.
func unitDirectives(t *testing.T, path string) map[string][]string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	out := map[string][]string{}
	section := ""
	for _, l := range strings.Split(string(b), "\n") {
		l = strings.TrimSpace(l)
		if l == "" || strings.HasPrefix(l, "#") || strings.HasPrefix(l, ";") || strings.HasPrefix(l, "--") {
			continue
		}
		if strings.HasPrefix(l, "[") {
			section = l
			continue
		}
		if section != "[Service]" {
			continue
		}
		if k, v, ok := strings.Cut(l, "="); ok && !strings.Contains(k, " ") {
			out[k] = append(out[k], v)
		}
	}
	return out
}

// Live run on Ubuntu 24.04 (systemd 255): User=root together with NoNewPrivileges=true drops
// CAP_SETUID from wardend's set, the child's setuid to the agent user fails with EPERM and the
// hardened service doesn't start at all. The system unit runs as root anyway: User=/Group= must
// not be in the template while NoNewPrivileges is on.
func TestSystemUnitKeepsSetuid(t *testing.T) {
	d := unitDirectives(t, "deploy/wardend.system.service")
	if got := d["NoNewPrivileges"]; len(got) == 0 || got[len(got)-1] != "true" {
		t.Fatalf("NoNewPrivileges=true is missing from the unit: %v", got)
	}
	for _, k := range []string{"User", "Group", "CapabilityBoundingSet", "AmbientCapabilities", "SecureBits"} {
		if v, ok := d[k]; ok {
			t.Errorf("%s=%v in wardend.system.service: the child can't drop its uid (needs CAP_SETUID/CAP_SETGID)", k, v)
		}
	}
	if !strings.Contains(strings.Join(d["ExecStart"], " "), "--child-user @AGENT_USER@") {
		// ExecStart spans several lines: the flags are on continuation lines, so check the whole file
		b, _ := os.ReadFile("deploy/wardend.system.service")
		if !strings.Contains(string(b), "--child-user @AGENT_USER@") {
			t.Error("ExecStart without --child-user @AGENT_USER@")
		}
	}
}

// Live run on a Pi 5 (systemd 257, 2026-09-30): RestrictSUIDSGID=true made systemd's seccomp
// filter answer openat2(2) with ENOSYS, and OpenClaw's fs-safe native module (openat2 with
// RESOLVE_BENEATH, no openat fallback) could not take the gateway lock: the gateway under
// wardend died on every start. The option must stay out of the template; the agent uid is the
// boundary against set-uid files anyway.
func TestSystemUnitNoRestrictSUIDSGID(t *testing.T) {
	d := unitDirectives(t, "deploy/wardend.system.service")
	if v, ok := d["RestrictSUIDSGID"]; ok {
		t.Errorf("RestrictSUIDSGID=%v in wardend.system.service: systemd answers openat2 with ENOSYS under it and OpenClaw's gateway lock fails", v)
	}
	b, err := os.ReadFile("deploy/wardend.system.service")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), "openat2") {
		t.Error("wardend.system.service: the comment explaining why RestrictSUIDSGID is absent is gone")
	}
}

// hardened-install.sh reports an existing harness user with the output of id. Escaped quotes
// inside $(...) reached id literally, so it printed an empty "already exists:" and an error.
func TestHardenedInstallShowsExistingUser(t *testing.T) {
	b, err := os.ReadFile("deploy/hardened-install.sh")
	if err != nil {
		t.Fatal(err)
	}
	line := ""
	for _, l := range strings.Split(string(b), "\n") {
		if strings.Contains(l, "already exists:") {
			line = strings.TrimSpace(l)
			break
		}
	}
	if line == "" {
		t.Fatal(`no "already exists:" line in hardened-install.sh`)
	}
	var stdout, stderr bytes.Buffer
	cmd := exec.Command("bash", "-c", line)
	cmd.Env = append(os.Environ(), "AGENT_USER=root")
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("%s: %v", line, err)
	}
	if !strings.Contains(stdout.String(), "uid=0(root)") || stderr.Len() != 0 {
		t.Fatalf("%s\nstdout: %q\nstderr: %q", line, stdout.String(), stderr.String())
	}
}
