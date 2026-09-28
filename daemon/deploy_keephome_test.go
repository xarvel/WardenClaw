// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// The wrapping install (KEEP_HOME): hardened-install.sh in DRY_RUN renders the unit with the
// harness's own Environment= lines from the wrapped service, PATH prefixed with the shim
// directory, without ProtectHome and PrivateTmp, ProtectSystem=full, ReadWritePaths only wardend's
// own directories; the harness command under /home passes; the sudo and docker shims and the
// root_exec config are in the plan. Nothing is changed: DRY_RUN prints the commands.
func TestHardenedInstallKeepHomeRendersWrappedUnit(t *testing.T) {
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash not installed")
	}
	dir := t.TempDir()
	envFile := filepath.Join(dir, "harness.env")
	if err := os.WriteFile(envFile, []byte("Environment=NODE_OPTIONS=\nEnvironment=PATH=/home/u/.nvm/versions/node/v24/bin:/usr/bin:/bin\nEnvironment=\"OPENCLAW_WINDOWS_TASK_NAME=OpenClaw Gateway\"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(dir, "wardend")
	if err := os.WriteFile(bin, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("bash", "deploy/hardened-install.sh", bin)
	// STRIP_PRIV as the wrapping install sets it: this user may be in sudo/docker (a developer box,
	// a CI runner); the dry run prints the gpasswd steps and goes on. ADMIN_USER names a stand-in
	// so that no account creation is planned for a nonexistent one.
	cmd.Env = append(os.Environ(), "DRY_RUN=1", "KEEP_HOME=1", "ROOT_EXEC=1", "STRIP_PRIV=1", "ADMIN_USER=root", "AGENT_USER="+userName(t), "AGENT_HOME="+homeDir(t),
		"HARNESS_CMD=/bin/sh -c sleep", "HARNESS_ENV_FILE="+envFile, "OLD_USER_UNIT=openclaw-gateway.service", "NO_NEXT_STEPS=1")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("hardened-install.sh: %v\n%s", err, out)
	}
	s := string(out)
	for _, want := range []string{
		"keep-home:",
		"Environment=PATH=/usr/local/libexec/wardend/bin:/home/u/.nvm/versions/node/v24/bin:/usr/bin:/bin",
		"Environment=NODE_OPTIONS=",
		`Environment="OPENCLAW_WINDOWS_TASK_NAME=OpenClaw Gateway"`,
		"RuntimeDirectory=wardend",
		"ln -sfn /usr/local/bin/wardend /usr/local/libexec/wardend/bin/sudo",
		"ln -sfn /usr/local/bin/wardend /usr/local/libexec/wardend/bin/docker",
		`"root_exec": {"enabled": true`,
		"systemctl --user disable --now openclaw-gateway.service",
		"-- /bin/sh -c sleep",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("rendered plan lacks %q:\n%s", want, s)
		}
	}
	for _, no := range []string{"ProtectHome=", "PrivateTmp=", "ProtectSystem=", "ReadWritePaths=", "ProtectKernelTunables=", "@HARNESS_ENV@", "@AGENT_HOME@"} {
		for _, l := range strings.Split(s, "\n") {
			if strings.HasPrefix(strings.TrimSpace(l), no) || (no[0] == '@' && strings.Contains(l, no) && !strings.HasPrefix(strings.TrimSpace(l), "#")) {
				t.Errorf("rendered unit still has %q: %s", no, l)
			}
		}
	}
	// without KEEP_HOME a harness under /home is refused, as before
	cmd = exec.Command("bash", "deploy/hardened-install.sh", bin)
	cmd.Env = append(os.Environ(), "DRY_RUN=1", "AGENT_USER=agent", "AGENT_HOME=/var/lib/agent", "HARNESS_CMD=/home/u/.nvm/bin/node x", "NO_NEXT_STEPS=1")
	if out, err := cmd.CombinedOutput(); err == nil || !strings.Contains(string(out), "under /home or /root") {
		t.Fatalf("classic install must refuse a harness under /home: %v\n%s", err, out)
	}
}

func userName(t *testing.T) string {
	t.Helper()
	if u := os.Getenv("USER"); u != "" {
		return u
	}
	t.Skip("USER not set")
	return ""
}

func homeDir(t *testing.T) string {
	t.Helper()
	h, err := os.UserHomeDir()
	if err != nil {
		t.Skip("no home")
	}
	return h
}
