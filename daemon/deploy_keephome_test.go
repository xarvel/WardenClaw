// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// The wrapping install (KEEP_HOME): hardened-install.sh in DRY_RUN renders the unit with the
// harness's own Environment= lines from the wrapped service, PATH prefixed with the shim
// directory, without ProtectHome and PrivateTmp, ProtectSystem=full, ReadWritePaths only wardend's
// own directories; the harness command under /home passes; the sudo and docker shims and the
// root_exec config are in the plan. Nothing is changed: DRY_RUN prints the commands.
func TestHardenedInstallKeepHomeRendersWrappedUnit(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("the systemd installer is Linux-only")
	}
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
		"-- /bin/sh -c sleep",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("rendered plan lacks %q:\n%s", want, s)
		}
	}
	// The old user unit is stopped through the user's systemd --user when that manager runs
	// (a developer box, CI); without one (a hardened host, where the agent user has no user
	// manager) the dry run says so and the unit is only unlinked. Either is the plan for this host.
	if !strings.Contains(s, "systemctl --user disable --now openclaw-gateway.service") &&
		!strings.Contains(s, "no running user manager for "+userName(t)) {
		t.Errorf("rendered plan neither stops the old user unit nor explains why not:\n%s", s)
	}
	if !strings.Contains(s, "rm -f "+homeDir(t)+"/.config/systemd/user/default.target.wants/openclaw-gateway.service") {
		t.Errorf("rendered plan does not unlink the old user unit:\n%s", s)
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

// A re-run over an installed unit (the wrapping install again, after an upgrade): the dry run
// names the backup of the previous unit (.wardend-bak) and prints the lines that change, so the
// administrator sees what the new template does to the installed unit before it is written.
func TestHardenedInstallRerunBacksUpUnit(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("the systemd installer is Linux-only")
	}
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash not installed")
	}
	dir := t.TempDir()
	unit := filepath.Join(dir, "wardend.service")
	if err := os.WriteFile(unit, []byte("[Unit]\nDescription=old\n[Service]\nExecStart=/usr/local/bin/wardend run --old-flag\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(dir, "wardend")
	if err := os.WriteFile(bin, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("bash", "deploy/hardened-install.sh", bin)
	cmd.Env = append(os.Environ(), "DRY_RUN=1", "KEEP_HOME=1", "STRIP_PRIV=1", "ADMIN_USER=root", "AGENT_USER="+userName(t), "AGENT_HOME="+homeDir(t),
		"HARNESS_CMD=/bin/sh -c sleep", "OLD_USER_UNIT=openclaw-gateway.service", "NO_NEXT_STEPS=1", "WARDEND_UNIT="+unit)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("hardened-install.sh: %v\n%s", err, out)
	}
	s := string(out)
	for _, want := range []string{
		"+ cp -p " + unit + " " + unit + ".wardend-bak",
		"the lines that change (- installed, + rendered):",
		"    - ExecStart=/usr/local/bin/wardend run --old-flag",
		"    + ExecStart=",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("dry run lacks %q:\n%s", want, s)
		}
	}
	if b, err := os.ReadFile(unit); err != nil || !strings.Contains(string(b), "--old-flag") {
		t.Fatalf("the dry run touched the unit: %v %q", err, b)
	}
	if _, err := os.Stat(unit + ".wardend-bak"); !os.IsNotExist(err) {
		t.Fatalf("the dry run wrote the backup: %v", err)
	}
}

// A home under /home (a regular account as the agent): the classic install renders
// ProtectHome=tmpfs with BindPaths= for that one directory instead of refusing, keeps it in
// ReadWritePaths, and accepts --rw-paths under it. /root stays refused; so does a harness
// command under /home.
func TestHardenedInstallHomeUnderHomeBindsOnlyThatHome(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("the systemd installer is Linux-only")
	}
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash not installed")
	}
	dir := t.TempDir()
	bin := filepath.Join(dir, "wardend")
	if err := os.WriteFile(bin, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	// An account that does not exist on this host, with this user's home as its home: the dry run
	// plans the useradd and goes on, and RW_PATHS points at a directory that exists. The developer
	// running the tests is in sudo/docker on most boxes, and the classic install (rightly) refuses
	// such an agent user; the check under test is the home-bind, not this host's group memberships.
	const agentUser = "wardend-test-agent"
	if _, err := user.Lookup(agentUser); err == nil {
		t.Skipf("user %s exists on this host", agentUser)
	}
	home := homeDir(t)
	if !strings.HasPrefix(home, "/home/") {
		t.Skipf("home %q is not under /home", home)
	}
	cmd := exec.Command("bash", "deploy/hardened-install.sh", bin)
	cmd.Env = append(os.Environ(), "DRY_RUN=1", "AGENT_USER="+agentUser, "AGENT_HOME="+home, "RW_PATHS="+home,
		"HARNESS_CMD=/bin/sh -c sleep", "NO_NEXT_STEPS=1")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("hardened-install.sh: %v\n%s", err, out)
	}
	s := string(out)
	for _, want := range []string{"home-bind:", "ProtectHome=tmpfs", "BindPaths=" + home, "ReadWritePaths=/var/lib/wardend /etc/wardend " + home} {
		if !strings.Contains(s, want) {
			t.Errorf("rendered plan lacks %q:\n%s", want, s)
		}
	}
	for _, l := range strings.Split(s, "\n") {
		if strings.TrimSpace(l) == "ProtectHome=true" {
			t.Errorf("rendered unit still hides the agent's home: %s", l)
		}
	}
	for _, bad := range []string{"AGENT_HOME=/root/agent", "AGENT_HOME=/run/user/1000"} {
		cmd = exec.Command("bash", "deploy/hardened-install.sh", bin)
		cmd.Env = append(os.Environ(), "DRY_RUN=1", "AGENT_USER=agent", bad, "HARNESS_CMD=/bin/sh -c sleep", "NO_NEXT_STEPS=1")
		if out, err := cmd.CombinedOutput(); err == nil || !strings.Contains(string(out), "hidden by ProtectHome") {
			t.Fatalf("%s must be refused: %v\n%s", bad, err, out)
		}
	}
}
