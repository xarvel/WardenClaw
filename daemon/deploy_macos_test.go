// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"archive/tar"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"
)

// The macOS path of install.sh (deploy/macos-install.sh), run in --dry-run on any OS with
// WARDEND_UNAME=Darwin, a release directory built here and a stand-in PlistBuddy: the OpenClaw
// gateway LaunchAgent of the agent user is found and read, the LaunchDaemon plist is rendered
// under the gateway's own label with the harness arguments and environment, the config JSON
// carries child_user, agent_home and the gate defaults, and launchd is told to boot the
// LaunchAgent out and bootstrap the daemon. Nothing is changed: DRY_RUN prints the commands.
// The Endpoint Security client itself is not exercised here (that needs a Mac).
func TestDarwinInstallDryRunWrapsLaunchAgent(t *testing.T) {
	rel, user, home := darwinFixture(t, true)
	out := runInstallDarwin(t, rel, "--dry-run", "--yes", "--from-dir", rel, "--agent-user", user, "--agent-home", home)
	uid := strconv.Itoa(os.Getuid())
	for _, want := range []string{
		"platform: macOS",
		"Found the OpenClaw gateway of " + user,
		"harness:      /usr/local/bin/node /opt/openclaw/dist/index.js gateway --port 18789",
		"+ launchctl bootout gui/" + uid + "/ai.openclaw.gateway",
		"+ launchctl disable gui/" + uid + "/ai.openclaw.gateway",
		"+ write /Library/LaunchDaemons/ai.openclaw.gateway.plist (root 0644):",
		"<string>ai.openclaw.gateway</string>",
		"<string>/Library/Application Support/WardenClaw/wardend.app/Contents/MacOS/wardend</string>",
		"<string>--child-user</string>",
		"<string>" + user + "</string>",
		"<string>/usr/local/bin/node</string>",
		"<string>/opt/openclaw/dist/index.js</string>",
		"<string>--port</string>",
		"<string>18789</string>",
		"<key>PATH</key><string>/Users/u/.nvm/versions/node/v24/bin:/usr/bin:/bin</string>",
		"<key>OPENCLAW_WINDOWS_TASK_NAME</key><string>OpenClaw Gateway &amp; co</string>",
		"<key>StandardOutPath</key>",
		"<string>/var/log/wardend.log</string>",
		"+ write /etc/wardend/config.json (root 0600):",
		`"child_user": "` + user + `"`,
		`"agent_home": "` + home + `"`,
		`"state_dir": "/var/db/wardend"`,
		`"root_exec": {"enabled": false}`,
		`"gate": {"scope": "auto", "deadline_miss": "fail-closed"}`,
		"+ install -d -o root -g wheel -m 0700 /var/db/wardend",
		"+ launchctl bootstrap system /Library/LaunchDaemons/ai.openclaw.gateway.plist",
		"CFBundleIdentifier",
		"<string>dev.wardenclaw.wardend</string>",
		"Full Disk Access",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("dry run lacks %q:\n%s", want, out)
		}
	}
	// the template's default PATH gives way to the harness's own; no placeholder survives
	if strings.Count(out, "<key>PATH</key>") != 1 {
		t.Errorf("expected exactly one PATH in the rendered plist:\n%s", out)
	}
	for _, l := range strings.Split(out, "\n") {
		if strings.Contains(l, "@") && strings.Contains(l, "<") && strings.Contains(l, "@LABEL@") {
			t.Errorf("unresolved placeholder: %s", l)
		}
	}
	for _, no := range []string{"systemctl", "hardened-install.sh", "runs on Linux only"} {
		if strings.Contains(out, no) {
			t.Errorf("the macOS dry run must not mention %q:\n%s", no, out)
		}
	}
}

// Without a LaunchAgent the installer takes --harness-cmd and the label dev.wardenclaw.wardend;
// with --yes and no command it stops.
func TestDarwinInstallDryRunHarnessCmd(t *testing.T) {
	rel, user, home := darwinFixture(t, false)
	out := runInstallDarwin(t, rel, "--dry-run", "--yes", "--from-dir", rel, "--agent-user", user, "--agent-home", home,
		"--harness-cmd", "/bin/sh -c sleep")
	for _, want := range []string{
		"+ write /Library/LaunchDaemons/dev.wardenclaw.wardend.plist (root 0644):",
		"<string>dev.wardenclaw.wardend</string>",
		"<string>/bin/sh</string>",
		"<string>-c</string>",
		"<string>sleep</string>",
		"<key>PATH</key><string>/usr/bin:/bin:/usr/sbin:/sbin:/usr/local/bin</string>",
		`"require_hardened": true`,
		"+ launchctl bootstrap system /Library/LaunchDaemons/dev.wardenclaw.wardend.plist",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("dry run lacks %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "launchctl bootout gui/") {
		t.Errorf("no LaunchAgent to boot out, yet:\n%s", out)
	}

	cmd := exec.Command("sh", "install.sh", "--dry-run", "--yes", "--from-dir", rel, "--agent-user", user, "--agent-home", home)
	cmd.Env = darwinEnv(rel)
	if out, err := cmd.CombinedOutput(); err == nil || !strings.Contains(string(out), "--harness-cmd is required") {
		t.Fatalf("--yes without a harness and without a LaunchAgent must stop: %v\n%s", err, out)
	}
	// --single-user is not a macOS thing
	cmd = exec.Command("sh", "install.sh", "--dry-run", "--single-user", "--from-dir", rel)
	cmd.Env = darwinEnv(rel)
	if out, err := cmd.CombinedOutput(); err == nil || !strings.Contains(string(out), "not available on macOS") {
		t.Fatalf("--single-user must be refused on macOS: %v\n%s", err, out)
	}
}

// uninstall.sh on Darwin: on a machine without the install it says so and changes nothing.
func TestDarwinUninstallDryRunNothingInstalled(t *testing.T) {
	// WARDEND_TEST_ROOT: an empty prefix for every install path, so a wardend installed on the
	// machine that runs the tests is not what the dry run finds.
	root := t.TempDir()
	cmd := exec.Command("sh", "uninstall.sh", "--dry-run", "--yes")
	cmd.Env = append(os.Environ(), "WARDEND_UNAME=Darwin", "WARDEND_TEST_ROOT="+root)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("uninstall.sh: %v\n%s", err, out)
	}
	if !strings.Contains(string(out), "Nothing to remove: wardend is not installed here (macOS).") {
		t.Fatalf("unexpected output:\n%s", out)
	}
	cmd = exec.Command("sh", "uninstall.sh", "--dry-run", "--remove-agent-user")
	cmd.Env = append(os.Environ(), "WARDEND_UNAME=Darwin")
	if out, err := cmd.CombinedOutput(); err == nil || !strings.Contains(string(out), "creates no agent user") {
		t.Fatalf("--remove-agent-user must be refused on macOS: %v\n%s", err, out)
	}
}

// darwinFixture builds a release directory (checksums.txt and wardend_darwin_<arch>.tar.gz with
// stub binaries, this tree's scripts and deploy/) and, with agent set, a fake home with the
// OpenClaw gateway LaunchAgent in it. Returns the release dir, the agent user and its home.
func darwinFixture(t *testing.T, agent bool) (rel, user, home string) {
	t.Helper()
	for _, tool := range []string{"sh", "tar", "gzip", "awk", "sed"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("%s not installed", tool)
		}
	}
	user = userName(t)
	dir := t.TempDir()
	rel = filepath.Join(dir, "release")
	arch := runtime.GOARCH
	if arch != "amd64" && arch != "arm64" {
		t.Skipf("install.sh has no archive for %s", arch)
	}
	name := "wardend_darwin_" + arch
	stage := filepath.Join(dir, "stage", name)
	for _, d := range []string{"deploy", "redteam"} {
		if err := os.MkdirAll(filepath.Join(stage, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	for _, f := range []string{"wardend", "wardenctl"} {
		if err := os.WriteFile(filepath.Join(stage, f), []byte("#!/bin/sh\n"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	// a version no installed copy can be newer than: check_downgrade reads /usr/local/share/wardend/VERSION
	if err := os.WriteFile(filepath.Join(stage, "VERSION"), []byte("v999.0.0\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	copyFile(t, "uninstall.sh", filepath.Join(stage, "uninstall.sh"))
	copyFile(t, "install.sh", filepath.Join(stage, "install.sh"))
	entries, err := os.ReadDir("deploy")
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if !e.IsDir() {
			copyFile(t, filepath.Join("deploy", e.Name()), filepath.Join(stage, "deploy", e.Name()))
		}
	}
	if err := os.MkdirAll(rel, 0o755); err != nil {
		t.Fatal(err)
	}
	tarball := filepath.Join(rel, name+".tar.gz")
	writeTarGz(t, tarball, filepath.Join(dir, "stage"), name)
	sum := sha256.New()
	b, err := os.ReadFile(tarball)
	if err != nil {
		t.Fatal(err)
	}
	sum.Write(b)
	if err := os.WriteFile(filepath.Join(rel, "checksums.txt"), []byte(hex.EncodeToString(sum.Sum(nil))+"  "+name+".tar.gz\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	home = filepath.Join(dir, "home")
	if err := os.MkdirAll(filepath.Join(home, "Library", "LaunchAgents"), 0o755); err != nil {
		t.Fatal(err)
	}
	if agent {
		// the plist itself is read only by the PlistBuddy stand-in, which answers from here
		if err := os.WriteFile(filepath.Join(home, "Library", "LaunchAgents", "ai.openclaw.gateway.plist"), []byte("<plist/>\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	stub := filepath.Join(dir, "PlistBuddy")
	if err := os.WriteFile(stub, []byte(`#!/bin/sh
# PlistBuddy -c "Print :KEY" FILE, the way /usr/libexec/PlistBuddy prints an array and a dict
case "$2" in
"Print :ProgramArguments") printf 'Array {\n    /usr/local/bin/node\n    /opt/openclaw/dist/index.js\n    gateway\n    --port\n    18789\n}\n' ;;
"Print :EnvironmentVariables") printf 'Dict {\n    PATH = /Users/u/.nvm/versions/node/v24/bin:/usr/bin:/bin\n    OPENCLAW_WINDOWS_TASK_NAME = OpenClaw Gateway & co\n}\n' ;;
*) echo "Print: Entry, \"$2\", Does Not Exist" >&2; exit 1 ;;
esac
`), 0o755); err != nil {
		t.Fatal(err)
	}
	return rel, user, home
}

func darwinEnv(rel string) []string {
	return append(os.Environ(), "WARDEND_UNAME=Darwin", "PLISTBUDDY="+filepath.Join(filepath.Dir(rel), "PlistBuddy"), "SUDO_USER=")
}

func runInstallDarwin(t *testing.T, rel string, args ...string) string {
	t.Helper()
	cmd := exec.Command("sh", append([]string{"install.sh"}, args...)...)
	cmd.Env = darwinEnv(rel)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("install.sh %s: %v\n%s", strings.Join(args, " "), err, out)
	}
	return string(out)
}

func copyFile(t *testing.T, src, dst string) {
	t.Helper()
	b, err := os.ReadFile(src)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dst, b, 0o755); err != nil {
		t.Fatal(err)
	}
}

func writeTarGz(t *testing.T, out, root, top string) {
	t.Helper()
	f, err := os.Create(out)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	gz := gzip.NewWriter(f)
	tw := tar.NewWriter(gz)
	err = filepath.Walk(filepath.Join(root, top), func(p string, fi os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		name, err := filepath.Rel(root, p)
		if err != nil {
			return err
		}
		h, err := tar.FileInfoHeader(fi, "")
		if err != nil {
			return err
		}
		h.Name = filepath.ToSlash(name)
		if fi.IsDir() {
			h.Name += "/"
		}
		// a fixed time in the past: tar warns about a time stamp "in the future" when a file was
		// written within the clock's granularity of now, and the warning lands in the output
		h.ModTime = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
		h.AccessTime, h.ChangeTime = time.Time{}, time.Time{}
		if err := tw.WriteHeader(h); err != nil {
			return err
		}
		if fi.IsDir() {
			return nil
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		_, err = tw.Write(b)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
}
