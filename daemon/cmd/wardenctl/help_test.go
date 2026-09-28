// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build linux

package main

// Help without side effects, on the real wardend and wardenctl binaries. Every subcommand with
// --help, -h, -help and help prints help to stdout and exits with code 0: it does not create or
// change files (key, config, state directories), does not connect to the wardend socket or to the
// wardenctl server, and prints nothing that looks like a key. Command line errors (code 2) also
// answer before any action. Two runs: an empty HOME, and a trap HOME where the wardend socket and
// the server of a paired wardenctl listen and count connections, and the wardenctl guard would let
// the command through (WARDENCTL_ALLOW_SAME_HOST=1).

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"io/fs"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/xarvel/WardenClaw/daemon/envelope"
	"github.com/xarvel/WardenClaw/daemon/feature"
)

type cliCall struct {
	bin  string // "wardend" | "wardenctl"
	args []string
	want string // code 0: a stdout substring; code 2: a stderr substring
	code int
}

var helpArgs = []string{"--help", "-h", "-help", "help"}

func helpCalls() []cliCall {
	var calls []cliCall
	help := func(bin, want string, args ...string) {
		calls = append(calls, cliCall{bin: bin, args: args, want: want})
	}
	usageErr := func(bin, want string, args ...string) {
		calls = append(calls, cliCall{bin: bin, args: args, want: want, code: 2})
	}
	for _, h := range helpArgs {
		help("wardend", "wardend <command> --help", h)
		help("wardenctl", "wardenctl <command> --help", h)
	}
	cmds := []string{"run", "config-check", "__child", "version", "keygen", "approve", "status", "journal", "verify-journal",
		"policy-defaults", "pair", "push"}
	if feature.HWKey {
		cmds = append(cmds, "hw-register", "hw-keys")
	}
	for _, c := range cmds {
		for _, h := range helpArgs {
			help("wardend", "usage: wardend "+c, c, h)
		}
		help("wardend", "usage: wardend "+c, "help", c)
	}
	for c, subs := range map[string][]string{"pair": {"start", "list", "approve", "reject", "revoke"}, "push": {"list", "test"}} {
		for _, s := range subs {
			for _, h := range helpArgs {
				help("wardend", "usage: wardend "+c+" "+s, c, s, h)
			}
			help("wardend", "usage: wardend "+c+" "+s, "help", c, s)
		}
	}
	// help among other flags and arguments: still only help
	help("wardend", "usage: wardend run", "run", "--mode", "ticket", "--help", "--", "touch", "run-was-executed")
	help("wardend", "usage: wardend run", "help", "run", "touch", "run-was-executed")
	help("wardend", "usage: wardend config-check", "config-check", "--config", "config.json", "--help", "--", "touch", "run-was-executed")
	help("wardend", "usage: wardend keygen", "keygen", "extra", "--help")
	help("wardend", "usage: wardend approve", "approve", "--key", "00", "--count", "0", "--help")
	help("wardend", "usage: wardend verify-journal", "verify-journal", "--pubkey", "x", "journal.jsonl", "-h")
	if feature.HWKey {
		help("wardend", "usage: wardend hw-register", "hw-register", "wchw1:AAAA", "--help")
	}
	help("wardend", "usage: wardend pair approve", "pair", "approve", "p-0123abcd", "--help")
	help("wardend", "usage: wardend pair start", "pair", "start", "--no-wait", "-h")
	help("wardend", "usage: wardend push test", "push", "test", "--device", "abcdef01", "--help")

	ctlCmds := []string{"pair", "pending", "show", "approve", "deny", "watch", "status", "forget", "version"}
	if feature.HWKey { // without the hwkey tag they answer "not in this release" (hwfeature_test.go)
		ctlCmds = append(ctlCmds, "hw-register", "hw-check")
	}
	for _, c := range ctlCmds {
		for _, h := range helpArgs {
			help("wardenctl", "usage: wardenctl "+c, c, h)
		}
		help("wardenctl", "usage: wardenctl "+c, "help", c)
	}
	help("wardenctl", "usage: wardenctl pending", "--json", "pending", "--help")
	help("wardenctl", "usage: wardenctl status", "status", "--json", "--help") // --json is not supported, help wins
	help("wardenctl", "usage: wardenctl approve", "--dir", "state-must-not-appear", "approve", "wd-0123456789", hwText("--hw", "--yes"), "--help")
	help("wardenctl", "usage: wardenctl pair", "pair", testPairLink, "--no-wait", "--help")
	help("wardenctl", "usage: wardenctl forget", "forget", "--yes", "--help")

	// command line errors: code 2 before the key, files and connections
	usageErr("wardend", "usage:")
	usageErr("wardend", `unknown command "bogus"`, "bogus")
	usageErr("wardend", `unexpected argument "now"`, "keygen", "now")
	usageErr("wardend", `unexpected argument "x"`, "policy-defaults", "x")
	usageErr("wardend", "flag provided but not defined", "status", "--bogus")
	usageErr("wardend", "flag provided but not defined", "config-check", "--bogus")
	usageErr("wardend", "usage: wardend pair start", "pair")
	usageErr("wardend", `unknown subcommand "bogus"`, "pair", "bogus")
	usageErr("wardend", "missing argument", "pair", "approve")
	usageErr("wardend", `unexpected argument "p-2"`, "pair", "reject", "p-1", "p-2")
	usageErr("wardend", `unknown subcommand "bogus"`, "push", "bogus")
	usageErr("wardend", "missing command", "run", "--mode", "observe")
	usageErr("wardend", "missing argument", "verify-journal")
	usageErr("wardenctl", "wardenctl <command> --help")
	usageErr("wardenctl", `unknown command "bogus"`, "bogus")
	usageErr("wardenctl", `unexpected argument "extra"`, "status", "extra")
	usageErr("wardenctl", "--json is only supported", "status", "--json")
	return calls
}

var (
	// seed and deviceId (hex), base64url keys (32 bytes = 43 characters), pairing code
	secretLike = regexp.MustCompile(`seed=|\b[0-9a-f]{64}\b|[A-Za-z0-9_-]{43,}|code=[0-9A-Z]{4}`)
	// attempts to connect to the wardend socket or to the wardenctl server
	connectLike = regexp.MustCompile(`dial |connect:|connection refused|no such file|is not running|socket is wrong|server check|WARNING: wardend is running nearby`)
)

// treeState: all files and directories under the roots: mode, size, modification time.
func treeState(t *testing.T, roots ...string) map[string]string {
	t.Helper()
	m := map[string]string{}
	for _, r := range roots {
		err := filepath.WalkDir(r, func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			info, err := d.Info()
			if err != nil {
				return err
			}
			m[p] = fmt.Sprintf("%v %d %d", info.Mode(), info.Size(), info.ModTime().UnixNano())
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	return m
}

func treeDiff(before, after map[string]string) []string {
	var d []string
	for p, v := range after {
		if w, ok := before[p]; !ok {
			d = append(d, "+ "+p)
		} else if w != v {
			d = append(d, "~ "+p)
		}
	}
	for p := range before {
		if _, ok := after[p]; !ok {
			d = append(d, "- "+p)
		}
	}
	sort.Strings(d)
	return d
}

// checkCalls: run all calls in the environment env with the working directory cwd; after each one
// the files under roots must not change.
func checkCalls(t *testing.T, bins map[string]string, env []string, cwd string, roots ...string) {
	t.Helper()
	calls := helpCalls()
	for _, c := range calls {
		name := c.bin + " " + strings.Join(c.args, " ")
		before := treeState(t, roots...)
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		cmd := exec.CommandContext(ctx, bins[c.bin], c.args...)
		cmd.Env, cmd.Dir = env, cwd // stdin: /dev/null
		var so, se bytes.Buffer
		cmd.Stdout, cmd.Stderr = &so, &se
		cmd.Run()
		timedOut := ctx.Err() != nil
		cancel()
		code := cmd.ProcessState.ExitCode()
		stdout, stderr := so.String(), se.String()
		switch {
		case timedOut:
			t.Errorf("%s: hung (20 s)", name)
		case code != c.code:
			t.Errorf("%s: code %d, want %d\nstdout:\n%s\nstderr:\n%s", name, code, c.code, stdout, stderr)
		case c.code == 0 && (stderr != "" || !strings.Contains(stdout, c.want)):
			t.Errorf("%s: help not in stdout or wrong (want %q)\nstdout:\n%s\nstderr:\n%s", name, c.want, stdout, stderr)
		case c.code != 0 && (stdout != "" || !strings.Contains(stderr, c.want)):
			t.Errorf("%s: error not in stderr or wrong (want %q)\nstdout:\n%s\nstderr:\n%s", name, c.want, stdout, stderr)
		}
		if m := secretLike.FindString(stdout + stderr); m != "" {
			t.Errorf("%s: key-like text in the output: %q", name, m)
		}
		if m := connectLike.FindString(stdout + stderr); m != "" {
			t.Errorf("%s: trace of a connection in the output: %q", name, m)
		}
		if d := treeDiff(before, treeState(t, roots...)); len(d) > 0 {
			t.Errorf("%s: files changed:\n  %s", name, strings.Join(d, "\n  "))
		}
	}
	t.Logf("%d calls", len(calls))
}

// shortTemp: a temporary directory with a short name. The t.TempDir path contains the test name:
// in help (default paths) it would give a long key-like word and a long socket path.
func shortTemp(t *testing.T) string {
	t.Helper()
	d, err := os.MkdirTemp("", "wdh")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(d) })
	return d
}

func TestHelpHasNoSideEffects(t *testing.T) {
	wbin, cbin := binaries(t)
	bins := map[string]string{"wardend": wbin, "wardenctl": cbin}
	env := func(home, tmp string, extra ...string) []string {
		return append([]string{"HOME=" + home, "TMPDIR=" + tmp, "PATH=/usr/bin:/bin", "LANG=C.UTF-8"}, extra...)
	}

	t.Run("empty-home", func(t *testing.T) {
		home, cwd, tmp := shortTemp(t), shortTemp(t), shortTemp(t)
		checkCalls(t, bins, env(home, tmp), cwd, home, cwd, tmp)
		if left := treeState(t, home, cwd, tmp); len(left) != 3 {
			t.Errorf("directories not empty: %v", left)
		}
	})

	t.Run("trap", func(t *testing.T) {
		home, cwd, tmp := shortTemp(t), shortTemp(t), shortTemp(t)
		// the default wardend socket: listen and count connections
		if err := os.Mkdir(filepath.Join(home, ".wardend"), 0o700); err != nil {
			t.Fatal(err)
		}
		ln, err := net.Listen("unix", filepath.Join(home, ".wardend", "wardend.sock"))
		if err != nil {
			t.Fatal(err)
		}
		defer ln.Close()
		var sockConns atomic.Int64
		go func() {
			for {
				c, err := ln.Accept()
				if err != nil {
					return
				}
				sockConns.Add(1)
				c.Close()
			}
		}()
		// a paired wardenctl in the default directory: the server counts requests
		var httpHits atomic.Int64
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			httpHits.Add(1)
			w.WriteHeader(http.StatusServiceUnavailable)
		}))
		defer srv.Close()
		ctlDir := filepath.Join(home, ".config", "wardenctl")
		devPub, devPriv, _ := ed25519.GenerateKey(rand.Reader)
		supPub, _, _ := ed25519.GenerateKey(rand.Reader)
		devID := envelope.DeviceID(devPub)
		if err := (fileStore{dir: ctlDir}).Save(devID, devPriv.Seed()); err != nil {
			t.Fatal(err)
		}
		st := &State{URL: srv.URL, SupervisorKey: envelope.B64URL(supPub), SupervisorID: envelope.DeviceID(supPub), Host: "trap",
			DeviceID: devID, Pubkey: envelope.B64URL(devPub), Name: "trap", KeyStore: "file", PairStatus: "approved"}
		if err := saveState(ctlDir, st); err != nil {
			t.Fatal(err)
		}
		checkCalls(t, bins, env(home, tmp, "WARDENCTL_ALLOW_SAME_HOST=1"), cwd, home, cwd, tmp)
		if n := sockConns.Load(); n != 0 {
			t.Errorf("connections to the wardend socket: %d", n)
		}
		if n := httpHits.Load(); n != 0 {
			t.Errorf("requests to the wardenctl server: %d", n)
		}
	})
}
