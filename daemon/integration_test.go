// SPDX-License-Identifier: AGPL-3.0-or-later

package main

// Integration tests: supervisor in-process, the helper child is the test binary with
// WARDEND_TEST_HELPER=1 (see TestMain). The device is a key generated in the test;
// it signs over the unix-socket JSON-RPC in the same format as the app.

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/xarvel/WardenClaw/daemon/envelope"
	"github.com/xarvel/WardenClaw/daemon/journal"
)

func TestMain(m *testing.M) {
	defaultRelayURL = "" // no test dials the public relay: a test that needs a relay sets relay_url itself
	switch os.Getenv("WARDEND_TEST_HELPER") {
	case "1":
		childMain(os.Args[2:]) // os.Args: [test-binary, "__child", ...]
		return
	case "main": // full CLI: os.Args[1:] = "run", ...
		os.Setenv("WARDEND_TEST_HELPER", "1") // the helper child is the same test binary
		os.Exit(cmdRun(os.Args[2:]))
	case "rootexec": // the rootexec client under the gate: os.Args[1:] = "rootexec", ...
		os.Exit(cmdRootExec(os.Args[2:], os.Stdout, os.Stderr))
	case "shim": // the sudo/docker shim: os.Args[0] is a symlink named sudo or docker to this binary
		os.Exit(cmdShim(filepath.Base(os.Args[0]), os.Args[1:], os.Stdout, os.Stderr))
	case "filtered": // process under an extra seccomp filter (httpapi_test: pair.* from under the filter)
		helperFiltered()
	case "listener": // attempt to install its own unotify filter (nested supervisor)
		_, err := installFilter(true)
		fmt.Printf("nested-listener: %v\n", err)
		os.Exit(0)
	case "memfd": // redteam: attempt to exec from a memfd (execveat AT_EMPTY_PATH), bypassing the on-disk path
		redteamMemfdExec()
	case "ldso": // redteam: attempt to run a binary directly via ld.so
		redteamLdSo()
	}
	os.Exit(m.Run())
}

type device struct {
	priv ed25519.PrivateKey
	id   string
}

func newDevice() device {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	return device{priv: priv, id: envelope.DeviceID(pub)}
}

func (d device) trusted() envelope.TrustedDevice {
	return envelope.TrustedDevice{ID: d.id, Pubkey: envelope.B64URL(d.priv.Public().(ed25519.PublicKey))}
}

type jentry struct {
	Kind string          `json:"kind"`
	Data json.RawMessage `json:"data"`
}

type result struct {
	code    int
	out     string
	errOut  string
	entries []jentry
	execs   []execRecord
	dir     string
	key     ed25519.PublicKey
}

// byClass returns records of class c; repeats of the same process (PATH search after EPERM:
// /usr/bin/x, /bin/x …) collapse into the first one.
func (r *result) byClass(c string) []execRecord {
	var out []execRecord
	seen := map[int]bool{}
	for _, e := range r.execs {
		if e.Class == c && !seen[e.Tgid] {
			seen[e.Tgid] = true
			out = append(out, e)
		}
	}
	return out
}

func (r *result) count(c string) (n int) {
	for _, e := range r.execs {
		if e.Class == c {
			n++
		}
	}
	return
}

func (r *result) dump() string {
	var b strings.Builder
	for _, e := range r.execs {
		fmt.Fprintf(&b, "  %-14s %-5s rule=%s reason=%q argv=%q\n", e.Class, e.Decision, e.Rule, e.Reason, e.Argv)
	}
	return b.String() + "stdout: " + r.out + "\nstderr: " + r.errOut
}

// run runs cmd under wardend; approver (if not nil) receives the socket path.
func run(t *testing.T, cfg Config, cmd []string, approver func(sock string)) *result {
	t.Helper()
	dir := t.TempDir()
	cfg.StateDir = dir
	if cfg.GatewayDB == "" {
		cfg.GatewayDB = "off"
	}
	if cfg.Linger.Duration == 0 {
		cfg.Linger.Duration = 500 * time.Millisecond
	}
	if cfg.PolicyMode == "" {
		// tests in this file cover the "approved root" mode; tripwire is in tripwire_e2e_test.go
		cfg.PolicyMode = "root"
	}
	var so, se bytes.Buffer
	idle, idleW, _ := os.Pipe() // stdin for the test commands; a separate exec for a delay would distort lineage
	defer idle.Close()
	defer idleW.Close()
	var wg sync.WaitGroup
	o := &runOpts{cmd: cmd, helperExe: os.Args[0], helperEnv: []string{"WARDEND_TEST_HELPER=1"}, quiet: true,
		stdout: &so, stderr: &se, stdin: idle, noSignals: true, noSelfCheck: true}
	if approver != nil {
		o.onReady = func(sock string) {
			wg.Add(1)
			go func() { defer wg.Done(); approver(sock) }()
		}
	}
	code, err := runSupervisor(&cfg, o)
	if err != nil {
		t.Fatalf("runSupervisor: %v (stderr: %s)", err, se.String())
	}
	wg.Wait()
	r := &result{code: code, out: so.String(), errOut: se.String(), dir: dir}
	b, _ := os.ReadFile(filepath.Join(dir, "journal.jsonl"))
	for _, line := range strings.Split(strings.TrimSpace(string(b)), "\n") {
		var e jentry
		if err := json.Unmarshal([]byte(line), &e); err != nil {
			t.Fatalf("journal line %q: %v", line, err)
		}
		r.entries = append(r.entries, e)
		if e.Kind == "exec" {
			var x execRecord
			json.Unmarshal(e.Data, &x)
			r.execs = append(r.execs, x)
		}
	}
	key, _ := journal.LoadOrCreateKey(filepath.Join(dir, "supervisor.key"))
	r.key = key.Public().(ed25519.PublicKey)
	f, _ := os.Open(filepath.Join(dir, "journal.jsonl"))
	defer f.Close()
	if v := journal.Verify(f, r.key); !v.OK {
		t.Fatalf("journal verify: %+v", v)
	}
	return r
}

// approveN signs the first n pending items (whose space-joined argv matches match, if set).
func approveN(d device, n int, match string, decision string) func(string) {
	return func(sock string) {
		var re = compileOrNil(match)
		approveLoop(sock, d.priv, re, decision, n, 20*time.Second, func(string) {})
	}
}

func TestObserveClassifiesAndAllows(t *testing.T) {
	r := run(t, Config{Mode: "observe"}, []string{"sh", "-c",
		`bash -c 'ls -d / >/dev/null; rm -rf /nonexistent-wardend-x/; (true; ls -d /tmp) & wait'; echo ok`}, nil)
	if r.code != 0 || !strings.Contains(r.out, "ok") {
		t.Fatalf("code=%d\n%s", r.code, r.dump())
	}
	if len(r.byClass("supervised_cmd")) != 1 || len(r.byClass("root")) != 1 || len(r.byClass("inherit")) < 2 {
		t.Fatalf("classes:\n%s", r.dump())
	}
	for _, e := range r.execs {
		if e.Decision != "allow" {
			t.Fatalf("observe must allow all:\n%s", r.dump())
		}
	}
}

// Main scenario: one ticket per root; children (including background ones and
// python → os.system → sh) pass.
func TestTicketOneRootChildrenInherit(t *testing.T) {
	d := newDevice()
	r := run(t, Config{Mode: "ticket", TrustedDevices: []envelope.TrustedDevice{d.trusted()}, TicketTTL: duration{10 * time.Second}},
		[]string{"sh", "-c", `bash -c 'ls -d /tmp; (sleep 0.2; ls -d /etc) & wait; python3 -c "import os; os.system(\"true\")"; echo rc=$?'`},
		approveN(d, 1, "", "allow"))
	if r.code != 0 || !strings.Contains(r.out, "/tmp\n/etc\nrc=0") {
		t.Fatalf("code=%d\n%s", r.code, r.dump())
	}
	roots := r.byClass("root")
	if len(roots) != 1 || roots[0].Decision != "allow" || roots[0].Digest == "" || roots[0].Ticket == nil {
		t.Fatalf("want exactly one ticketed root:\n%s", r.dump())
	}
	if roots[0].Toctou == nil || roots[0].Toctou.Outcome != "match" {
		t.Fatalf("stop-verify: %+v", roots[0].Toctou)
	}
	inh := r.byClass("inherit")
	if len(inh) < 5 {
		t.Fatalf("children must inherit:\n%s", r.dump())
	}
	for _, e := range inh {
		if e.RootPid != roots[0].Tgid || e.Decision != "allow" {
			t.Fatalf("bad inherit: %+v", e)
		}
	}
	// the envelope in the journal matches the digest
	raw, _ := json.Marshal(roots[0].Envelope)
	v, _ := envelope.ParseJSON(raw)
	if _, dg, _ := envelope.Digest(v); dg != roots[0].Digest {
		t.Fatal("journal envelope digest mismatch")
	}
}

func TestDenyAlwaysEvenInsideRoot(t *testing.T) {
	d := newDevice()
	// rm -rf / : GNU rm refuses anyway (preserve-root), so it is safe even if the rule did not fire
	r := run(t, Config{Mode: "ticket", TrustedDevices: []envelope.TrustedDevice{d.trusted()}, TicketTTL: duration{10 * time.Second}},
		[]string{"sh", "-c", `rm -rf / 2>&1; echo rc1=$?; bash -c 'dd if=/dev/zero of=/dev/null count=1 2>&1; echo rc2=$?'`},
		approveN(d, 1, "", "allow"))
	if !strings.Contains(r.out, "rc1=126") || !strings.Contains(r.out, "rc2=126") || strings.Count(r.out, "Operation not permitted") != 2 {
		t.Fatalf("\n%s", r.dump())
	}
	deny := r.byClass("deny_always")
	if len(deny) != 2 || deny[0].Rule != "rm-recursive-root" || deny[1].Rule != "dd-to-device" {
		t.Fatalf("\n%s", r.dump())
	}
}

func TestTicketRejectsForgeriesThenTTL(t *testing.T) {
	d := newDevice()
	evil := newDevice()
	var reasons []string
	r := run(t, Config{Mode: "ticket", TrustedDevices: []envelope.TrustedDevice{d.trusted()}, TicketTTL: duration{2 * time.Second}},
		[]string{"sh", "-c", `bash -c 'echo SHOULD-NOT-RUN'; echo rc=$?`},
		func(sock string) {
			c, err := dialRPC(sock)
			if err != nil {
				t.Error(err)
				return
			}
			defer c.Close()
			var p struct {
				Pending []pendingItem `json:"pending"`
			}
			for i := 0; i < 50 && len(p.Pending) == 0; i++ {
				c.call("pending", map[string]any{"wait": 200}, &p)
			}
			if len(p.Pending) != 1 {
				t.Error("no pending")
				return
			}
			it := p.Pending[0]
			try := func(b envelope.DecisionBody) {
				var res map[string]any
				c.call("decide", b, &res)
				reasons = append(reasons, fmt.Sprint(res["reason"]))
			}
			sup := supOf(&it)
			// 1) untrusted device
			try(envelope.Sign(evil.priv, sup, it.ID, it.Digest, "allow", envelope.NowMs(), envelope.NewNonce()))
			// 2) a foreign key under a trusted deviceId
			f := envelope.Sign(evil.priv, sup, it.ID, it.Digest, "allow", envelope.NowMs(), envelope.NewNonce())
			f.DeviceID = d.id
			try(f)
			// 3) valid signature, but over a different digest
			try(envelope.Sign(d.priv, sup, it.ID, strings.Repeat("ab", 32), "allow", envelope.NowMs(), envelope.NewNonce()))
			// 4) expired ts
			try(envelope.Sign(d.priv, sup, it.ID, it.Digest, "allow", envelope.NowMs()-600_000, envelope.NewNonce()))
			// 5) a decision on a plugin tool call with this item's id and digest (crypto review, finding 1)
			tp := envelope.ExecPayload("", it.ID, it.Digest, "allow", envelope.NowMs(), envelope.NewNonce())
			tp.Type = envelope.TicketTool
			try(envelope.SignPayload(d.priv, tp))
			// 6) an exec ticket for another supervisor
			try(envelope.Sign(d.priv, strings.Repeat("0f", 32), it.ID, it.Digest, "allow", envelope.NowMs(), envelope.NewNonce()))
		})
	if strings.Contains(r.out, "SHOULD-NOT-RUN") || !strings.Contains(r.out, "rc=126") {
		t.Fatalf("\n%s", r.dump())
	}
	want := []string{"untrusted_device", "bad_signature", "digest_mismatch", "stale_timestamp", "ticket_type_mismatch", "supervisor_mismatch"}
	if strings.Join(reasons, ",") != strings.Join(want, ",") {
		t.Fatalf("reasons=%v", reasons)
	}
	roots := r.byClass("root")
	if len(roots) != 1 || roots[0].Reason != "ttl expired" || roots[0].WaitUs < 1_900_000 {
		t.Fatalf("\n%s", r.dump())
	}
}

func TestTicketDeviceDenies(t *testing.T) {
	d := newDevice()
	r := run(t, Config{Mode: "ticket", TrustedDevices: []envelope.TrustedDevice{d.trusted()}, TicketTTL: duration{10 * time.Second}},
		[]string{"sh", "-c", `bash -c 'echo SHOULD-NOT-RUN'; echo rc=$?`}, approveN(d, 1, "", "deny"))
	if strings.Contains(r.out, "SHOULD-NOT-RUN") || !strings.Contains(r.out, "rc=126") {
		t.Fatalf("\n%s", r.dump())
	}
	if roots := r.byClass("root"); len(roots) != 1 || !strings.Contains(roots[0].Reason, "denied by device") {
		t.Fatalf("\n%s", r.dump())
	}
	// after EPERM dash tries /bin/bash (the same file); the second request is answered from the deny cache
	reqs := 0
	for _, e := range r.execs {
		if e.Class == "root" {
			reqs++
			if reqs > 1 && !strings.HasPrefix(e.Reason, "repeat of denied request") {
				t.Fatalf("PATH retry must hit deny cache:\n%s", r.dump())
			}
		}
	}
}

func TestQueueLimitEAGAIN(t *testing.T) {
	d := newDevice()
	r := run(t, Config{Mode: "ticket", TrustedDevices: []envelope.TrustedDevice{d.trusted()}, TicketTTL: duration{1500 * time.Millisecond}, MaxPending: 1},
		[]string{"bash", "-c", `bash -c true & bash -c true & bash -c true & wait`}, nil)
	var full, ttl int
	for _, e := range r.byClass("root") {
		switch {
		case strings.Contains(e.Reason, "queue full") && e.Errno == "resource temporarily unavailable":
			full++
		case e.Reason == "ttl expired":
			ttl++
		}
	}
	if full != 2 || ttl != 1 {
		t.Fatalf("full=%d ttl=%d\n%s", full, ttl, r.dump())
	}
}

// A delegating spawn inside an approved root: setsid is always a new root (a second ticket).
// The device approves only the first one → setsid gets EPERM on TTL.
func TestSetsidIsNewRoot(t *testing.T) {
	d := newDevice()
	r := run(t, Config{Mode: "ticket", TrustedDevices: []envelope.TrustedDevice{d.trusted()}, TicketTTL: duration{1500 * time.Millisecond}},
		[]string{"sh", "-c", `bash -c 'setsid nohup ls -d /tmp 2>&1 & wait; echo rc=$?'`}, approveN(d, 1, "^bash", "allow"))
	roots := r.byClass("root")
	del := r.byClass("delegating")
	if len(roots) != 1 || roots[0].Decision != "allow" || len(del) != 1 || del[0].Decision != "deny" || del[0].RootPid != roots[0].Tgid {
		t.Fatalf("\n%s", r.dump())
	}
	if !strings.Contains(r.out, "setsid") || !strings.Contains(r.out, "Operation not permitted") {
		t.Fatalf("\n%s", r.dump())
	}
	// and if it is approved too, nohup and ls then inherit from the new root
	r2 := run(t, Config{Mode: "ticket", TrustedDevices: []envelope.TrustedDevice{d.trusted()}, TicketTTL: duration{5 * time.Second}},
		[]string{"sh", "-c", `bash -c 'setsid nohup ls -d /tmp 2>/dev/null & wait'`}, approveN(d, 2, "", "allow"))
	if len(r2.byClass("root")) != 1 || len(r2.byClass("delegating")) != 1 || r2.count("inherit") != 2 || !strings.Contains(r2.out, "/tmp") {
		t.Fatalf("\n%s", r2.dump())
	}
}

// An orphan that lost its link to the root BEFORE its first exec (the root parent has already
// exited) is a new root (fail-closed). With `wait` the same code inherits.
func TestOrphanBeforeExecIsNewRoot(t *testing.T) {
	d := newDevice()
	cfg := Config{Mode: "ticket", TrustedDevices: []envelope.TrustedDevice{d.trusted()}, TicketTTL: duration{1500 * time.Millisecond}, Linger: duration{3 * time.Second}}
	// Delay using bash builtins only: `read -t` on an unclosed pipe sometimes hangs in a
	// non-interactive systemd scope and holds the test's stdout/stderr forever.
	delayedLS := `target=$((SECONDS+1)); while ((SECONDS<target)); do :; done; ls -d /tmp`
	r := run(t, cfg, []string{"sh", "-c", `bash -c '(` + delayedLS + `) & exit 0'`}, approveN(d, 1, "^bash", "allow"))
	roots := r.byClass("root")
	if len(roots) != 2 || roots[0].Decision != "allow" || roots[1].Decision != "deny" || roots[1].Argv[0] != "ls" {
		t.Fatalf("orphan ls must be a new (unapproved) root:\n%s", r.dump())
	}
	// The orphan was re-parented to us (wardend is the tree's subreaper, reaper.go): with Yama
	// ptrace_scope=1 (Ubuntu) its memory stayed readable, and wardend reaped it before returning.
	// (Only this orphan is checked: the test process stays a subreaper, so live orphans of earlier
	// tests end up as its zombies with no supervisor around to reap them.)
	if ppid, _, state, _, ok := procStat(roots[1].Tgid); ok && ppid == os.Getpid() && state == 'Z' {
		t.Fatalf("the orphan %d must be reaped, not left a zombie", roots[1].Tgid)
	}
	r2 := run(t, cfg, []string{"sh", "-c", `bash -c '(` + delayedLS + `) & wait'`}, approveN(d, 1, "^bash", "allow"))
	if len(r2.byClass("root")) != 1 || len(r2.byClass("inherit")) != 1 || !strings.Contains(r2.out, "/tmp") {
		t.Fatalf("with wait ls inherits:\n%s", r2.dump())
	}
}

// A nested unotify filter (a second supervisor inside the tree) is blocked by the wardend filter.
func TestNestedListenerBlocked(t *testing.T) {
	r := run(t, Config{Mode: "observe"}, []string{"env", "WARDEND_TEST_HELPER=listener", os.Args[0]}, nil)
	if !strings.Contains(r.out, "nested-listener: seccomp(SET_MODE_FILTER") || !strings.Contains(r.out, "operation not permitted") {
		t.Fatalf("\n%s", r.dump())
	}
}

func TestStatusAndJournalRPC(t *testing.T) {
	d := newDevice()
	var status map[string]any
	var tail struct{ Lines []json.RawMessage }
	run(t, Config{Mode: "ticket", TrustedDevices: []envelope.TrustedDevice{d.trusted()}, TicketTTL: duration{10 * time.Second}},
		[]string{"sh", "-c", `bash -c 'ls >/dev/null; ls >/dev/null; read -t 1'`},
		func(sock string) {
			st, err := os.Stat(sock)
			if err != nil || st.Mode().Perm() != 0o600 {
				t.Errorf("socket perms: %v %v", st.Mode(), err)
			}
			approveN(d, 1, "", "allow")(sock)
			time.Sleep(200 * time.Millisecond)
			c, err := dialRPC(sock)
			if err != nil {
				t.Error(err)
				return
			}
			defer c.Close()
			c.call("status", nil, &status)
			c.call("journal.tail", map[string]any{"n": 3}, &tail)
		})
	m := status["metrics"].(map[string]any)
	lat := m["latencyUs"].(map[string]any)
	if m["execs"].(float64) < 3 || lat["p50"].(float64) <= 0 || lat["p95"].(float64) < lat["p50"].(float64) {
		t.Fatalf("status: %v", status)
	}
	if tk := m["tickets"].(map[string]any); tk["allowed"].(float64) != 1 {
		t.Fatalf("tickets: %v", tk)
	}
	if len(tail.Lines) != 3 {
		t.Fatalf("tail: %d", len(tail.Lines))
	}
}

// Forwarding SIGTERM to the child and returning its exit code (full CLI in a subprocess).
func TestSignalForwarding(t *testing.T) {
	dir := t.TempDir()
	cmd := exec.Command(os.Args[0], "run", "--mode", "observe", "--state-dir", dir, "--gateway-db", "off", "--relay-url", "off", "--quiet", "--",
		"bash", "-c", `trap 'echo got-term; exit 7' TERM; echo ready; while :; do read -t 0.05 x; done`)
	cmd.Env = append(os.Environ(), "WARDEND_TEST_HELPER=main")
	idle, idleW, _ := os.Pipe()
	defer idleW.Close()
	cmd.Stdin = idle
	var out bytes.Buffer
	pr, pw, _ := os.Pipe()
	cmd.Stdout = pw
	cmd.Stderr = &out
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	pw.Close()
	buf := make([]byte, 64)
	n, _ := pr.Read(buf) // "ready"
	if !strings.Contains(string(buf[:n]), "ready") {
		t.Fatalf("no ready: %q", buf[:n])
	}
	cmd.Process.Signal(syscall.SIGTERM)
	rest := make([]byte, 256)
	m, _ := pr.Read(rest)
	err := cmd.Wait()
	ee, _ := err.(*exec.ExitError)
	if ee == nil || ee.ExitCode() != 7 || !strings.Contains(string(rest[:m]), "got-term") {
		t.Fatalf("err=%v out=%q stderr=%s", err, rest[:m], out.String())
	}
}

func compileOrNil(s string) *regexp.Regexp {
	if s == "" {
		return nil
	}
	return regexp.MustCompile(s)
}
