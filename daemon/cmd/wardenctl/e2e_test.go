// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build linux

package main

// End-to-end tests against a real wardend (built from this same repository) under real
// seccomp: pairing via link → card → approve/deny → exec runs or gets EPERM;
// watch; YubiKey second signature (fake fido2-*); wardenctl refusal under the wardend filter.
//
// A nested supervisor is forbidden, so within the wardend tree (agent session) tests are skipped.
// A human runs them from their own terminal outside wardend, or CI does; for an agent, a
// `systemd-run --user` wrapper is running code outside the gate (README, "Tests").

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/xarvel/WardenClaw/daemon/envelope"
	"github.com/xarvel/WardenClaw/daemon/feature"
)

var (
	buildOnce sync.Once
	buildDir  string
	buildErr  error
)

// buildTags: e2e binaries are built with the same tags as the test (hwkey or without it).
func buildTags() string {
	if feature.HWKey {
		return "hwkey"
	}
	return ""
}

// noHW: --no-hw in a YubiKey build (allow uses a touch by default); no flag without the tag.
func noHW() []string {
	if feature.HWKey {
		return []string{"--no-hw"}
	}
	return nil
}

// binaries: wardend and wardenctl built from this tree.
func binaries(t *testing.T) (wardend, wardenctl string) {
	t.Helper()
	buildOnce.Do(func() {
		buildDir, buildErr = os.MkdirTemp("", "wardenctl-e2e-bin-")
		if buildErr != nil {
			return
		}
		afterAll = append(afterAll, func() { os.RemoveAll(buildDir) })
		goBin := filepath.Join(runtime.GOROOT(), "bin", "go")
		for _, b := range [][2]string{{"wardend", "github.com/xarvel/WardenClaw/daemon"}, {"wardenctl", "github.com/xarvel/WardenClaw/daemon/cmd/wardenctl"}} {
			cmd := exec.Command(goBin, "build", "-tags", buildTags(), "-o", filepath.Join(buildDir, b[0]), b[1])
			cmd.Dir = filepath.Join("..", "..")
			if out, err := cmd.CombinedOutput(); err != nil {
				buildErr = fmt.Errorf("go build %s: %v\n%s", b[1], err, out)
				return
			}
		}
	})
	if buildErr != nil {
		t.Fatal(buildErr)
	}
	return filepath.Join(buildDir, "wardend"), filepath.Join(buildDir, "wardenctl")
}

func skipIfSupervised(t *testing.T) {
	t.Helper()
	if n, _ := procStatus(os.Getpid(), "Seccomp_filters"); n != "" && n != "0" {
		t.Skip("process under a seccomp filter (wardend tree?): a nested supervisor is forbidden. e2e is run by a human from their own terminal outside wardend, or by CI, not by an agent")
	}
}

// syncBuf: a buffer written by one goroutine and read by the test.
type syncBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuf) Write(p []byte) (int, error) { s.mu.Lock(); defer s.mu.Unlock(); return s.b.Write(p) }
func (s *syncBuf) String() string              { s.mu.Lock(); defer s.mu.Unlock(); return s.b.String() }

func waitFor(t *testing.T, what string, d time.Duration, f func() bool) {
	t.Helper()
	end := time.Now().Add(d)
	for time.Now().Before(end) {
		if f() {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for: %s", what)
}

func fileExists(p string) bool { _, err := os.Stat(p); return err == nil }

func freePort(t *testing.T) string {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().String()
}

type wd struct {
	t        *testing.T
	bin      string
	dir      string
	sock     string
	addr     string
	cmd      *exec.Cmd
	stdin    io.WriteCloser
	out, err syncBuf
	done     chan struct{}
	code     int
}

// startWardend: wardend run in ticket mode; the child waits for a line on stdin (the builtin read
// does not exec) so that cards appear after pairing. Policy mode root: the tests check the
// root card (`bash -c "echo …"`), in tripwire no rule would fire on it.
func startWardend(t *testing.T, dir, addr, policy, ttl, script string) *wd {
	bin, _ := binaries(t)
	w := &wd{t: t, bin: bin, dir: dir, sock: filepath.Join(dir, "wardend.sock"), addr: addr, done: make(chan struct{})}
	args := []string{"run", "--mode", "ticket", "--policy-mode", "root", "--state-dir", dir, "--config", filepath.Join(dir, "config.json"),
		"--gateway-db", "off", "--http-listen", addr, "--ttl", ttl}
	if policy != "" {
		args = append(args, "--policy", policy)
	}
	args = append(args, "--", "sh", "-c", script)
	if cfg := filepath.Join(dir, "config.json"); !fileExists(cfg) {
		os.WriteFile(cfg, []byte("{}\n"), 0o600) // wardend pair approve will append the device here
	}
	w.cmd = exec.Command(bin, args...)
	w.cmd.Env = append(os.Environ(), "WARDEND_SELFCHECK=off") // test binary/temp dir is group-writable
	w.cmd.Stdout, w.cmd.Stderr = &w.out, &w.err
	// Its own process group, so that cleanup kills the harness tree together with wardend, and a
	// bound on Wait after the kill: the harness (`sh` blocked on `read`) inherits the stdout and
	// stderr pipes, and without WaitDelay a wardend that did not come up hung the test in cleanup
	// until the package timeout, instead of failing with the reason.
	w.cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	w.cmd.WaitDelay = 5 * time.Second
	var err error
	if w.stdin, err = w.cmd.StdinPipe(); err != nil {
		t.Fatal(err)
	}
	if err := w.cmd.Start(); err != nil {
		t.Fatal(err)
	}
	go func() {
		w.cmd.Wait()
		w.code = w.cmd.ProcessState.ExitCode()
		close(w.done)
	}()
	t.Cleanup(func() {
		select {
		case <-w.done:
		default:
			syscall.Kill(-w.cmd.Process.Pid, syscall.SIGKILL) // wardend and everything it started
			w.stdin.Close()
			<-w.done
		}
	})
	var last string
	end := time.Now().Add(10 * time.Second)
	for {
		var st struct{ HTTP struct{ Up bool } }
		out, err := w.cliJSON("status")
		if err == nil && json.Unmarshal([]byte(out), &st) == nil && st.HTTP.Up {
			break
		}
		last = fmt.Sprintf("%v: %s", err, out)
		if time.Now().After(end) {
			t.Fatalf("wardend did not come up: status: %s\nwardend stderr:\n%s", last, w.err.String())
		}
		time.Sleep(100 * time.Millisecond)
	}
	return w
}

func (w *wd) cli(args ...string) (string, error) {
	c := exec.Command(w.bin, append(args, "--socket", w.sock)...)
	out, err := c.CombinedOutput()
	return string(out), err
}

// cliJSON: stdout only, for commands whose output is parsed as JSON. wardend prints warnings
// (e.g. "ticket mode and no trusted devices" from status) to stderr, and mixed in they would
// break the parse; on error stderr is appended for the message.
func (w *wd) cliJSON(args ...string) (string, error) {
	c := exec.Command(w.bin, append(args, "--socket", w.sock)...)
	var stderr bytes.Buffer
	c.Stderr = &stderr
	out, err := c.Output()
	if err != nil {
		return string(out) + stderr.String(), err
	}
	return string(out), nil
}

func (w *wd) release() { w.stdin.Write([]byte("go\n")) }

func (w *wd) wait(d time.Duration) {
	w.t.Helper()
	select {
	case <-w.done:
	case <-time.After(d):
		w.t.Fatalf("wardend did not exit\nstdout:\n%s\nstderr:\n%s", w.out.String(), w.err.String())
	}
}

func ctlApp(dir string, in io.Reader) (*app, *syncBuf, *syncBuf) {
	out, errb := &syncBuf{}, &syncBuf{}
	return &app{dir: dir, stdin: in, stdout: out, stderr: errb, now: time.Now,
		guard: func() guardVerdict { return guardVerdict{} }}, out, errb
}

// ctl: one wardenctl command in the test process (without the "next to the agent" check).
func ctl(t *testing.T, dir string, args ...string) (int, string, string) {
	t.Helper()
	a, out, errb := ctlApp(dir, strings.NewReader(""))
	code := a.run(context.Background(), args)
	return code, out.String(), errb.String()
}

var linkRe = regexp.MustCompile(`wardenclaw://pair\?\S+`)
var pairReqRe = regexp.MustCompile(`(p-[0-9a-z]+)\s+pending\s+"[^"]*"\s+fingerprint ([0-9a-f ]{19})`)
var fpRe = regexp.MustCompile(`This device's fingerprint:\s+([0-9a-f ]{19})`)

// pairCtl: full pairing: wardend pair start → wardenctl pair → fingerprint check in
// wardend pair list → wardend pair approve.
func pairCtl(t *testing.T, w *wd, ctlDir string) {
	t.Helper()
	out, err := w.cli("pair", "start", "--url", "http://"+w.addr, "--qr", "none", "--no-wait")
	link := linkRe.FindString(out)
	if err != nil || link == "" {
		t.Fatalf("pair start: %v\n%s", err, out)
	}
	a, cout, cerr := ctlApp(ctlDir, strings.NewReader(""))
	codeCh := make(chan int, 1)
	go func() { codeCh <- a.run(context.Background(), []string{"pair", link, "--name", "e2e-mac"}) }()
	var id, fp string
	waitFor(t, "pairing request in wardend pair list", 15*time.Second, func() bool {
		l, _ := w.cli("pair", "list")
		if m := pairReqRe.FindStringSubmatch(l); m != nil {
			id, fp = m[1], m[2]
			return true
		}
		return false
	})
	waitFor(t, "fingerprint in wardenctl output", 5*time.Second, func() bool { return fpRe.MatchString(cout.String()) })
	if got := fpRe.FindStringSubmatch(cout.String())[1]; got != fp {
		t.Fatalf("fingerprints differ: wardenctl %s, wardend %s", got, fp)
	}
	if out, err := w.cli("pair", "approve", id); err != nil {
		t.Fatalf("pair approve: %v\n%s", err, out)
	}
	select {
	case code := <-codeCh:
		if code != 0 || !strings.Contains(cout.String(), "Approved") {
			t.Fatalf("wardenctl pair: %d\n%s\n%s", code, cout, cerr)
		}
	case <-time.After(15 * time.Second):
		t.Fatalf("wardenctl pair did not finish\n%s\n%s", cout, cerr)
	}
}

var cardIDRe = regexp.MustCompile(`wd-[0-9a-f]{32}`)

// waitCard: the card with this command fragment in wardenctl pending.
func waitCard(t *testing.T, ctlDir, frag string) string {
	t.Helper()
	var id string
	waitFor(t, "card "+frag, 15*time.Second, func() bool {
		_, out, _ := ctl(t, ctlDir, "pending")
		for _, l := range strings.Split(out, "\n  wd-") {
			if strings.Contains(l, frag) {
				id = cardIDRe.FindString("wd-" + l)
				return id != ""
			}
		}
		return false
	})
	return id
}

func TestE2EPairApproveDeny(t *testing.T) {
	skipIfSupervised(t)
	dir, ctlDir := t.TempDir(), t.TempDir()
	w := startWardend(t, dir, freePort(t), "", "30s",
		`read x; bash -c "echo root-ran"; echo "rc1=$?"; bash -c "echo denied-ran"; echo "rc2=$?"`)

	// link with a foreign key (server responses are not signed by it): pairing does not start
	pub, _, _ := ed25519.GenerateKey(nil)
	fake := envelope.PairLink{URL: "http://" + w.addr, Key: envelope.B64URL(pub), Code: "ABCD2345"}.String()
	if code, _, e := ctl(t, ctlDir, "pair", fake); code != 1 || !strings.Contains(e, "not signed by the server key from the link") {
		t.Fatalf("foreign key: %d %s", code, e)
	}
	if _, err := os.Stat(filepath.Join(ctlDir, stateFile)); err == nil {
		t.Fatal("state left after a failed pairing")
	}

	pairCtl(t, w, ctlDir)
	if code, out, e := ctl(t, ctlDir, "status"); code != 0 || !strings.Contains(out, "this device is trusted: yes") || !strings.Contains(out, "mode ticket") ||
		!strings.Contains(out, "(ed25519)") || !strings.Contains(out, "trusted devices: 1 (ed25519: 1, es256: 0)") {
		t.Fatalf("status %d\n%s\n%s", code, out, e)
	} else {
		t.Logf("status:\n%s", out)
	}
	w.release()

	id := waitCard(t, ctlDir, "echo root-ran")
	code, out, e := ctl(t, ctlDir, "pending", "--json")
	var pending pendingJSON
	if code != 0 || e != "" || json.Unmarshal([]byte(out), &pending) != nil || len(pending.Pending) != 1 || pending.Pending[0].ID != id || !pending.Pending[0].Verified {
		t.Fatalf("pending --json %d\n%s\n%s", code, out, e)
	}
	code, out, e = ctl(t, ctlDir, "--json", "show", strings.TrimPrefix(id, "wd-")[:10])
	var shown showJSON
	if code != 0 || e != "" || json.Unmarshal([]byte(out), &shown) != nil || shown.Card.ID != id || shown.Card.Command != "echo root-ran" {
		t.Fatalf("show --json %d\n%s\n%s", code, out, e)
	}
	code, out, e = ctl(t, ctlDir, "show", strings.TrimPrefix(id, "wd-")[:10])
	for _, want := range []string{"echo root-ran", "exe:", "bash", "cwd:", "uid/gid:", "class:    root", "process chain", "digest:"} {
		if code != 0 || !strings.Contains(out, want) {
			t.Fatalf("show: missing %q (%d)\n%s\n%s", want, code, out, e)
		}
	}
	t.Logf("show:\n%s", out)
	if code, out, e := ctl(t, ctlDir, append([]string{"approve", id, "--json"}, noHW()...)...); code != 0 || e != "" {
		t.Fatalf("approve --json %d\n%s\n%s", code, out, e)
	} else {
		var decision decisionJSON
		if json.Unmarshal([]byte(out), &decision) != nil || !decision.OK || decision.ID != id || decision.Decision != "allow" {
			t.Fatalf("approve --json response: %s", out)
		}
	}
	// the same card again: it is already gone
	if code, _, e := ctl(t, ctlDir, append([]string{"approve", id}, noHW()...)...); code != 1 || !strings.Contains(e, "not in the queue") {
		t.Fatalf("repeat approve: %d %s", code, e)
	}
	id2 := waitCard(t, ctlDir, "echo denied-ran")
	if code, out, e := ctl(t, ctlDir, "deny", id2, "--json"); code != 0 || e != "" {
		t.Fatalf("deny --json %d\n%s\n%s", code, out, e)
	} else {
		var decision decisionJSON
		if json.Unmarshal([]byte(out), &decision) != nil || !decision.OK || decision.ID != id2 || decision.Decision != "deny" {
			t.Fatalf("deny --json response: %s", out)
		}
	}
	w.wait(20 * time.Second)
	o := w.out.String()
	if w.code != 0 || !strings.Contains(o, "root-ran") || !strings.Contains(o, "rc1=0") || strings.Contains(o, "denied-ran") || !strings.Contains(o, "rc2=126") {
		t.Fatalf("wardend code=%d\nstdout:\n%s\nstderr:\n%s", w.code, o, w.err.String())
	}
	// in the journal both tickets are signed by this device
	st, _ := loadState(ctlDir)
	jb, _ := os.ReadFile(filepath.Join(dir, "journal.jsonl"))
	if n := strings.Count(string(jb), `"deviceId":"`+st.DeviceID+`"`); n < 2 {
		t.Fatalf("journal has %d tickets from this device", n)
	}
	// forget
	if code, out, _ := ctl(t, ctlDir, "forget", "--yes"); code != 0 || !strings.Contains(out, "wardend pair revoke "+st.DeviceID[:16]) {
		t.Fatalf("forget %d %s", code, out)
	}
	if ents, _ := os.ReadDir(ctlDir); len(ents) != 0 {
		t.Fatalf("files left after forget: %v", ents)
	}
}

func TestE2EWatch(t *testing.T) {
	skipIfSupervised(t)
	dir, ctlDir := t.TempDir(), t.TempDir()
	w := startWardend(t, dir, freePort(t), "", "6s",
		`read x; bash -c "echo one"; echo "rc1=$?"; bash -c "echo two"; echo "rc2=$?"; bash -c "echo three"; echo "rc3=$?"; bash -c "echo token-ran"; echo "rc4=$?"`)
	pairCtl(t, w, ctlDir)

	pr, pw := io.Pipe()
	a, out, errb := ctlApp(ctlDir, pr)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	codeCh := make(chan int, 1)
	go func() { codeCh <- a.run(ctx, append([]string{"watch"}, noHW()...)) }() // YubiKey is not bound
	nth := func(sub string, n int) func() bool {
		return func() bool { return strings.Count(out.String(), sub) >= n }
	}
	w.release()

	// 1: Enter (do nothing): the card expires by TTL, exec gets EPERM
	waitFor(t, "question for card 1", 15*time.Second, nth("Allow wd-", 1))
	pw.Write([]byte("\n"))
	waitFor(t, "skip", 5*time.Second, nth("Skipped", 1))
	// 2: details, then y
	waitFor(t, "question for card 2", 20*time.Second, nth("Allow wd-", 2))
	if !strings.Contains(out.String(), "echo two") {
		t.Fatalf("card 2 is not about echo two:\n%s", out)
	}
	pw.Write([]byte("d\n"))
	waitFor(t, "details", 5*time.Second, nth("process chain", 1))
	pw.Write([]byte("y\n"))
	waitFor(t, "allowed", 10*time.Second, nth("Allowed", 1))
	// 3: decided by another device (the same key from another process) while watch is asking
	waitFor(t, "question for card 3", 15*time.Second, nth("Allow wd-", 3))
	id3 := waitCard(t, ctlDir, "echo three")
	if code, _, e := ctl(t, ctlDir, "deny", id3); code != 0 {
		t.Fatalf("deny 3: %s", e)
	}
	waitFor(t, "question withdrawn", 30*time.Second, nth("withdrawn", 1))
	// 4: dangerous card (secrets rule, the command is harmless): y does not allow it, the whole
	// word allow is needed
	waitFor(t, "question for the dangerous card", 15*time.Second, nth("Dangerous card wd-", 1))
	pw.Write([]byte("y\n"))
	waitFor(t, "y does not allow the dangerous one", 5*time.Second, nth("only the word allow in full allows it", 1))
	if strings.Count(out.String(), "Allowed") != 1 {
		t.Fatalf("y allowed the dangerous card:\n%s", out)
	}
	pw.Write([]byte("allow\n"))
	waitFor(t, "allowed by the word allow", 10*time.Second, nth("Allowed", 2))
	w.wait(20 * time.Second)
	cancel()
	pw.Close()
	if code := <-codeCh; code != 0 {
		t.Fatalf("watch code %d\n%s", code, errb)
	}
	t.Logf("watch:\n%s", out)
	o := w.out.String()
	for _, want := range []string{"rc1=126", "two", "rc2=0", "rc3=126", "token-ran", "rc4=0"} {
		if !strings.Contains(o, want) {
			t.Fatalf("no %q in wardend output:\n%s\nwatch:\n%s", want, o, out)
		}
	}
	if strings.Contains(o, "\none\n") || strings.Contains(o, "\nthree\n") {
		t.Fatalf("extra commands ran:\n%s", o)
	}
}

func TestE2EHardwareKey(t *testing.T) {
	if !feature.HWKey {
		t.Skip("YubiKey only in a build with the hwkey tag")
	}
	skipIfSupervised(t)
	wbin, _ := binaries(t)
	dir, ctlDir := t.TempDir(), t.TempDir()
	addr := freePort(t)
	fakes := installFakes(t, "fido2-token", "fido2-cred", "fido2-assert")
	t.Setenv("WARDENCTL_FIDO2_DIR", fakes)

	// 1. pairing (the config and the supervisor key stay in dir)
	w1 := startWardend(t, dir, addr, "", "30s", `read x`)
	pairCtl(t, w1, ctlDir)
	w1.release()
	w1.wait(10 * time.Second)

	// 2. YubiKey: wardenctl hw-register → command → real wardend hw-register
	code, out, e := ctl(t, ctlDir, "hw-register", "--name", "YubiKey e2e")
	m := blobRe.FindStringSubmatch(out)
	if code != 0 || m == nil {
		t.Fatalf("hw-register %d\n%s\n%s", code, out, e)
	}
	if o, err := exec.Command(wbin, "hw-register", "--config", filepath.Join(dir, "config.json"), m[1]).CombinedOutput(); err != nil {
		t.Fatalf("wardend hw-register: %v\n%s", err, o)
	}
	// 3. policy: bash only with the key
	pol, err := exec.Command(wbin, "policy-defaults").Output()
	if err != nil {
		t.Fatal(err)
	}
	var pm map[string]any
	json.Unmarshal(pol, &pm)
	pm["require_hardware"] = []any{map[string]any{"id": "hw-bash", "argv0": "^bash$"}}
	pb, _ := json.Marshal(pm)
	polPath := filepath.Join(dir, "policy.json")
	os.WriteFile(polPath, pb, 0o600)

	w := startWardend(t, dir, addr, polPath, "30s", `read x; bash -c "echo hw-ran"; echo "rc=$?"`)
	if code, out, e := ctl(t, ctlDir, "status"); code != 0 || !strings.Contains(out, "YubiKey bound here is registered: yes") {
		t.Fatalf("status %d\n%s\n%s", code, out, e)
	}
	w.release()
	id := waitCard(t, ctlDir, "echo hw-ran")
	if _, out, _ := ctl(t, ctlDir, "pending"); !strings.Contains(out, "[YubiKey]") {
		t.Fatalf("pending without the YubiKey mark:\n%s", out)
	} else {
		t.Logf("pending:\n%s", out)
	}
	// without the libfido2 utilities: a clear error, the card stays
	t.Setenv("WARDENCTL_FIDO2_DIR", t.TempDir())
	if code, _, e := ctl(t, ctlDir, "approve", id); code != 1 || !strings.Contains(e, "utility fido2-assert not found") {
		t.Fatalf("without fido2-assert: %d %s", code, e)
	}
	t.Setenv("WARDENCTL_FIDO2_DIR", fakes)
	if code, out, e := ctl(t, ctlDir, "approve", id); code != 0 || !strings.Contains(out, "Allowed") || !strings.Contains(e, "Touch the YubiKey") {
		t.Fatalf("approve with the key %d\n%s\n%s", code, out, e)
	}
	w.wait(20 * time.Second)
	if o := w.out.String(); !strings.Contains(o, "hw-ran") || !strings.Contains(o, "rc=0") {
		t.Fatalf("stdout:\n%s\nstderr:\n%s", o, w.err.String())
	}
	jb, _ := os.ReadFile(filepath.Join(dir, "journal.jsonl"))
	if !bytes.Contains(jb, []byte(`"verified":{`)) {
		t.Fatal("no verified second signature in the journal")
	}
}

// wardenctl started as a child of wardend (like an agent) refuses to work, even with
// WARDENCTL_ALLOW_SAME_HOST=1.
func TestE2EGuardUnderFilter(t *testing.T) {
	skipIfSupervised(t)
	wbin, cbin := binaries(t)
	dir := t.TempDir()
	home := t.TempDir()
	cmd := exec.Command(wbin, "run", "--mode", "observe", "--state-dir", dir, "--gateway-db", "off", "--http-listen", "off", "--quiet",
		"--", cbin, "--dir", filepath.Join(dir, "ctl"), "pending")
	cmd.Env = append(os.Environ(), "HOME="+home, "WARDENCTL_ALLOW_SAME_HOST=1")
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	cmd.Run()
	if cmd.ProcessState.ExitCode() != 3 || !strings.Contains(out.String(), "under the wardend filter") ||
		!strings.Contains(out.String(), "Nothing bypasses this") || !strings.Contains(out.String(), "among the parents") {
		t.Fatalf("exit %d\n%s", cmd.ProcessState.ExitCode(), out.String())
	}
	// the same binary outside the tree but next to the wardend directory: a soft refusal
	os.Mkdir(filepath.Join(home, ".wardend"), 0o700)
	c2 := exec.Command(cbin, "--dir", filepath.Join(dir, "ctl"), "pending")
	c2.Env = append(os.Environ(), "HOME="+home, "WARDENCTL_ALLOW_SAME_HOST=")
	o2, _ := c2.CombinedOutput()
	if c2.ProcessState.ExitCode() != 3 || !strings.Contains(string(o2), "WARDENCTL_ALLOW_SAME_HOST=1") {
		t.Fatalf("exit %d\n%s", c2.ProcessState.ExitCode(), o2)
	}
	sc := bufio.NewScanner(bytes.NewReader(o2))
	sc.Scan()
	if !strings.Contains(sc.Text(), "as the same user") {
		t.Fatalf("first line: %s", sc.Text())
	}
}
