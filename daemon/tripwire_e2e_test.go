// SPDX-License-Identifier: AGPL-3.0-or-later

package main

// Tripwire mode under a real seccomp filter (the same run() as the integration tests): a normal
// command passes without a card, ssh waits for a signature, ssh under an approved scp passes as
// a pair, sudo is refused with a reason and without a card. Plus resolution of /proc/self/exe
// and /dev/fd via the caller's process.

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/xarvel/WardenClaw/daemon/envelope"
)

func need(t *testing.T, bins ...string) {
	t.Helper()
	for _, b := range bins {
		if _, err := exec.LookPath(b); err != nil {
			t.Skipf("%s not installed", b)
		}
	}
}

// execsOf returns exec records with the real binary base (without PATH-search misses: class missing).
func (r *result) execsOf(base string) []execRecord {
	var out []execRecord
	for _, e := range r.execs {
		if filepath.Base(e.Exe) == base && e.Class != "missing" {
			out = append(out, e)
		}
	}
	return out
}

func twCfg(d device, ttl time.Duration) Config {
	return Config{Mode: "ticket", PolicyMode: "tripwire", TrustedDevices: []envelope.TrustedDevice{d.trusted()}, TicketTTL: duration{ttl}}
}

// ls and other ordinary work pass without a card: there is nobody to approve, the TTL is short,
// and the command still runs.
func TestTripwireLsWithoutCard(t *testing.T) {
	d := newDevice()
	r := run(t, twCfg(d, 2*time.Second), []string{"sh", "-c", `ls -d /tmp; echo ok`}, nil)
	if r.code != 0 || !strings.Contains(r.out, "/tmp\n") || !strings.Contains(r.out, "ok") {
		t.Fatalf("code=%d\n%s", r.code, r.dump())
	}
	ls := r.execsOf("ls")
	if len(ls) == 0 || ls[0].Class != "logged" || ls[0].Decision != "allow" || ls[0].Digest != "" {
		t.Fatalf("ls must be logged without a card:\n%s", r.dump())
	}
	for _, e := range r.execs {
		if e.Class == "tripwire" || e.Class == "root" || e.Ticket != nil {
			t.Fatalf("no cards expected:\n%s", r.dump())
		}
	}
}

// ssh is remote execution: a card; without a signature EPERM on TTL, with a signature it runs.
func TestTripwireSshNeedsCard(t *testing.T) {
	need(t, "ssh")
	d := newDevice()
	r := run(t, twCfg(d, 1500*time.Millisecond), []string{"sh", "-c", `ssh -V 2>/dev/null; echo rc=$?`}, nil)
	if !strings.Contains(r.out, "rc=126") {
		t.Fatalf("unapproved ssh must fail with EPERM (126):\n%s", r.dump())
	}
	s := r.execsOf("ssh")
	if len(s) == 0 || s[0].Class != "tripwire" || s[0].Rule != "remote/ssh" || s[0].Category != "remote" || s[0].Decision != "deny" || !strings.Contains(s[0].Reason, "ttl") {
		t.Fatalf("ssh record:\n%s", r.dump())
	}
	r = run(t, twCfg(d, 10*time.Second), []string{"sh", "-c", `ssh -V; echo rc=$?`}, approveN(d, 1, "ssh", "allow"))
	if !strings.Contains(r.out, "rc=0") || !strings.Contains(r.errOut, "OpenSSH") {
		t.Fatalf("approved ssh must run:\n%s", r.dump())
	}
	s = r.execsOf("ssh")
	if len(s) != 1 || s[0].Decision != "allow" || s[0].Ticket == nil || s[0].Digest == "" {
		t.Fatalf("approved ssh record:\n%s", r.dump())
	}
	if env := s[0].Envelope; env == nil {
		t.Fatal("envelope missing")
	}
}

// An approved scp passes the permission only to its own ssh transport (a pair from the design):
// one card for scp, ssh is implied. A sibling nc in the same shell gets its own card.
func TestTripwireImpliedChildOnly(t *testing.T) {
	need(t, "scp", "ssh")
	d := newDevice()
	cmd := `scp -o BatchMode=yes -o ConnectTimeout=2 /etc/hostname wardend-test.invalid:/tmp/ 2>/dev/null; echo scp=$?; ` +
		`ssh -V 2>/dev/null; echo ssh=$?`
	r := run(t, twCfg(d, 1500*time.Millisecond), []string{"sh", "-c", cmd}, approveN(d, 1, "^scp", "allow"))
	scp := r.execsOf("scp")
	if len(scp) != 1 || scp[0].Class != "tripwire" || scp[0].Decision != "allow" {
		t.Fatalf("scp must be one approved card:\n%s", r.dump())
	}
	var implied, other []execRecord
	for _, e := range r.execsOf("ssh") {
		if e.Class == "implied" {
			implied = append(implied, e)
		} else {
			other = append(other, e)
		}
	}
	if len(implied) != 1 || implied[0].Decision != "allow" || implied[0].RootPid != scp[0].Tgid || implied[0].Ticket != nil {
		t.Fatalf("ssh under scp must be implied without a card:\n%s", r.dump())
	}
	// ssh -V after scp is not a child of scp: its own card, not approved (the second record is a
	// PATH-search retry served from the deny cache)
	if len(other) == 0 || other[0].Class != "tripwire" || other[0].Decision != "deny" || !strings.Contains(other[0].Reason, "ttl") ||
		!strings.Contains(r.out, "ssh=126") {
		t.Fatalf("sibling ssh must need its own card:\n%s", r.dump())
	}
}

// sudo under no_new_privs: refused at once, with a reason, without a card and without a TTL wait.
func TestTripwireSudoRefused(t *testing.T) {
	need(t, "sudo")
	if st, err := os.Stat("/usr/bin/sudo"); err != nil || st.Mode()&os.ModeSetuid == 0 {
		t.Skip("/usr/bin/sudo is not setuid")
	}
	d := newDevice()
	t0 := time.Now()
	r := run(t, twCfg(d, 30*time.Second), []string{"sh", "-c", `sudo -n true 2>/dev/null; echo rc=$?`}, nil)
	if el := time.Since(t0); el > 10*time.Second {
		t.Fatalf("refusal must not wait for a card: %s", el)
	}
	if !strings.Contains(r.out, "rc=126") {
		t.Fatalf("sudo must get EPERM:\n%s", r.dump())
	}
	s := r.execsOf("sudo")
	if len(s) == 0 || s[0].Class != "refuse" || s[0].Decision != "deny" || s[0].Errno != "operation not permitted" ||
		!strings.Contains(s[0].Reason, "no_new_privs") || s[0].Digest != "" || s[0].Rule != "privilege/sudo" {
		t.Fatalf("sudo record:\n%s", r.dump())
	}
}

// observe + tripwire: everything is allowed; the journal has the class and rule of what would happen.
func TestTripwireObserve(t *testing.T) {
	need(t, "ssh")
	r := run(t, Config{Mode: "observe", PolicyMode: "tripwire"}, []string{"sh", "-c", `ls -d / >/dev/null; ssh -V 2>/dev/null; echo ok`}, nil)
	if !strings.Contains(r.out, "ok") {
		t.Fatalf("%s", r.dump())
	}
	if s := r.execsOf("ssh"); len(s) == 0 || s[0].Class != "tripwire" || s[0].Decision != "allow" || !strings.Contains(s[0].Reason, "would require ticket") {
		t.Fatalf("observe ssh:\n%s", r.dump())
	}
	if l := r.execsOf("ls"); len(l) == 0 || l[0].Class != "logged" {
		t.Fatalf("observe ls:\n%s", r.dump())
	}
	var start struct {
		PolicyMode string   `json:"policyMode"`
		Packs      []string `json:"packs"`
	}
	for _, e := range r.entries {
		if e.Kind == "start" {
			if err := json.Unmarshal(e.Data, &start); err != nil {
				t.Fatal(err)
			}
		}
	}
	if start.PolicyMode != "tripwire" || len(start.Packs) == 0 {
		t.Fatalf("start record: %+v", start)
	}
}

// /proc/self/exe and /dev/fd/N are resolved via the caller's process, not wardend.
func TestResolveTargetViaCaller(t *testing.T) {
	f, err := os.Open("/etc/hostname")
	if err != nil {
		t.Skip("/etc/hostname")
	}
	defer f.Close()
	c := exec.Command("sleep", "5")
	c.Stdin = f
	if err := c.Start(); err != nil {
		t.Fatal(err)
	}
	defer c.Process.Kill()
	pid := c.Process.Pid
	sleepBin, _ := exec.LookPath("sleep")
	want, _ := filepath.EvalSymlinks(sleepBin)
	for i := 0; i < 50; i++ { // wait for the exec of sleep
		if got, _ := evalSymlinksAs("/proc/self/exe", pid, pid); got == want {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	for p, w := range map[string]string{"/proc/self/exe": want, "/proc/thread-self/exe": want, "/dev/fd/0": "/etc/hostname", "/dev/stdin": "/etc/hostname"} {
		got, err := evalSymlinksAs(p, pid, pid)
		if err != nil || got != w {
			t.Errorf("%s: got %q (%v), want %q", p, got, err, w)
		}
	}
	// ordinary paths: same as filepath.EvalSymlinks
	for _, p := range []string{"/bin/sh", "/usr/bin/../bin/env", "/etc/hostname"} {
		a, _ := filepath.EvalSymlinks(p)
		if b, err := evalSymlinksAs(p, pid, pid); err != nil || a != b {
			t.Errorf("%s: %q vs %q (%v)", p, b, a, err)
		}
	}
	ev := &execEvent{Path: "/proc/self/exe", Tgid: pid, Pid: pid}
	resolveTarget(ev, "/")
	if ev.Target != want {
		t.Errorf("resolveTarget: %q, want %q", ev.Target, want)
	}
}

// Bypassing path resolution via a foreign mount namespace: the process moves into its own
// user+mount ns with the unshare(2) syscall (nsexec.c), then execve's the target. Previously
// wardend resolved the path in its own ns and the class was logged without a card; now such a
// launch escalates to a mount-ns card and gets EPERM without approval.
func TestTripwireForeignMountNs(t *testing.T) {
	cc, err := exec.LookPath("cc")
	if err != nil {
		t.Skip("no C compiler")
	}
	nsexec := filepath.Join(t.TempDir(), "nsexec")
	if b, err := exec.Command(cc, "-O1", "-o", nsexec, "bench/nsexec.c").CombinedOutput(); err != nil {
		t.Fatalf("cc: %v %s", err, b)
	}
	d := newDevice()
	// no approver: the mount-ns card expires on TTL and yields EPERM
	r := run(t, twCfg(d, 1500*time.Millisecond), []string{nsexec, "/bin/true"}, nil)

	var mnt []execRecord
	for _, e := range r.execs {
		if e.Category == "mount-ns" {
			mnt = append(mnt, e)
		}
	}
	if len(mnt) == 0 {
		if strings.Contains(r.errOut, "unshare") { // kernel without unprivileged userns
			t.Skip("unprivileged user+mount namespaces unavailable")
		}
		t.Fatalf("exec in a foreign mount ns must produce a mount-ns card:\n%s", r.dump())
	}
	e := mnt[0]
	if e.Class != "tripwire" || e.Decision != "deny" || !strings.Contains(e.Reason, "ttl") {
		t.Fatalf("foreign-ns exec must be a denied mount-ns card:\n%s", r.dump())
	}
	// and the class skeleton does not count such a launch as logged
	if e.Class == "logged" {
		t.Fatalf("foreign-ns exec still logged:\n%s", r.dump())
	}
}

// A self-built executable (next-steps.md, item 1): a binary owned by the agent, run as a child,
// produces a self-built card with the file's provenance even if the rules do not know it by
// name. Previously it would have been logged without a card.
func TestTripwireSelfBuiltExe(t *testing.T) {
	cc, err := exec.LookPath("cc")
	if err != nil {
		t.Skip("no C compiler")
	}
	dir := t.TempDir()
	src := filepath.Join(dir, "tool.c")
	if err := os.WriteFile(src, []byte("int main(){return 0;}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	tool := filepath.Join(dir, "notcurl") // an innocent name, but the file was made by the agent
	if b, err := exec.Command(cc, "-o", tool, src).CombinedOutput(); err != nil {
		t.Fatalf("cc: %v %s", err, b)
	}
	d := newDevice()
	// sh is the first exec (supervised_cmd); the tool itself runs as its child
	r := run(t, twCfg(d, 1200*time.Millisecond), []string{"sh", "-c", tool + "; echo rc=$?"}, nil)

	var sb []execRecord
	for _, e := range r.execs {
		if e.Category == "self-built" {
			sb = append(sb, e)
		}
	}
	if len(sb) == 0 {
		t.Fatalf("an agent-owned exe must produce a self-built card:\n%s", r.dump())
	}
	e := sb[0]
	if e.Class != "tripwire" || e.Decision != "deny" || e.Provenance == nil || !strings.HasPrefix(e.Provenance.Kind, "elf") || e.Provenance.SHA256 == "" {
		t.Fatalf("self-built record wrong:\n%s\nprov=%+v", r.dump(), e.Provenance)
	}
	if !strings.Contains(r.out, "rc=126") { // a human sees EPERM as 126
		t.Fatalf("denied self-built exe must yield EPERM:\n%s", r.dump())
	}
}

func TestDefaultMaxPendingAndPolicyMode(t *testing.T) {
	c := &Config{StateDir: t.TempDir()}
	if err := c.fill(); err != nil {
		t.Fatal(err)
	}
	if c.MaxPending != 64 || c.PolicyMode != "tripwire" {
		t.Fatalf("max_pending %d, policy_mode %q", c.MaxPending, c.PolicyMode)
	}
	bad := &Config{StateDir: t.TempDir(), PolicyMode: "subtree"}
	if err := bad.fill(); err == nil {
		t.Fatal("bad policy_mode accepted")
	}
}
