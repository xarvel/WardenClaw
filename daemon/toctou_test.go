// SPDX-License-Identifier: AGPL-3.0-or-later

package main

// TOCTOU: an "evil" process (bench/evil_argv.c) rewrites argv[1] from a second thread while the
// main one does execve. The device approves only envelopes with argv[1] == "SAFE-ARG".
// Leak = echo printed something other than SAFE-ARG (the kernel copied something other than what
// was approved).

import (
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/xarvel/WardenClaw/daemon/envelope"
)

func buildEvil(t *testing.T) string {
	t.Helper()
	cc, err := exec.LookPath("cc")
	if err != nil {
		t.Skip("no C compiler")
	}
	out := filepath.Join(t.TempDir(), "evil_argv")
	if b, err := exec.Command(cc, "-O1", "-pthread", "-o", out, "bench/evil_argv.c").CombinedOutput(); err != nil {
		t.Fatalf("cc: %v %s", err, b)
	}
	return out
}

func approveSafeOnly(d device, stop <-chan struct{}) func(string) {
	return func(sock string) {
		c, err := dialRPC(sock)
		if err != nil {
			return
		}
		defer c.Close()
		done := map[string]bool{}
		var since int64
		for {
			select {
			case <-stop:
				return
			default:
			}
			var p struct {
				Seq     int64         `json:"seq"`
				Pending []pendingItem `json:"pending"`
			}
			if err := c.call("pending", map[string]any{"since": since, "wait": 300}, &p); err != nil {
				return
			}
			since = p.Seq
			for _, it := range p.Pending {
				if done[it.ID] {
					continue
				}
				done[it.ID] = true
				dec := "deny"
				if a, ok := it.Envelope["argv"].([]any); ok && len(a) == 2 && a[1] == "SAFE-ARG" {
					dec = "allow"
				}
				var r map[string]any
				c.call("decide", envelope.Sign(d.priv, supOf(&it), it.ID, it.Digest, dec, envelope.NowMs(), envelope.NewNonce()), &r)
			}
		}
	}
}

type evilStats struct {
	approved, denied, printedSafe, leaked, kills int
	leaks                                        []string
}

func runEvil(t *testing.T, mode toctouMode, iters int) evilStats {
	evil := buildEvil(t)
	d := newDevice()
	pol := filepath.Join(t.TempDir(), "policy.json")
	os.WriteFile(pol, []byte(`{"service_allow":[{"id":"evil-test-binary","path":"^`+evil+`$"}]}`), 0o600)
	stop := make(chan struct{})
	var r *result
	func() {
		defer close(stop)
		r = run(t, Config{Mode: "ticket", Policy: pol, TrustedDevices: []envelope.TrustedDevice{d.trusted()},
			TicketTTL: duration{5 * time.Second}, ToctouRoots: string(mode)},
			[]string{"bash", "-c", "for i in $(eval echo {1.." + strconv.Itoa(iters) + "}); do " + evil + " 2>/dev/null; done; true"},
			approveSafeOnly(d, stop))
	}()
	var s evilStats
	for _, line := range strings.Split(r.out, "\n") {
		switch {
		case line == "":
		case line == "SAFE-ARG":
			s.printedSafe++
		default:
			s.leaked++
			s.leaks = append(s.leaks, line)
		}
	}
	for _, e := range r.execs {
		if e.Class != "root" {
			continue
		}
		if e.Decision == "allow" {
			s.approved++
		} else {
			s.denied++
		}
		if e.Toctou != nil && e.Toctou.Outcome == "mismatch_killed" {
			s.kills++
		}
	}
	t.Logf("toctou=%s iters=%d: approved=%d denied=%d printed SAFE=%d LEAKED=%d %q killed=%d",
		mode, iters, s.approved, s.denied, s.printedSafe, s.leaked, s.leaks, s.kills)
	return s
}

// stop-verify: the new image stops before the first instruction, substitution is caught, no leaks.
func TestToctouEvilStop(t *testing.T) {
	s := runEvil(t, toctouStop, 40)
	if s.leaked != 0 {
		t.Fatalf("stop mode leaked %d: %q", s.leaked, s.leaks)
	}
	if s.approved == 0 {
		t.Fatal("nothing approved: test did not exercise the race")
	}
	if s.printedSafe+s.kills != s.approved {
		t.Fatalf("approved=%d = printed SAFE %d + killed %d expected", s.approved, s.printedSafe, s.kills)
	}
}

// Without the check the race is real (confirmation that the test catches anything at all); poll
// has a window. These modes do not fail: they document the window (README, "TOCTOU: post-check").
func TestToctouEvilOffAndPollWindow(t *testing.T) {
	off := runEvil(t, toctouOff, 40)
	poll := runEvil(t, toctouPoll, 40)
	t.Logf("off: leaked %d of %d approved; poll: leaked %d, killed %d of %d approved", off.leaked, off.approved, poll.leaked, poll.kills, poll.approved)
}

// SIGSTOP/SIGCONT around an approved exec are visible to the parent (CLD_STOPPED/CONTINUED). We
// check that typical parents, dash/bash (above), python subprocess (vfork/posix_spawn), node
// child_process (libuv fork), do not break: output and exit codes are the same as without wardend.
func TestStopVerifyParents(t *testing.T) {
	d := newDevice()
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("no node")
	}
	script := `import subprocess,sys
r = subprocess.run(["bash","-c","echo py-child; exit 3"])
print("py rc", r.returncode)
o = subprocess.check_output(["bash","-c","echo py-out"]).decode().strip()
print("py out", o)
r = subprocess.run(["` + node + `","-e","const cp=require('child_process');console.log(cp.execSync('echo node-child').toString().trim());const r=cp.spawnSync('bash',['-c','exit 5']);console.log('node rc',r.status)"])
print("node exit", r.returncode)`
	r := run(t, Config{Mode: "ticket", TrustedDevices: []envelope.TrustedDevice{d.trusted()}, TicketTTL: duration{10 * time.Second}},
		[]string{"python3", "-u", "-c", script}, approveN(d, 3, "", "allow"))
	want := "py-child\npy rc 3\npy out py-out\nnode-child\nnode rc 5\nnode exit 0\n"
	if r.out != want {
		t.Fatalf("got %q want %q\n%s", r.out, want, r.dump())
	}
	n := 0
	for _, e := range r.byClass("root") {
		if e.Toctou == nil || e.Toctou.Outcome != "match" {
			t.Fatalf("root without stop-verify match: %+v", e)
		}
		n++
	}
	if n != 3 {
		t.Fatalf("want 3 ticketed roots (bash, bash, node):\n%s", r.dump())
	}
}
