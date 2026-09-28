// SPDX-License-Identifier: AGPL-3.0-or-later

package main

// Red team (in-process): attacks that try to bypass wardend WITHOUT touching inter-process
// vectors (kill/ptrace/writes to files); those need a separate uid and are covered in
// redteam/run.sh and redteam/README.md. Here are the vectors that wardend closes regardless of
// uid: bypassing the exec gate via memfd/ld.so, a nested filter, self-approval over the
// transport, ticket forgery.
//
// Each redteam helper runs AS A COMMAND under the filter (env WARDEND_TEST_HELPER=<mode>,
// see TestMain), i.e. in the position of a malicious descendant of the harness.

import (
	"fmt"
	"os"
	"strings"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"

	"github.com/xarvel/WardenClaw/daemon/envelope"
)

// redteamMemfdExec: copy /bin/true into an anonymous memfd and try execveat(AT_EMPTY_PATH).
// Expected under ticket without approval: the exec is gated, the memfd realpath does not
// resolve → class=missing → deny.
func redteamMemfdExec() {
	fd, err := unix.MemfdCreate("rt", 0)
	if err != nil {
		fmt.Printf("memfd-exec: memfd_create: %v\n", err)
		os.Exit(0)
	}
	data, err := os.ReadFile("/bin/true")
	if err == nil {
		unix.Pwrite(fd, data, 0)
	}
	name, _ := unix.BytePtrFromString("rt")
	empty, _ := unix.BytePtrFromString("")
	argv := []*byte{name, nil}
	envp := []*byte{nil}
	_, _, e := unix.Syscall6(unix.SYS_EXECVEAT, uintptr(fd), uintptr(unsafe.Pointer(empty)),
		uintptr(unsafe.Pointer(&argv[0])), uintptr(unsafe.Pointer(&envp[0])), uintptr(0x1000 /*AT_EMPTY_PATH*/), 0)
	// we get here ONLY if execveat failed (otherwise the image was replaced with /bin/true)
	fmt.Printf("memfd-exec: blocked errno=%v\n", e)
	os.Exit(0)
}

// redteamLdSo: run /bin/true directly via the dynamic linker (ld.so /bin/true).
// This is a plain execve of ld.so itself → gated like any exec.
func redteamLdSo() {
	cands := []string{"/lib/ld-linux-aarch64.so.1", "/lib64/ld-linux-x86-64.so.2", "/lib/ld-linux-armhf.so.3"}
	ld := ""
	for _, c := range cands {
		if _, err := os.Stat(c); err == nil {
			ld = c
			break
		}
	}
	if ld == "" {
		fmt.Println("ldso: no ld.so found")
		os.Exit(0)
	}
	err := unix.Exec(ld, []string{ld, "/bin/true"}, os.Environ())
	fmt.Printf("ldso: blocked err=%v\n", err)
	os.Exit(0)
}

// TestRedteamMemfdIntercepted: an exec from an anonymous memfd (execveat AT_EMPTY_PATH) is NOT a
// silent bypass; it is intercepted by the same USER_NOTIF as a regular execve. In observe this
// shows up as an execveat record in the journal; in enforce it would be subject to the same
// rules (see the next test).
func TestRedteamMemfdIntercepted(t *testing.T) {
	r := run(t, Config{Mode: "observe"}, []string{"env", "WARDEND_TEST_HELPER=memfd", os.Args[0]}, nil)
	found := false
	for _, e := range r.execs {
		if e.Syscall == "execveat" {
			found = true
		}
	}
	if !found {
		t.Fatalf("execveat from memfd must be intercepted by the notifier:\n%s", r.dump())
	}
}

// TestRedteamMemfdDeniedUnapproved: a memfd/any exec as an UNapproved root in ticket is denied;
// an attacker cannot run their own code (including from a memfd) without a ticket.
func TestRedteamMemfdDeniedUnapproved(t *testing.T) {
	d := newDevice()
	r := run(t, Config{Mode: "ticket", TrustedDevices: []envelope.TrustedDevice{d.trusted()}, TicketTTL: duration{600 * time.Millisecond}},
		[]string{"env", "WARDEND_TEST_HELPER=memfd", os.Args[0]}, nil)
	// the exec of the helper binary (the root) is denied on TTL → the memfd code itself never ran
	if strings.Contains(r.out, "memfd-exec") {
		t.Fatalf("unapproved root must not have run:\n%s", r.dump())
	}
	roots := r.byClass("root")
	if len(roots) == 0 || roots[0].Decision != "deny" {
		t.Fatalf("unapproved exec must be deny:\n%s", r.dump())
	}
}

// TestRedteamLdSoIntercepted: running a binary directly via ld.so is a plain execve of ld.so,
// intercepted by the notifier (visible in the journal in observe).
func TestRedteamLdSoIntercepted(t *testing.T) {
	r := run(t, Config{Mode: "observe"}, []string{"env", "WARDEND_TEST_HELPER=ldso", os.Args[0]}, nil)
	if strings.Contains(r.out, "no ld.so") {
		t.Skip("ld.so not found")
	}
	found := false
	for _, e := range r.execs {
		if strings.Contains(e.Path, "ld-") || strings.Contains(e.Exe, "ld-") {
			found = true
		}
	}
	if !found {
		t.Fatalf("exec via ld.so must be intercepted:\n%s", r.dump())
	}
}

// TestRedteamSupervisedCannotSelfApprove: a descendant under the filter can neither pair a
// device for itself (peerSupervised) nor approve a ticket without a trusted device's key.
func TestRedteamSupervisedCannotSelfApprove(t *testing.T) {
	d := newDevice()
	evil := newDevice()
	var pairErr, decideReason string
	r := run(t, Config{Mode: "ticket", TrustedDevices: []envelope.TrustedDevice{d.trusted()}, TicketTTL: duration{1500 * time.Millisecond}},
		[]string{"sh", "-c", `bash -c 'echo SHOULD-NOT-RUN'; echo rc=$?`},
		func(sock string) {
			c, err := dialRPC(sock)
			if err != nil {
				t.Error(err)
				return
			}
			defer c.Close()
			// wait for the card
			var p struct {
				Pending []pendingItem `json:"pending"`
			}
			for i := 0; i < 50 && len(p.Pending) == 0; i++ {
				c.call("pending", map[string]any{"wait": 100}, &p)
			}
			if len(p.Pending) == 1 {
				// self-approval with an untrusted key (the agent generated its own) → rejected
				var res map[string]any
				b := envelope.Sign(evil.priv, supOf(&p.Pending[0]), p.Pending[0].ID, p.Pending[0].Digest, "allow", envelope.NowMs(), envelope.NewNonce())
				c.call("decide", b, &res)
				decideReason = fmt.Sprint(res["reason"])
			}
		})
	_ = pairErr
	if strings.Contains(r.out, "SHOULD-NOT-RUN") {
		t.Fatalf("self-approval with an untrusted key went through:\n%s", r.dump())
	}
	if decideReason != "untrusted_device" {
		t.Fatalf("want untrusted_device, got %q", decideReason)
	}
}
