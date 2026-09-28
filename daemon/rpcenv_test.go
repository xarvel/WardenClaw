// SPDX-License-Identifier: AGPL-3.0-or-later

package main

// An in-process supervisor without seccomp (newHWSupervisor) with its RPC on a real unix socket:
// pairing, status and the socket's peer check.

import (
	"crypto/ed25519"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"unsafe"

	"golang.org/x/sys/unix"

	"github.com/xarvel/WardenClaw/daemon/envelope"
)

type rpcEnv struct {
	s    *supervisor
	sock string
}

// newRPCEnv: ticket mode; without an argument no device is trusted.
func newRPCEnv(t *testing.T, trusted ...device) *rpcEnv {
	t.Helper()
	d := newDevice()
	if len(trusted) > 0 {
		d = trusted[0]
	}
	s := newHWSupervisor(t, `{}`, d)
	if len(trusted) == 0 {
		s.devices.Remove(d.id)
	}
	s.pair = newPairing()
	s.supervisorID = envelope.DeviceID(s.key.Public().(ed25519.PublicKey))
	sock := filepath.Join(s.cfg.StateDir, "w.sock")
	r, err := startRPC(sock, s)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(r.close)
	return &rpcEnv{s: s, sock: sock}
}

func rpcDo(t *testing.T, sock, method string, params any, out any) error {
	t.Helper()
	c, err := dialRPC(sock)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	return c.call(method, params, out)
}

// A socket client under a seccomp filter (like the gateway/agent under wardend) does not control
// pairing.
func TestPairRPCRefusedUnderFilter(t *testing.T) {
	e := newRPCEnv(t)
	if e.s.peerSupervised(os.Getpid()) {
		t.Fatal("test process itself must be allowed")
	}
	cmd := exec.Command(os.Args[0], "-test.run=^$")
	cmd.Env = append(os.Environ(), "WARDEND_TEST_HELPER=filtered")
	out, _ := cmd.StdoutPipe()
	stdin, _ := cmd.StdinPipe()
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { stdin.Close(); cmd.Wait() }()
	buf := make([]byte, 16)
	if n, _ := out.Read(buf); !strings.HasPrefix(string(buf[:n]), "ready") {
		t.Fatalf("helper: %q", buf[:n])
	}
	if !e.s.peerSupervised(cmd.Process.Pid) {
		t.Fatal("process with an extra seccomp filter must count as supervised")
	}
	// a descendant of the supervisor's child (even without an extra filter)
	sl := exec.Command("sleep", "5")
	sl.Start()
	defer sl.Process.Kill()
	e.s.childPid = os.Getpid()
	if !e.s.peerSupervised(sl.Process.Pid) {
		t.Fatal("descendant of the supervised child must count as supervised")
	}
	e.s.childPid = -1
}

// helperFiltered: TestMain mode: install an allowing seccomp filter and wait on stdin.
func helperFiltered() {
	unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)
	prog := []unix.SockFilter{{Code: 0x06, K: 0x7fff0000}} // BPF_RET|BPF_K SECCOMP_RET_ALLOW
	fp := unix.SockFprog{Len: 1, Filter: &prog[0]}
	if _, _, errno := unix.Syscall(unix.SYS_SECCOMP, 1 /* SET_MODE_FILTER */, 0, uintptrOf(&fp)); errno != 0 {
		fmt.Println("seccomp:", errno)
		os.Exit(1)
	}
	fmt.Print("ready")
	io.Copy(io.Discard, os.Stdin)
	os.Exit(0)
}

func uintptrOf(fp *unix.SockFprog) uintptr { return uintptr(unsafe.Pointer(fp)) }
