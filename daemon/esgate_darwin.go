// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build darwin && cgo

package main

// The Endpoint Security gate: every AUTH_EXEC of the supervised tree becomes an execEvent and goes
// through decide1 as on Linux. The kernel copied argv, env and the target itself, so there is no
// memory to read and no TOCTOU post-check.
//
// "The command waits for the ticket" is the kernel's wait, as on Linux: the AUTH_EXEC message is
// not answered until the ticket is decided, and the caller sits inside execve until then. The
// difference is the kernel's own deadline per message: the ticket wait of an exec is capped at
// what is left of that deadline minus a margin (execEvent.ttl, decide1), and a watchdog answers
// DENY if nothing came back by then, so the deadline is never missed. With a descendants client
// (macOS 27) the floor of that deadline is raised to the ticket TTL first
// (es_set_deadline_min_milliseconds), so the cap only matters for the global client. A SIGSTOP of the caller was
// considered and rejected: the agent owns the stopped process and could SIGCONT it before the
// decision. Fail-closed on every leg: no gate, no answer, no budget, a late decision: DENY.
//
// Two client scopes (config gate.scope): "descendants" (macOS 27, es_new_descendants_client) sees
// wardend's descendants only; "global" (es_new_client) sees every exec on the host and answers
// ALLOW at once for what is not ours. In both the supervised tree is tracked from fork/exit
// notifications (gatetree.go): the kernel's "descendant of wardend" includes what wardend starts
// outside the gate (rootexec commands), and a walk of parent pids would lose an orphan whose
// parent exited. Membership = the tree rooted at the supervised command; an orphan stays in.
//
// Unverified on hardware: this file builds only on a Mac with cgo; the EC2 stand is pending.

/*
#cgo LDFLAGS: -lEndpointSecurity -lbsm
#include <stdlib.h>
#include "esgate_darwin.h"
*/
import "C"

import (
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"

	"github.com/xarvel/WardenClaw/daemon/envelope"
)

const (
	esCloseWait      = 3 * time.Second        // in-flight decisions get this long to answer the kernel at close
	esShortDeadline  = 500 * time.Millisecond // a message that arrives with less than this left is counted and logged once
	esDeadlineMargin = 1 * time.Second        // the answer must reach the kernel this long before its deadline
	esMinBudget      = 2 * time.Second        // less than this to wait for a ticket: no card, DENY
)

// esGate is the running client; esActive points at the one goESExec and the notifications go to.
type esGate struct {
	s            *supervisor
	scope        string    // descendants | global
	deadlineMiss string    // fail-closed | kill
	uid          int       // the child user
	floorMs      int64     // the AUTH_EXEC deadline floor the kernel confirmed (descendants client), 0 otherwise
	tree         *gateTree // members of the supervised tree; empty until setRoot
	root         atomic.Int64
	rootOnce     sync.Once
	inflight     sync.WaitGroup
	closed       atomic.Bool
	shortOnce    sync.Once
	// counters for the journal and status
	seen, outside, short, truncated, missed atomic.Int64
}

var esActive atomic.Pointer[esGate]

// startESGate opens the client for the configured scope and deadline mode; the command is not
// started if this fails. childUID is the uid the command runs as (rootexec_darwin.go asks).
func startESGate(s *supervisor, cfg *Config, childUID int) (execGate, error) {
	scope := cfg.gateScope()
	hasDesc := C.wc_es_has_descendants() != 0
	switch scope {
	case gateScopeAuto:
		scope = gateScopeGlobal
		if hasDesc {
			scope = gateScopeDescendants
		}
	case gateScopeDescendants:
		if !hasDesc {
			return nil, errors.New("gate.scope descendants: es_new_descendants_client is not available on this macOS (27 or newer); use auto or global")
		}
	}
	miss := cfg.gateDeadlineMiss()
	if miss == gateMissFailClosed && C.wc_es_has_deadline_mode() == 0 {
		return nil, errors.New("no es_set_deadline_miss_mode (a macOS 27 host and a wardend built against the macOS 27 SDK): an exec wardend does not answer in time would be ALLOWED and wardend killed. " +
			"That is not acceptable by default; set gate.deadline_miss to \"kill\" to accept it")
	}
	g := &esGate{s: s, scope: scope, deadlineMiss: miss, uid: childUID, tree: newGateTree(0)}
	if !esActive.CompareAndSwap(nil, g) {
		return nil, errors.New("an Endpoint Security gate is already running in this process")
	}
	// A descendants client may raise the AUTH_EXEC deadline floor: the ticket TTL plus the margin
	// of the gate and a second of slack, so that a card can be answered for the whole TTL.
	var minMs C.uint32_t
	if scope == gateScopeDescendants {
		minMs = C.uint32_t((cfg.TicketTTL.Duration + esDeadlineMargin + time.Second).Milliseconds())
	}
	var cerr *C.char
	var floorMs C.uint32_t
	rc := C.wc_es_open(cbool(scope == gateScopeDescendants), cbool(miss == gateMissFailClosed), 1, minMs, &floorMs, &cerr)
	if rc != 0 { // WC_ES_OK
		esActive.CompareAndSwap(g, nil)
		return nil, fmt.Errorf("endpoint security: %s", C.GoString(cerr))
	}
	g.floorMs = int64(floorMs)
	return g, nil
}

func cbool(b bool) C.int {
	if b {
		return 1
	}
	return 0
}

// setRoot: the supervised command has a pid; the tree starts there. The first call wins: the
// gate itself calls it from the command's first exec (goESExec), which happens inside
// child.Start, before the supervisor has the pid; the supervisor's call after Start is the check
// that both saw the same process (rootPid). The supervisor's childPid is set here too, so that
// decide1 classifies that first exec as supervised_cmd.
func (g *esGate) setRoot(pid int) {
	g.rootOnce.Do(func() {
		g.tree.SetRoot(pid)
		g.root.Store(int64(pid))
		if g.s.childPid == 0 {
			g.s.childPid = pid
		}
	})
}

// rootPid: the root the gate works with, 0 before the command's first exec.
func (g *esGate) rootPid() int { return int(g.root.Load()) }

// member: pid belongs to the supervised tree (nobody does before the root is known).
func (g *esGate) member(pid, ppid int) bool { return g.tree.Member(pid, ppid) }

func (g *esGate) childUID() int { return g.uid }

func (g *esGate) info() map[string]any {
	return map[string]any{"kind": "endpoint-security", "scope": g.scope, "deadlineMiss": g.deadlineMiss, "deadlineFloorMs": g.floorMs,
		"seen": g.seen.Load(), "outsideTree": g.outside.Load(), "shortDeadline": g.short.Load(), "deadlineMissed": g.missed.Load(), "truncated": g.truncated.Load(), "tree": g.tree.Len()}
}

// close: in-flight decisions answer the kernel first (the supervisor resolved the queue, so the
// callers waiting for a ticket get DENY now), then the client goes away.
func (g *esGate) close() {
	if !g.closed.CompareAndSwap(false, true) {
		return
	}
	done := make(chan struct{})
	go func() {
		g.inflight.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(esCloseWait):
		g.s.logf("wardend: endpoint security: in-flight decisions did not finish in %s before the close\n", esCloseWait)
	}
	C.wc_es_close()
	esActive.CompareAndSwap(g, nil)
}

// goESExec is called by the handler (esgate_darwin.c) on ES's queue for every AUTH_EXEC. It must
// return quickly: the message is answered here only for processes outside the tree; for the
// tree the event is copied and decided in a goroutine.
//
//export goESExec
func goESExec(x *C.wc_exec_t, msg unsafe.Pointer) {
	g := esActive.Load()
	if g == nil || g.closed.Load() {
		C.wc_es_respond(msg, 0) // no gate to decide: fail closed
		return
	}
	g.seen.Add(1)
	if int64(x.deadline_ms) < esShortDeadline.Milliseconds() {
		g.short.Add(1)
		g.shortOnce.Do(func() {
			g.s.logf("wardend: endpoint security: a message arrived with %d ms of its deadline left (counted in status; the flow is unchanged)\n", int64(x.deadline_ms))
		})
	}
	pid, ppid := int(x.pid), int(x.ppid)
	// The first exec by a child of wardend after the gate opened is the supervised command: the
	// supervisor forks nothing else between startESGate and child.Start, and Start returns only
	// after this exec is answered. Later children of wardend (rootexec commands) are outside.
	if g.rootPid() == 0 && ppid == g.s.supPid {
		g.setRoot(pid)
	}
	// Outside the tree: the kernel is answered at once and nothing is journaled.
	if !g.member(pid, ppid) {
		g.outside.Add(1)
		C.wc_es_respond(msg, 1)
		return
	}
	ev := g.event(x)
	deadlineMs := int64(x.deadline_ms)
	g.inflight.Add(1)
	g.s.goSafe("es exec", func() {
		defer g.inflight.Done()
		g.handle(ev, msg, deadlineMs)
	})
}

// goESFork / goESExit feed the tree (gatetree.go) from the notifications.
//
//export goESFork
func goESFork(parent, child C.int32_t) {
	if g := esActive.Load(); g != nil {
		g.tree.Fork(int(parent), int(child))
	}
}

//export goESExit
func goESExit(pid C.int32_t) {
	if g := esActive.Load(); g != nil {
		g.tree.Exit(int(pid))
	}
}

// event copies a wc_exec_t into an execEvent. Everything the kernel resolved is taken as is:
// the target is a real path already (no resolveTarget), argv and env are what the new image
// will see.
func (g *esGate) event(x *C.wc_exec_t) *execEvent {
	pid := int(x.pid)
	ev := &execEvent{Pid: pid, Tgid: pid, PPid: int(x.ppid), Threads: 1,
		Start: uint64(x.start_sec)*1_000_000 + uint64(x.start_usec),
		UID:   int(x.euid), GID: int(x.egid), Syscall: "exec",
		Target: cstr(x.target_exe), TargetDev: uint64(x.target_dev), TargetIno: uint64(x.target_ino),
		TargetUID: uint32(x.target_uid), TargetMode: uint32(x.target_mode),
		CallerExe: cstr(x.caller_exe), Cwd: cstr(x.cwd)}
	// Path: what was asked for. A script exec reports the script (the target is its
	// interpreter, as the kernel rewrote argv to name it).
	ev.Path = ev.Target
	if script := cstr(x.script); script != "" {
		ev.Path = script
	}
	ev.CallerCmd, _ = procCmdline(pid)
	ev.Argv = unpack(x.argv, x.argv_len, x.argc)
	ev.ArgvOK = x.argv_truncated == 0
	env := unpack(x.env, x.env_len, x.envc)
	ev.EnvHash = envHash(env)
	ev.EnvCount = len(env)
	ev.Env = envelope.SelectEnv(env)
	ev.Chain = chainOf(pid, g.s.supPid)
	var errs []string
	if x.argv_truncated != 0 {
		errs = append(errs, "argv: longer than the gate copies")
	}
	if x.env_truncated != 0 {
		errs = append(errs, "env: longer than the gate copies")
	}
	if len(errs) > 0 {
		g.truncated.Add(1)
		ev.ReadError = strings.Join(errs, "; ")
	}
	return ev
}

func cstr(s C.wc_str_t) string {
	if s.data == nil || s.len == 0 {
		return ""
	}
	return C.GoStringN(s.data, C.int(s.len))
}

// unpack splits a NUL-separated buffer of n strings.
func unpack(buf *C.char, n C.size_t, count C.uint32_t) []string {
	if buf == nil || n == 0 {
		return []string{}
	}
	b := C.GoBytes(unsafe.Pointer(buf), C.int(n))
	out := make([]string, 0, int(count))
	for len(b) > 0 && len(out) < int(count) {
		i := 0
		for i < len(b) && b[i] != 0 {
			i++
		}
		out = append(out, string(b[:i]))
		if i < len(b) {
			i++
		}
		b = b[i:]
	}
	return out
}

// handle: the record, the decision, the journal and the metrics, as supervisor_linux.go handle
// does for a seccomp notification. The kernel is answered when decide1 returns, which is at the
// latest at the event's ttl (what is left of the message deadline minus esDeadlineMargin); a
// watchdog at the same point answers DENY should decide1 be late for any other reason.
func (g *esGate) handle(ev *execEvent, msg unsafe.Pointer, deadlineMs int64) {
	s := g.s
	respond := func(allow bool) error {
		if r := C.wc_es_respond(msg, cbool(allow)); r != 0 {
			return fmt.Errorf("es_respond_auth_result: %d", int(r))
		}
		return nil
	}
	t0 := time.Now()
	rec := &execRecord{Pid: ev.Pid, Tgid: ev.Tgid, PPid: ev.PPid, Syscall: ev.Syscall, Path: ev.Path, Exe: ev.Target,
		CallerExe: ev.CallerExe, Argv: ev.Argv, Cwd: ev.Cwd, EnvHash: ev.EnvHash, UID: ev.UID, Chain: ev.Chain, ReadError: ev.ReadError}
	left := time.Duration(deadlineMs) * time.Millisecond
	budget := left - esDeadlineMargin
	rec.Deadline = &deadlineRecord{LeftMs: deadlineMs, BudgetMs: budget.Milliseconds()}
	var allow bool
	switch {
	case budget < esMinBudget:
		// Not enough time for a card to be asked and answered: the kernel gets DENY now, without
		// a ticket. Classification still runs for the journal (ttl of a few ms: no card is queued
		// long enough to reach a device).
		rec.Deadline.TooShort = true
		ev.ttl = time.Millisecond
		allow = s.decideBool(ev, rec)
		if allow {
			rec.Reason = strings.TrimSpace(rec.Reason + " (allowed by the policy; the deadline budget was too short for a card anyway)")
		}
		if rerr := respond(allow); rerr != nil {
			rec.Reason = strings.TrimSpace(rec.Reason + " respond: " + rerr.Error())
			allow = false
		}
	default:
		ev.ttl = budget
		done := make(chan bool, 1)
		go func() { done <- s.decideBool(ev, rec) }()
		select {
		case allow = <-done:
		case <-time.After(budget):
			// decide1 is late (its own wait is at most the budget, so this is the relay or the
			// journal being slow): the kernel gets DENY now and the late decision is discarded.
			rec.Deadline.Missed = true
			g.missed.Add(1)
			if rerr := respond(false); rerr != nil {
				rec.Reason = strings.TrimSpace(rec.Reason + " respond: " + rerr.Error())
			}
			<-done
			allow = false
			rec.Reason = strings.TrimSpace(rec.Reason + " (no decision before the kernel's deadline: denied)")
			goto journal
		}
		if rerr := respond(allow); rerr != nil {
			// The kernel did not take the answer: whatever it does with the exec is its own
			// deadline handling (fail-closed on macOS 27); the record says deny.
			rec.Reason = strings.TrimSpace(rec.Reason + " respond: " + rerr.Error())
			allow = false
		}
	}
journal:
	lat := time.Since(t0).Microseconds() - rec.WaitUs
	s.m.execs.Add(1)
	s.m.class(rec.Class)
	s.m.latency.add(lat)
	if allow {
		rec.Decision = "allow"
		s.m.allowed.Add(1)
	} else {
		rec.Decision = "deny"
		if rec.Errno == "" {
			rec.Errno = unix.EPERM.Error()
		}
		s.m.denied.Add(1)
	}
	rec.LatencyUs = lat
	s.journal("exec", rec)
}

// decideBool is decide1 without the Linux-only results: the post-check mode and the pidfd have no
// meaning here (ES gives the kernel's own copy of the exec; there is no pidfd on macOS).
func (s *supervisor) decideBool(ev *execEvent, rec *execRecord) bool {
	allow, errno, _, pidfd := s.decide1(ev, rec)
	closeFd(pidfd)
	if !allow {
		rec.Errno = errno.Error()
	}
	return allow
}
