// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build darwin

package main

// The macOS supervisor: the gate is an Endpoint Security client inside wardend itself
// (esgate_darwin.go). wardend runs as root (ES needs it) and starts the command directly as the
// child user; every exec of the command's tree reaches goESExec, which decides through the same
// decide1 as Linux while the kernel holds the caller in execve; the wait is capped by the
// message's deadline (esgate_darwin.go).
//
// Differences from Linux (supervisor_linux.go): no helper child and no socketpair (nothing to
// install in the child), no reaper (the tree is tracked by fork/exit notifications, not by
// re-parenting), no TOCTOU post-check (ES hands over the argv and the target the kernel copied).

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"os/user"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/xarvel/WardenClaw/daemon/envelope"
	"github.com/xarvel/WardenClaw/daemon/hwkey"
	"github.com/xarvel/WardenClaw/daemon/journal"
	"github.com/xarvel/WardenClaw/daemon/policy"
)

// execGate is what the supervisor and rootexec see of the Endpoint Security gate (esgate_darwin.go
// implements it with cgo; esgate_darwin_nocgo.go refuses to start one).
type execGate interface {
	// setRoot names the supervised command once it has a pid: the root of the tree. The first
	// call wins; rootPid is what the gate works with (0 before the command's first exec).
	setRoot(pid int)
	rootPid() int
	// member: pid (with parent ppid) belongs to the supervised tree.
	member(pid, ppid int) bool
	// childUID: the uid the command runs as.
	childUID() int
	// info: what the journal and status say about the gate (scope, deadline mode, counters).
	info() map[string]any
	// close stops the client; pending execs are answered by the supervisor before this.
	close()
}

// One ES client per process: rootexec (rootexec_darwin.go) asks the running gate about a
// requester; the supervisor struct has no OS-specific field for it.
var (
	gateMu     sync.Mutex
	activeGate execGate
)

func setCurrentGate(g execGate) {
	gateMu.Lock()
	activeGate = g
	gateMu.Unlock()
}

// currentGate: the running gate, nil before the start and after the close.
func currentGate() execGate {
	gateMu.Lock()
	defer gateMu.Unlock()
	return activeGate
}

const errChildUserRequired = "wardend on macOS runs as root for Endpoint Security and must run the command as another user: set child_user (wardend wrap does it from SUDO_USER)"

func runSupervisor(cfg *Config, o *runOpts) (int, error) {
	if o.stdout == nil {
		o.stdout = os.Stdout
	}
	if o.stderr == nil {
		o.stderr = os.Stderr
	}
	if o.stdin == nil {
		o.stdin = os.Stdin
	}
	if err := cfg.fill(); err != nil {
		return 2, err
	}
	if os.Geteuid() != 0 || cfg.ChildUser == "" {
		return 2, errors.New(errChildUserRequired)
	}
	uid, gid, groups, err := resolveChildUser(cfg.ChildUser)
	if err != nil {
		return 2, fmt.Errorf("child_user %q: %w", cfg.ChildUser, err)
	}
	if uid == 0 {
		return 2, errors.New(errChildUserRequired)
	}
	// Installation integrity check: a writable binary/config/key means a model under the same uid
	// can disable wardend without exec. In enforce mode fatal violations stop the startup.
	exePath := o.helperExe
	if exePath == "" {
		exePath, _ = os.Executable()
	}
	if !o.noSelfCheck {
		if err := runSelfCheck(cfg, exePath, o.stderr, o.wrap != nil); err != nil {
			return 2, err
		}
	}
	pol, err := policy.Load(cfg.Policy)
	if err != nil {
		return 2, err
	}
	if err := pol.Setup(cfg.policyOptions(o.cmd, exePath)); err != nil {
		return 2, err
	}
	if err := hwFeatureCheck(len(cfg.HardwareKeys), len(pol.RequireHardware)); err != nil {
		return 2, err
	}
	hw, err := hwkey.NewStore(cfg.HardwareKeys, cfg.HardwareCounters)
	if err != nil {
		return 2, err
	}
	key, err := journal.LoadOrCreateKey(cfg.KeyFile)
	if err != nil {
		return 1, err
	}
	jr, err := journal.Open(cfg.Journal, key)
	if err != nil {
		return 1, err
	}
	defer jr.Close()
	pub := key.Public().(ed25519.PublicKey)
	s := &supervisor{
		cfg: cfg, pol: pol, jr: jr, key: key, supervisorID: envelope.DeviceID(pub), host: cfg.Host,
		devices: envelope.NewDevices(cfg.TrustedDevices), hw: hw, nonces: envelope.NewNonceCache(cfg.TsWindow.Duration),
		q: newQueue(cfg.MaxPending), m: newMetrics(), supPid: os.Getpid(), started: time.Now(), stderr: o.stderr, quiet: o.quiet,
	}
	s.tracker = policy.NewTracker(sysProc{}, s.supPid)
	s.denyCache = map[string]deniedReq{}
	s.lfd = -1
	s.pair = newPairing()
	s.wrap, s.pairWS = o.wrap != nil, o.pairWS
	printStartupWarnings(o.stderr, cfg, pol, hw, s.wrap)

	rpc, err := startRPC(cfg.Socket, s)
	if err != nil {
		return 1, err
	}
	defer rpc.close()
	// The relay (relaysup.go): an outbound socket, unless relay_url is off. If it fails to start, the
	// supervisor still runs: without it roots simply get no tickets (fail-closed), the reason is
	// shown in status.
	if cfg.relayOn() {
		rctx, rcancel := context.WithCancel(context.Background())
		defer func() { // what is being sent (the answer to the last ticket) goes out first
			if s.relay != nil {
				if n := s.relay.flush(relayFlushTimeout); n > 0 {
					fmt.Fprintf(o.stderr, "wardend: relay: %d frames were not sent before the exit\n", n)
				}
			}
			rcancel()
		}()
		if err := s.startRelay(rctx); err != nil {
			s.relayErr = err.Error()
			fmt.Fprintf(o.stderr, "wardend: relay %s: %v (no device can reach this wardend)\n", cfg.RelayURL, err)
		}
	}
	// wardend wrap: a device that can answer, before the command starts (wrap.go)
	if o.wrap != nil {
		if err := s.wrapPrepare(o.wrap, o.cmd); err != nil {
			return 1, err
		}
	}
	// rootexec requests from under the gate (rootexec.go); only with root_exec.enabled.
	if rx, err := startRootExec(cfg, s); err != nil {
		return 1, err
	} else if rx != nil {
		s.rootExec = rx
		defer rx.close()
	}

	// The command, as the child user, with that user's HOME/USER/LOGNAME (wardend's own
	// environment is root's under sudo). Started only after the gate is up: its first exec must be
	// seen, and the kernel answers it only through this client.
	path, err := exec.LookPath(o.cmd[0])
	if err != nil {
		return 127, err
	}
	child := exec.Command(path, o.cmd[1:]...)
	child.Stdin, child.Stdout, child.Stderr = o.stdin, o.stdout, o.stderr
	child.Env = childEnv(os.Environ(), cfg.ChildUser, uid)
	if o.helperEnv != nil {
		child.Env = append(child.Env, o.helperEnv...)
	}
	gs := make([]uint32, len(groups))
	for i, g := range groups {
		gs[i] = uint32(g)
	}
	child.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: uint32(uid), Gid: uint32(gid), Groups: gs}}

	g, err := startESGate(s, cfg, uid)
	if err != nil {
		return 2, err
	}
	setCurrentGate(g)
	defer setCurrentGate(nil)
	if err := child.Start(); err != nil {
		g.close()
		return 1, err
	}
	// The tree's root. The command's first exec happened inside Start and the gate took the root
	// from it (goESExec); this call is a no-op that lets us check both saw the same process.
	g.setRoot(child.Process.Pid)
	if r := g.rootPid(); r != child.Process.Pid {
		_ = child.Process.Kill()
		_ = child.Wait()
		g.close()
		return 1, fmt.Errorf("endpoint security: the gate took pid %d as the supervised command, Start returned pid %d: not gating a tree that is not ours", r, child.Process.Pid)
	}
	s.childPid = child.Process.Pid
	s.journal("start", hwStatus(map[string]any{
		"mode": cfg.Mode, "policyMode": cfg.PolicyMode, "packs": pol.PackNames(), "agentHome": pol.AgentHome(),
		"cmd": o.cmd, "childPid": child.Process.Pid, "childUser": cfg.ChildUser, "childUid": uid, "supervisorPid": s.supPid, "supervisorId": s.supervisorID,
		"host": s.host, "journalKey": jr.PublicKey(), "trustedDevices": s.devices.IDs(), "ticketTtlMs": cfg.TicketTTL.Milliseconds(),
		"maxPending": cfg.MaxPending, "toctouRoots": "off", "toctouService": "off", "socket": cfg.Socket,
		"relay": cfg.RelayURL, "rootExec": s.rootExecInfo(), "gate": g.info(),
	}, hw.Len(), len(pol.RequireHardware), nil))
	if !o.quiet && o.wrap == nil {
		fmt.Fprintf(o.stderr, "wardend: mode=%s policy=%s pid=%d child=%d gate=endpoint-security socket=%s journal=%s\n", cfg.Mode, cfg.PolicyMode, s.supPid, child.Process.Pid, cfg.Socket, cfg.Journal)
	}
	if o.onReady != nil {
		o.onReady(cfg.Socket)
	}

	// Signals: SIGTERM/SIGINT/SIGHUP/SIGQUIT/SIGUSR1/SIGUSR2 → the child (launchd stops the daemon
	// with SIGTERM to the main process, us; we pass it to the gateway and wait for its exit).
	sigc := make(chan os.Signal, 8)
	if !o.noSignals {
		signal.Notify(sigc, syscall.SIGTERM, syscall.SIGINT, syscall.SIGHUP, syscall.SIGQUIT, syscall.SIGUSR1, syscall.SIGUSR2)
		defer signal.Stop(sigc)
	}
	childDone := make(chan struct{})
	var childErr error
	s.goSafe("child wait", func() {
		childErr = child.Wait()
		close(childDone)
	})
	s.goSafe("signal forward", func() {
		for {
			select {
			case sig := <-sigc:
				_ = child.Process.Signal(sig)
				s.journal("signal", map[string]any{"signal": sig.String(), "forwardedTo": child.Process.Pid})
			case <-childDone:
				return
			}
		}
	})
	// Periodic cleanup of lineage/roots.
	sweepStop := make(chan struct{})
	s.goSafe("sweep", func() {
		t := time.NewTicker(sweepInterval)
		defer t.Stop()
		for {
			select {
			case <-t.C:
				for _, r := range s.tracker.Sweep() {
					s.journal("root_exit", map[string]any{"pid": r.Pid, "digest": r.Digest, "children": r.Children, "aliveMs": time.Since(r.ApprovedAt).Milliseconds()})
				}
			case <-sweepStop:
				return
			}
		}
	})

	// The child exited: the rest of the tree is served for cfg.Linger, then the gate closes.
	<-childDone
	time.Sleep(cfg.Linger.Duration)
	// exiting: those waiting for a ticket are denied (the kernel gets DENY for their execs), then
	// the client is deleted (the kernel sees no client: nothing is gated, nothing of the tree is
	// left that we answer for)
	_, items := s.q.snapshot()
	for _, it := range items {
		s.q.resolve(it.ID, ticketResult{Reason: "supervisor exiting"})
	}
	g.close()
	close(sweepStop)

	code := childExitCode(childErr)
	st := s.m.snapshot()
	s.journal("stop", map[string]any{"childExit": code, "metrics": st, "uptimeMs": time.Since(s.started).Milliseconds(), "gate": g.info()})
	switch {
	case o.quiet:
	case o.wrap != nil:
		s.wrapSummary(o.stderr)
	default:
		lat := st["latencyUs"].(pct)
		fmt.Fprintf(o.stderr, "wardend: mode=%s execs=%d denied=%d latency p50=%dus p95=%dus max=%dus exit=%d\n",
			cfg.Mode, st["execs"], st["denied"], lat.P50, lat.P95, lat.Max, code)
	}
	return code, nil
}

// childEnv: wardend's environment with HOME, USER and LOGNAME of the child user (under sudo they
// are root's) and without the SUDO_* variables that describe wardend's own launch.
func childEnv(env []string, spec string, uid int) []string {
	name, home := spec, ""
	if u, err := user.LookupId(strconv.Itoa(uid)); err == nil {
		name, home = u.Username, u.HomeDir
	}
	out := make([]string, 0, len(env)+3)
	for _, kv := range env {
		k, _, _ := strings.Cut(kv, "=")
		switch {
		case k == "HOME" || k == "USER" || k == "LOGNAME", strings.HasPrefix(k, "SUDO_"):
			continue
		}
		out = append(out, kv)
	}
	if home != "" {
		out = append(out, "HOME="+home)
	}
	return append(out, "USER="+name, "LOGNAME="+name)
}

// printStartupWarnings: configurations that start but leave roots without a working approval.
// pairsFirst: wardend wrap pairs a device before the command starts, or does not start it.
func printStartupWarnings(w io.Writer, cfg *Config, pol *policy.Config, hw *hwkey.Store, pairsFirst bool) {
	if cfg.Mode == "ticket" && len(cfg.TrustedDevices) == 0 && !pairsFirst {
		fmt.Fprintln(w, "wardend: ticket without trusted_devices: roots will be denied by TTL until a phone is paired (wardend pair start)")
	}
	for _, t := range cfg.TrustedDevices {
		if t.Pubkey == "" {
			fmt.Fprintf(w, "wardend: trusted_devices entry %s has no pubkey: its tickets are refused (unknown_device); pair the device again (wardend pair start)\n", t.ID)
		}
	}
	if cfg.Mode == "ticket" && len(pol.RequireHardware) > 0 && hw.Len() == 0 {
		fmt.Fprintln(w, "wardend: require_hardware without hardware_keys: such roots will be denied (wardend hw-register)")
	}
}
