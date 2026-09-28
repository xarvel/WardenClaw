// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"github.com/xarvel/WardenClaw/daemon/envelope"
	"github.com/xarvel/WardenClaw/daemon/hwkey"
	"github.com/xarvel/WardenClaw/daemon/journal"
	"github.com/xarvel/WardenClaw/daemon/policy"
)

const (
	sweepInterval = 2 * time.Second  // how often the roots of exited processes are swept
	notifPollMs   = 500              // listener poll timeout while the child runs
	lingerPollMs  = 100              // listener poll timeout after the child exited (cfg.Linger)
	denyCacheTTL  = 10 * time.Second // how long a denial answers repeats of the same request
)

type supervisor struct {
	cfg          *Config
	pol          *policy.Config
	tracker      *policy.Tracker
	jr           *journal.Journal
	devices      *envelope.Devices
	hw           *hwkey.Store
	nonces       *envelope.NonceCache
	q            *queue
	m            *metrics
	key          ed25519.PrivateKey
	supervisorID string
	host         string
	supPid       int
	supMntNs     string // supervisor's /proc/self/ns/mnt ("" if not read): baseline for mount ns comparison
	lfd          int
	childPid     int
	ownFilters   int // seccomp filters of wardend itself; the tree has one more (reaper.go)
	initialDone  sync.Once
	denyMu       sync.Mutex
	denyCache    map[string]deniedReq
	started      time.Time
	stderr       io.Writer
	quiet        bool
	pair         *pairing
	http         *httpAPI // nil if http_listen is off or failed to start (httpErr)
	httpErr      string
	ntfy         *notifier
	push         *pushService // device tokens + APNs (apns not configured: storage/revocation only)
	// for tests: called after the socket is up
	onReady func(socket string)
}

// deniedReq: a recent denial of a root. Shells and execvp continue the PATH search after EPERM
// (/usr/bin/bash → /bin/bash is the same file), and without a cache the human would get a second
// request for the same thing. Key: process (tgid+starttime) + realpath + argv; lives denyCacheTTL.
type deniedReq struct {
	until  time.Time
	reason string
}

// runOpts: what is not part of the config (the process and test substitutions).
type runOpts struct {
	cmd         []string
	helperExe   string
	helperArgs  []string
	helperEnv   []string
	stdout      io.Writer
	stderr      io.Writer
	stdin       io.Reader
	quiet       bool
	onReady     func(socket string)
	noSignals   bool // tests: do not intercept process signals
	noSelfCheck bool // tests: do not check installation permissions (the test binary is group-writable)
}

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
	// Installation integrity check: a writable binary/config/key means a model under the same uid
	// can disable wardend without exec. In enforce mode fatal violations stop the startup.
	exePath := o.helperExe
	if exePath == "" {
		exePath, _ = os.Executable()
	}
	if !o.noSelfCheck {
		if err := runSelfCheck(cfg, exePath, o.stderr); err != nil {
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
		devices: envelope.NewDevices(cfg.TrustedDevices, cfg.GatewayDB), hw: hw, nonces: envelope.NewNonceCache(cfg.TsWindow.Duration),
		q: newQueue(cfg.MaxPending), m: newMetrics(), supPid: os.Getpid(), started: time.Now(), stderr: o.stderr, quiet: o.quiet,
	}
	s.tracker = policy.NewTracker(sysProc{}, s.supPid)
	s.denyCache = map[string]deniedReq{}
	if n, ok := seccompFilters(s.supPid); ok {
		s.ownFilters = n
	}
	if l, err := os.Readlink("/proc/self/ns/mnt"); err == nil {
		s.supMntNs = l
	}
	s.pair = newPairing()
	printStartupWarnings(o.stderr, cfg, pol, hw)

	rpc, err := startRPC(cfg.Socket, s)
	if err != nil {
		return 1, err
	}
	defer rpc.close()
	// The app's HTTP endpoint. If it fails to start (port busy), the supervisor still runs:
	// without a transport roots simply get no tickets (fail-closed), the reason is shown in status.
	if cfg.HTTPListen != "" {
		if h, err := startHTTP(cfg.HTTPListen, s); err != nil {
			s.httpErr = err.Error()
			fmt.Fprintf(o.stderr, "wardend: http %s: %v (the app will not be able to connect directly)\n", cfg.HTTPListen, err)
		} else {
			s.http = h
			defer h.close()
		}
	}
	if s.ntfy = newNotifier(cfg.NtfyURL, cfg.NtfyToken, s.logf); s.ntfy != nil {
		nctx, ncancel := context.WithCancel(context.Background())
		defer ncancel()
		s.goSafe("ntfy", func() { s.ntfy.run(nctx) })
	}

	s.push = newPushService(cfg, s)
	if s.push.enabled() {
		pctx, pcancel := context.WithCancel(context.Background())
		defer pcancel()
		s.goSafe("push", func() { s.push.run(pctx) })
	}

	// socketpair for SCM_RIGHTS
	sp, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return 1, err
	}
	parentSock := os.NewFile(uintptr(sp[0]), "sock-parent")
	childSock := os.NewFile(uintptr(sp[1]), "sock-child")
	defer parentSock.Close()

	exe := o.helperExe
	if exe == "" {
		if exe, err = os.Executable(); err != nil {
			return 1, err
		}
	}
	hargs := append([]string{}, o.helperArgs...)
	hargs = append(hargs, "__child", "--fd", "3")
	if cfg.ChildUser != "" {
		hargs = append(hargs, "--user", cfg.ChildUser)
	}
	hargs = append(hargs, "--")
	hargs = append(hargs, o.cmd...)
	child := exec.Command(exe, hargs...)
	child.Stdin, child.Stdout, child.Stderr = o.stdin, o.stdout, o.stderr
	child.ExtraFiles = []*os.File{childSock}
	child.Env = os.Environ()
	if o.helperEnv != nil {
		child.Env = append(child.Env, o.helperEnv...)
	}
	// Orphans of the tree are re-parented to us rather than to init (reaper.go): Yama keeps
	// their memory readable, and the sweep reaps them.
	if err := becomeSubreaper(); err != nil {
		fmt.Fprintln(o.stderr, "wardend: prctl(PR_SET_CHILD_SUBREAPER):", err)
	}
	if !o.quiet && os.Geteuid() != 0 {
		if b, err := os.ReadFile("/proc/sys/kernel/yama/ptrace_scope"); err == nil && strings.TrimSpace(string(b)) >= "2" {
			fmt.Fprintf(o.stderr, "wardend: kernel.yama.ptrace_scope=%s without CAP_SYS_PTRACE: the tree's memory is unreadable, every exec will be denied (class unreadable)\n", strings.TrimSpace(string(b)))
		}
	}
	if err := child.Start(); err != nil {
		return 1, err
	}
	childSock.Close()

	lfd, err := recvListenerFd(parentSock)
	if err != nil {
		child.Wait()
		return 1, err
	}
	s.lfd = lfd
	s.childPid = child.Process.Pid
	s.journal("start", hwStatus(map[string]any{
		"mode": cfg.Mode, "policyMode": cfg.PolicyMode, "packs": pol.PackNames(), "agentHome": pol.AgentHome(),
		"cmd": o.cmd, "childPid": child.Process.Pid, "supervisorPid": s.supPid, "supervisorId": s.supervisorID,
		"host": s.host, "journalKey": jr.PublicKey(), "trustedDevices": s.devices.IDs(), "ticketTtlMs": cfg.TicketTTL.Milliseconds(),
		"maxPending": cfg.MaxPending, "toctouRoots": cfg.ToctouRoots, "toctouService": cfg.ToctouService, "socket": cfg.Socket,
		"http": s.httpInfo(), "ntfy": cfg.NtfyURL != "",
	}, hw.Len(), len(pol.RequireHardware), nil))
	unix.Write(int(parentSock.Fd()), []byte{'A'})
	if !o.quiet {
		fmt.Fprintf(o.stderr, "wardend: mode=%s policy=%s pid=%d child=%d socket=%s journal=%s\n", cfg.Mode, cfg.PolicyMode, s.supPid, child.Process.Pid, cfg.Socket, cfg.Journal)
	}
	if o.onReady != nil {
		o.onReady(cfg.Socket)
	}

	// Signals: SIGTERM/SIGINT/SIGHUP/SIGQUIT/SIGUSR1/SIGUSR2 → the child (systemd KillMode=mixed
	// sends SIGTERM only to the main process, us; we pass it to the gateway and wait for its exit).
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
				reapOrphans(s.childPid, s.ownFilters)
			case <-sweepStop:
				return
			}
		}
	})

	loopDone := make(chan struct{})
	var wg sync.WaitGroup
	s.goSafe("notif loop", func() {
		defer close(loopDone)
		var lingerUntil time.Time
		for {
			timeout := notifPollMs
			select {
			case <-childDone:
				if lingerUntil.IsZero() {
					lingerUntil = time.Now().Add(cfg.Linger.Duration)
				}
				if time.Now().After(lingerUntil) {
					return
				}
				timeout = lingerPollMs
			default:
			}
			readable, hup, err := pollNotif(lfd, timeout)
			if err != nil {
				fmt.Fprintln(o.stderr, "wardend: poll:", err)
				return
			}
			if hup && !readable {
				return // all processes under the filter have exited (the tree is empty)
			}
			if !readable {
				continue
			}
			var n seccompNotif
			if err := notifRecv(lfd, &n); err != nil {
				if err == unix.ENOENT {
					continue
				}
				fmt.Fprintln(o.stderr, "wardend: recv:", err)
				return
			}
			wg.Add(1)
			s.goSafe("handle", func() {
				defer wg.Done()
				s.handle(&n)
			})
		}
	})
	<-loopDone
	// exiting: those waiting for a ticket are denied, then the listener closes (the rest get ENOSYS)
	_, items := s.q.snapshot()
	for _, it := range items {
		s.q.resolve(it.ID, ticketResult{Reason: "supervisor exiting"})
	}
	wg.Wait()
	<-childDone
	close(sweepStop)
	s.reapAtExit()
	unix.Close(lfd)

	code := childExitCode(childErr)
	st := s.m.snapshot()
	s.journal("stop", map[string]any{"childExit": code, "metrics": st, "uptimeMs": time.Since(s.started).Milliseconds()})
	if !o.quiet {
		lat := st["latencyUs"].(pct)
		fmt.Fprintf(o.stderr, "wardend: mode=%s execs=%d denied=%d latency p50=%dus p95=%dus max=%dus exit=%d\n",
			cfg.Mode, st["execs"], st["denied"], lat.P50, lat.P95, lat.Max, code)
	}
	return code, nil
}

// printStartupWarnings: configurations that start but leave roots without a working approval.
func printStartupWarnings(w io.Writer, cfg *Config, pol *policy.Config, hw *hwkey.Store) {
	if cfg.Mode == "ticket" && len(cfg.TrustedDevices) == 0 {
		fmt.Fprintln(w, "wardend: ticket without trusted_devices: roots will be denied by TTL until a phone is paired (wardend pair start)")
	}
	if cfg.GatewayDB != "" {
		n := 0
		for _, t := range cfg.TrustedDevices {
			if t.Pubkey == "" {
				n++
			}
		}
		fmt.Fprintf(w, "wardend: gateway_db %s: the key of devices without pubkey (%d) is taken from the OpenClaw gateway DB, which the agent uid can write; only a key with sha256(key) = deviceId is accepted. It is safer to pin the key: pair the phone again (wardend pair start) and turn off gateway_db\n", cfg.GatewayDB, n)
	}
	if cfg.Mode == "ticket" && len(pol.RequireHardware) > 0 && hw.Len() == 0 {
		fmt.Fprintln(w, "wardend: require_hardware without hardware_keys: such roots will be denied (wardend hw-register)")
	}
}

// recvListenerFd: the seccomp listener fd that the helper sends over the socketpair (SCM_RIGHTS).
func recvListenerFd(sock *os.File) (int, error) {
	buf := make([]byte, 1)
	oob := make([]byte, unix.CmsgSpace(4))
	_, oobn, _, _, err := unix.Recvmsg(int(sock.Fd()), buf, oob, 0)
	if err != nil {
		return -1, fmt.Errorf("recvmsg: %w", err)
	}
	msgs, err := unix.ParseSocketControlMessage(oob[:oobn])
	if err != nil {
		return -1, fmt.Errorf("parse scm: %w (child failed?)", err)
	}
	lfd := -1
	for _, m := range msgs {
		if fds, _ := unix.ParseUnixRights(&m); len(fds) > 0 {
			lfd = fds[0]
		}
	}
	if lfd < 0 {
		return -1, errors.New("listener fd not received")
	}
	return lfd, nil
}

// childExitCode: the child's exit status the way a shell reports it (128+N after signal N).
func childExitCode(err error) int {
	if err == nil {
		return 0
	}
	var ee *exec.ExitError
	if !errors.As(err, &ee) {
		return 1
	}
	if ws, ok := ee.Sys().(syscall.WaitStatus); ok && ws.Signaled() {
		return 128 + int(ws.Signal())
	}
	return ee.ExitCode()
}

func (s *supervisor) journal(kind string, data any) {
	if _, err := s.jr.Append(kind, data); err != nil {
		fmt.Fprintln(s.stderr, "wardend: journal:", err)
	}
}

// execRecord: a journal record for every exec.
type execRecord struct {
	Pid        int             `json:"pid"`
	Tgid       int             `json:"tgid"`
	PPid       int             `json:"ppid"`
	Syscall    string          `json:"syscall"`
	Path       string          `json:"path"`
	Exe        string          `json:"exe"`
	CallerExe  string          `json:"callerExe"`
	Argv       []string        `json:"argv"`
	Cwd        string          `json:"cwd"`
	EnvHash    string          `json:"envHash,omitempty"`
	LoaderEnv  []string        `json:"loaderEnv,omitempty"` // LD_PRELOAD, LD_AUDIT, LD_LIBRARY_PATH in the environment
	UID        int             `json:"uid"`
	Chain      []envelope.Link `json:"chain"`
	Class      string          `json:"class"`
	Rule       string          `json:"rule,omitempty"`
	Category   string          `json:"category,omitempty"` // tripwire: hit category
	Detail     string          `json:"detail,omitempty"`   // tripwire: verb from the rule's vocabulary
	RootPid    int             `json:"rootPid,omitempty"`
	Decision   string          `json:"decision"` // allow | deny
	Errno      string          `json:"errno,omitempty"`
	Reason     string          `json:"reason,omitempty"`
	Digest     string          `json:"digest,omitempty"`
	Envelope   map[string]any  `json:"envelope,omitempty"`
	Ticket     any             `json:"ticket,omitempty"`
	Hardware   *hwRecord       `json:"hardware,omitempty"`
	Provenance *provInfo       `json:"provenance,omitempty"` // self-built: provenance of the target file
	Toctou     *toctouResult   `json:"toctou,omitempty"`
	LatencyUs  int64           `json:"latencyUs"`
	WaitUs     int64           `json:"ticketWaitUs,omitempty"`
	ReadError  string          `json:"readError,omitempty"`
}

// hwRecord: the second factor in an exec record.
type hwRecord struct {
	Required  bool          `json:"required"`            // static rule (known in advance)
	Rule      string        `json:"rule,omitempty"`      // matched rule (static or score-based)
	Escalated bool          `json:"escalated,omitempty"` // inherit → new root because of the rule
	MinScore  *int          `json:"minScore,omitempty"`  // threshold of score rules for this exec
	Verified  *hwkey.Result `json:"verified,omitempty"`  // verified assertion
}

func (s *supervisor) handle(n *seccompNotif) {
	t0 := time.Now()
	ev := collect(n, s.supPid) // the target is parked in the kernel; read its memory BEFORE replying
	rec := &execRecord{Pid: ev.Pid, Tgid: ev.Tgid, PPid: ev.PPid, Syscall: ev.Syscall, Path: ev.Path, Exe: ev.Target,
		CallerExe: ev.CallerExe, Argv: ev.Argv, Cwd: ev.Cwd, EnvHash: ev.EnvHash, UID: ev.UID, Chain: ev.Chain, ReadError: ev.ReadError}

	allow, errno, tmode, pidfd := s.decide1(ev, rec)
	waitUs := rec.WaitUs
	// ID_VALID after reading/waiting: the notification is alive (the process has not died, the
	// pid is not reused).
	if err := notifIDValid(s.lfd, n.ID); err != nil {
		allow, errno = false, unix.ESRCH
		rec.Reason = strings.TrimSpace(rec.Reason + " notification no longer valid")
	}
	resp := seccompNotifResp{ID: n.ID}
	armed := false
	if allow {
		resp.Flags = unix.SECCOMP_USER_NOTIF_FLAG_CONTINUE
		if tmode == toctouStop {
			if err := armStop(ev.Tgid, ev.Pid); err == nil {
				armed = true
			}
		}
	} else {
		resp.Error = -int32(errno)
	}
	err := notifSend(s.lfd, &resp)
	lat := time.Since(t0).Microseconds() - waitUs
	if err != nil {
		rec.Reason = strings.TrimSpace(rec.Reason + " send: " + err.Error())
		if armed {
			_ = unix.Kill(ev.Tgid, unix.SIGCONT)
		}
	} else if allow && tmode != toctouOff && (armed || tmode == toctouPoll) {
		r := verifyExec(tmode, ev.Tgid, pidfd, expectFor(ev))
		rec.Toctou = &r
		if r.Outcome == "mismatch_killed" {
			s.m.toctouKills.Add(1)
			s.journal("toctou_kill", map[string]any{"pid": ev.Tgid, "expectedArgv": ev.Argv, "expectedExe": ev.Target, "got": r, "digest": rec.Digest})
			if !s.quiet {
				fmt.Fprintf(s.stderr, "wardend: TOCTOU: pid %d exec'd %q (%s), approved %q — killed\n", ev.Tgid, r.GotArgv, r.GotExe, ev.Argv)
			}
		}
	}
	if pidfd >= 0 {
		unix.Close(pidfd)
	}
	s.m.execs.Add(1)
	s.m.class(rec.Class)
	s.m.latency.add(lat)
	if allow {
		rec.Decision = "allow"
		s.m.allowed.Add(1)
	} else {
		rec.Decision = "deny"
		rec.Errno = errno.Error()
		s.m.denied.Add(1)
	}
	rec.LatencyUs = lat
	s.journal("exec", rec)
}

// newPushService: the token store always (so that revocation works), APNs if configured.
func newPushService(cfg *Config, s *supervisor) *pushService {
	p := &pushService{cfg: cfg.APNS, cards: make(chan pushCard, 64), journal: s.journal, logf: s.logf,
		trusted: s.trustedDevice}
	st, err := loadPushStore(cfg.PushTokens)
	if err != nil {
		fmt.Fprintf(s.stderr, "wardend: push_tokens: %v (starting with an empty list)\n", err)
	}
	p.store = st
	if cfg.APNS != nil {
		c, err := newAPNSClient(*cfg.APNS)
		if err != nil {
			p.apnsErr = err.Error()
			fmt.Fprintf(s.stderr, "wardend: apns disabled: %v (notifications only via ntfy/long-poll)\n", err)
		} else {
			p.apns = c
		}
	}
	return p
}

func (s *supervisor) logf(format string, a ...any) { fmt.Fprintf(s.stderr, format, a...) }
