// SPDX-License-Identifier: AGPL-3.0-or-later

package main

// rootexec: a process under the gate asks wardend to run ONE command as wardend's own user (root
// in the hardened install) after a ticket. The agent has no sudo, no docker group and no way to
// reach the root socket; this is the only road up, and every step of it is a card.
//
//	agent (under the filter)                       wardend (root)
//	  wardend rootexec -- docker restart x  ──▶  rootexec.sock (root:<agent group> 0660)
//	      JSON line + SCM_RIGHTS [0,1,2]           SO_PEERCRED: the agent uid, a descendant of the
//	                                               supervised command, under the filter
//	                                               resolve argv[0] on a fixed root PATH, pin the file
//	                                               (open, root-owned, not writable by others)
//	                                               deny_always / guard / privilege tools → refused
//	                                               policy root_exec: no rule → refused, no card
//	                                               envelope type "rootexec" (uid 0) → card → ticket
//	  ◀── {event:card}                             the phone signs the digest of THIS argv/cwd/exe
//	                                               fork: setsid, uid/gid of wardend, clean env,
//	                                               execve(/proc/self/fd/<pinned>) — the approved
//	                                               inode, whatever the path holds now
//	  ◀── {event:done, exit}                       journal: rootexec (decision) + rootexec_exit
//
// The command's stdin/stdout/stderr are the client's own descriptors passed over the socket, so
// output flows directly and nothing is buffered here. The command is not under the seccomp
// filter (it runs as root, outside the tree; its children too): the human approved exactly this
// launch, and its subtree is root's business. Everything the built-in guard cannot express (a
// compose file the agent wrote, a script the agent can edit) is the operator's policy: root_exec
// rules name what may be asked for, the card shows argv, cwd and the pinned file, and the phone
// decides.

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"github.com/xarvel/WardenClaw/daemon/envelope"
	"github.com/xarvel/WardenClaw/daemon/policy"
)

const (
	rootExecReqMax         = 64 << 10 // longest request line
	rootExecArgvMax        = 4096     // argv entries
	rootExecDefaultTimeout = 10 * time.Minute
	rootExecKillGrace      = 5 * time.Second // SIGTERM → SIGKILL
	rootExecPATH           = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
	rootExecSocketRoot     = "/run/wardend/rootexec.sock" // RuntimeDirectory=wardend in the unit
	rootExecSocketName     = "rootexec.sock"              // under state_dir when not root
)

// Exit codes of `wardend rootexec` that are not the command's own.
const (
	rootExecExitTTL     = 124 // the card expired, or the command hit the timeout
	rootExecExitRefused = 125 // no card: policy, mode, guard, socket
	rootExecExitDenied  = 126 // the phone said no
)

// rootExecRequest: the client's first message: one JSON line, and in the same sendmsg the
// SCM_RIGHTS [stdin, stdout, stderr] for the command.
type rootExecRequest struct {
	V    int      `json:"v"`
	Argv []string `json:"argv"`
	Cwd  string   `json:"cwd"`
	Term string   `json:"term,omitempty"` // TERM for the command (display programs), letters and digits only
}

// rootExecEvent: server → client, JSON lines. After the request the client may send
// {"event":"signal","signal":N} lines, forwarded to the running command's process group.
type rootExecEvent struct {
	Event     string `json:"event"` // card | refused | denied | started | done
	ID        string `json:"id,omitempty"`
	Reason    string `json:"reason,omitempty"`
	ExpiresAt int64  `json:"expiresAt,omitempty"`
	Pid       int    `json:"pid,omitempty"`
	Exit      int    `json:"exit,omitempty"`   // done: exit status the way a shell reports it (128+N after signal N)
	Signal    string `json:"signal,omitempty"` // done: the signal that ended the command, if any
	TimedOut  bool   `json:"timedOut,omitempty"`
}

type rootExecServer struct {
	s       *supervisor
	ln      *net.UnixListener
	path    string
	uid     int // the only uid that may connect (child_user, else wardend's own)
	gid     int // group of the socket
	runUID  int // ids the command runs with: wardend's own
	runGID  int
	runUser string
	timeout time.Duration
	env     []string // the command's environment (fixed; TERM is appended per request)
	wg      sync.WaitGroup
	ctx     context.Context
	stop    context.CancelFunc
}

var (
	rootExecTermRx = regexp.MustCompile(`^[A-Za-z0-9._+-]{1,64}$`)
	rootExecWordRx = regexp.MustCompile(`[^\s;|&()<>"'` + "`" + `]+`)
)

// startRootExec: the listener, if root_exec.enabled. The socket is root:<group> 0660 (the state
// directory is 0700 and unreachable for the agent, hence /run/wardend when running as root).
func startRootExec(cfg *Config, s *supervisor) (*rootExecServer, error) {
	rc := cfg.RootExec
	if rc == nil || !rc.Enabled {
		return nil, nil
	}
	r := &rootExecServer{s: s, runUID: os.Geteuid(), runGID: os.Getegid(), timeout: rc.Timeout.Duration}
	if r.timeout <= 0 {
		r.timeout = rootExecDefaultTimeout
	}
	if u, err := user.LookupId(strconv.Itoa(r.runUID)); err == nil {
		r.runUser = u.Username
	} else {
		r.runUser = strconv.Itoa(r.runUID)
	}
	r.uid, r.gid = r.runUID, r.runGID
	if cfg.ChildUser != "" {
		uid, gid, _, err := resolveChildUser(cfg.ChildUser)
		if err != nil {
			return nil, fmt.Errorf("root_exec: child_user %q: %w", cfg.ChildUser, err)
		}
		r.uid, r.gid = uid, gid
	}
	if rc.Group != "" {
		gid, err := lookupGID(rc.Group)
		if err != nil {
			return nil, fmt.Errorf("root_exec: group %q: %w", rc.Group, err)
		}
		r.gid = gid
	}
	r.path = rc.Socket
	if r.path == "" {
		if r.runUID == 0 {
			r.path = rootExecSocketRoot
		} else {
			r.path = filepath.Join(cfg.StateDir, rootExecSocketName)
		}
	}
	home := "/root"
	if r.runUID != 0 {
		if h, err := os.UserHomeDir(); err == nil {
			home = h
		}
	}
	r.env = []string{"PATH=" + rootExecPATH, "HOME=" + home, "USER=" + r.runUser, "LOGNAME=" + r.runUser, "WARDEND_ROOTEXEC=1"}
	for _, k := range []string{"LANG", "LC_ALL", "TZ"} {
		if v, ok := os.LookupEnv(k); ok {
			r.env = append(r.env, k+"="+v)
		}
	}
	ln, err := listenRootExecSocket(r.path, r.gid)
	if err != nil {
		return nil, fmt.Errorf("root_exec: %w", err)
	}
	r.ln = ln
	r.ctx, r.stop = context.WithCancel(context.Background())
	r.wg.Add(1)
	s.goSafe("rootexec accept", r.accept)
	return r, nil
}

func lookupGID(spec string) (int, error) {
	if n, err := strconv.Atoi(spec); err == nil {
		return n, nil
	}
	g, err := user.LookupGroup(spec)
	if err != nil {
		return 0, err
	}
	return strconv.Atoi(g.Gid)
}

// listenRootExecSocket: the socket 0660, owned by the wardend uid and gid (chown fails silently
// when wardend is not root and gid is not its own: then the file keeps the process group).
func listenRootExecSocket(path string, gid int) (*net.UnixListener, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, err
	}
	if _, err := os.Stat(path); err == nil {
		if c, err := net.DialTimeout("unix", path, 300*time.Millisecond); err == nil {
			c.Close()
			return nil, fmt.Errorf("%s: another wardend is listening", path)
		}
		_ = os.Remove(path)
	}
	old := unix.Umask(0o117)
	ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	unix.Umask(old)
	if err != nil {
		return nil, err
	}
	_ = os.Chown(path, os.Geteuid(), gid)
	_ = os.Chmod(path, 0o660)
	ln.SetUnlinkOnClose(true)
	return ln, nil
}

func (r *rootExecServer) close() {
	r.stop()
	r.ln.Close()
	r.wg.Wait()
}

func (s *supervisor) rootExecInfo() map[string]any {
	r := s.rootExec
	if r == nil {
		return map[string]any{"enabled": false}
	}
	return map[string]any{"enabled": true, "socket": r.path, "clientUid": r.uid, "socketGid": r.gid,
		"runAsUid": r.runUID, "runAsUser": r.runUser, "timeoutMs": r.timeout.Milliseconds(), "rules": len(s.pol.RootExec)}
}

func (r *rootExecServer) accept() {
	defer r.wg.Done()
	for {
		c, err := r.ln.AcceptUnix()
		if err != nil {
			return
		}
		r.wg.Add(1)
		r.s.goSafe("rootexec serve", func() { defer r.wg.Done(); r.serve(c) })
	}
}

// rootExecRecord: the journal record of a request (kind "rootexec"); "rootexec_exit" follows for
// a command that ran.
type rootExecRecord struct {
	ID        string          `json:"id,omitempty"`
	Digest    string          `json:"digest,omitempty"`
	Argv      []string        `json:"argv"`
	Exe       string          `json:"exe,omitempty"`
	Cwd       string          `json:"cwd"`
	RunAsUID  int             `json:"runAsUid"`
	Requester rootExecPeer    `json:"requester"`
	Rule      string          `json:"rule,omitempty"`
	Decision  string          `json:"decision"` // allow | deny
	Reason    string          `json:"reason,omitempty"`
	Envelope  map[string]any  `json:"envelope,omitempty"`
	Ticket    any             `json:"ticket,omitempty"`
	Hardware  *hwRecord       `json:"hardware,omitempty"`
	Pid       int             `json:"pid,omitempty"` // the command, when started
	WaitUs    int64           `json:"ticketWaitUs,omitempty"`
	Links     []envelope.Link `json:"chain,omitempty"`
}

type rootExecPeer struct {
	Pid int    `json:"pid"`
	UID int    `json:"uid"`
	Exe string `json:"exe,omitempty"`
}

// serve: one request per connection.
func (r *rootExecServer) serve(c *net.UnixConn) {
	defer c.Close()
	s := r.s
	pid, uid, ok := peerCred(c)
	if !ok {
		return
	}
	rec := &rootExecRecord{Decision: "deny", RunAsUID: r.runUID, Requester: rootExecPeer{Pid: pid, UID: uid, Exe: procExe(pid)}}
	send := func(ev rootExecEvent) {
		b, _ := json.Marshal(ev)
		_ = c.SetWriteDeadline(time.Now().Add(10 * time.Second))
		_, _ = c.Write(append(b, '\n'))
		_ = c.SetWriteDeadline(time.Time{})
	}
	refuse := func(reason string) {
		rec.Reason = reason
		s.m.rootexecRefused.Add(1)
		s.journal("rootexec", rec)
		send(rootExecEvent{Event: "refused", Reason: reason})
	}
	req, fds, err := readRootExecRequest(c)
	if err != nil {
		refuse("bad request: " + err.Error())
		return
	}
	defer func() {
		for _, f := range fds {
			f.Close()
		}
	}()
	rec.Argv, rec.Cwd = req.Argv, req.Cwd
	// Who is asking: only the agent uid, only from under the filter, only a descendant of the
	// supervised command (or an orphan of the tree, re-parented to wardend as its subreaper).
	if uid != r.uid {
		refuse(fmt.Sprintf("peer uid %d: only uid %d may ask", uid, r.uid))
		return
	}
	if why := s.peerUnderGate(pid); why != "" {
		refuse("requester is not under the gate: " + why)
		return
	}
	if len(req.Argv) == 0 || len(req.Argv) > rootExecArgvMax {
		refuse("argv: empty or too long")
		return
	}
	if !filepath.IsAbs(req.Cwd) {
		refuse("cwd must be absolute")
		return
	}
	if st, err := os.Stat(req.Cwd); err != nil || !st.IsDir() {
		refuse("cwd: not a directory")
		return
	}
	exeFile, real, why := r.pinExecutable(req.Argv[0], req.Cwd)
	if why != "" {
		refuse(why)
		return
	}
	defer exeFile.Close()
	rec.Exe = real
	chain := chainOf(pid, s.supPid)
	rec.Links = chain
	pe := &policy.Exec{Path: real, Argv: req.Argv, CallerExe: rec.Requester.Exe, Cwd: req.Cwd, Chain: chainExes(chain), Pid: pid}
	if d := s.pol.MatchDeny(pe); d != nil {
		refuse("deny_always: " + d.ID)
		return
	}
	if why := r.guard(req.Argv, real); why != "" {
		refuse(why)
		return
	}
	rule := s.pol.MatchRootExec(pe)
	if rule == nil {
		refuse("no root_exec rule matches: the policy does not allow asking for this command (policy root_exec)")
		return
	}
	rec.Rule = rule.ID
	// The card: the same 14 fields as an exec envelope, type rootexec, uid/gid of the launch.
	env := append([]string{}, r.env...)
	if req.Term != "" && rootExecTermRx.MatchString(req.Term) {
		env = append(env, "TERM="+req.Term)
	}
	_, start, _, _, _ := procStat(pid)
	cookie, pidfd := pidfdCookie(pid, start)
	defer closeFd(pidfd)
	ev := &envelope.Exec{Type: envelope.TypeRootExec, Argv: req.Argv, Cwd: req.Cwd, Exe: real, UID: r.runUID, GID: r.runGID,
		PpidChain: chain, Env: envelope.SelectEnv(env), EnvHash: envHash(env),
		Requester: envelope.Requester{Host: s.host, SupervisorID: s.supervisorID}, PidfdCookie: cookie,
		Ts: envelope.NowMs(), Nonce: envelope.NewNonce()}
	_, digest, err := ev.Canonical()
	if err != nil {
		refuse(err.Error() + " (non-UTF-8 argv/cwd: the envelope cannot be built)")
		return
	}
	em := ev.Map()
	rec.Digest, rec.Envelope = digest, em
	var hwRec *hwRecord
	hwRule := s.pol.HardwareStaticCat(pe, policy.ClassRootExec, string(policy.ClassRootExec))
	if hwRule != nil {
		hwRec = &hwRecord{Required: true, Rule: hwRule.ID}
	}
	if ms, ok := s.pol.HardwareMinScoreCat(pe, policy.ClassRootExec, string(policy.ClassRootExec)); ok {
		if hwRec == nil {
			hwRec = &hwRecord{}
		}
		hwRec.MinScore = &ms
	}
	rec.Hardware = hwRec
	s.m.class(string(policy.ClassRootExec))
	// The client keeps the connection: EOF before the decision withdraws the request; lines
	// after the start are signals for the command.
	sigc := make(chan int, 8)
	gone := make(chan struct{})
	s.goSafe("rootexec client", func() { readRootExecClient(c, sigc, gone) })
	id := envelope.PendingID(digest)
	rec.ID = id
	// No card: observe and deny-list run everything they do not refuse and only journal what a
	// ticket would have asked (as for any root in those modes; the agent had sudo before wardend,
	// and this is the week of watching); a rule with "ticket": false is the operator's standing
	// approval for that command. The guard and the pinned file applied all the same.
	switch {
	case s.cfg.Mode != "ticket":
		rec.Reason = s.cfg.Mode + ": would require ticket (" + rule.ID + ")"
	case !rule.NeedsTicket():
		rec.Reason = "policy: no ticket (" + rule.ID + ")"
	default:
		now := time.Now()
		it := &pendingItem{ID: id, Kind: "exec", Digest: digest, Envelope: em,
			Meta: r.cardMeta(req, rec, rule, hwRec), CreatedAt: now.UnixMilli(), ExpiresAt: now.Add(s.cfg.TicketTTL.Duration).UnixMilli(),
			pe: pe, class: policy.ClassRootExec, category: string(policy.ClassRootExec), hwRule: hwRule}
		if err := s.q.add(it); err != nil {
			s.m.queueFull.Add(1)
			refuse("pending queue full (max " + fmt.Sprint(s.cfg.MaxPending) + ")")
			return
		}
		defer s.q.remove(it.ID)
		send(rootExecEvent{Event: "card", ID: it.ID, ExpiresAt: it.ExpiresAt})
		s.relayCard(it)
		tw := time.Now()
		var res ticketResult
		select {
		case res = <-it.done:
		case <-time.After(s.cfg.TicketTTL.Duration):
			res = ticketResult{Reason: "ttl expired"}
			s.m.ticketsTTL.Add(1)
		case <-gone:
			res = ticketResult{Reason: "client disconnected before the decision"}
		case <-r.ctx.Done():
			res = ticketResult{Reason: "supervisor exiting"}
		}
		s.relayCardDone(it, res)
		rec.WaitUs = time.Since(tw).Microseconds()
		s.m.ticketWait.add(rec.WaitUs)
		if res.Body != nil {
			rec.Ticket = res.Body
		}
		if res.Hardware != nil || res.HWRule != "" {
			if rec.Hardware == nil {
				rec.Hardware = &hwRecord{}
			}
			rec.Hardware.Verified = res.Hardware
			if res.HWRule != "" {
				rec.Hardware.Rule = res.HWRule
			}
		}
		rec.Reason = res.Reason
		if !res.Allow {
			s.m.rootexecDenied.Add(1)
			if res.Body != nil {
				s.m.ticketsDenied.Add(1)
			}
			s.journal("rootexec", rec)
			send(rootExecEvent{Event: "denied", ID: it.ID, Reason: res.Reason})
			return
		}
		s.m.ticketsOK.Add(1)
	}
	// Between the card and the launch nothing is re-read: argv, cwd and env are what was signed,
	// the file is the pinned inode (execve of /proc/self/fd/3 in the child).
	cmd := exec.Command("/proc/self/fd/3")
	cmd.Args = req.Argv
	cmd.Dir = req.Cwd
	cmd.Env = env
	cmd.Stdin, cmd.Stdout, cmd.Stderr = fds[0], fds[1], fds[2]
	cmd.ExtraFiles = []*os.File{exeFile}
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if os.Geteuid() == 0 {
		// no supplementary groups: the command gets root and nothing it did not ask for
		cmd.SysProcAttr.Credential = &syscall.Credential{Uid: uint32(r.runUID), Gid: uint32(r.runGID), Groups: []uint32{}}
	}
	if err := cmd.Start(); err != nil {
		rec.Reason = "start: " + err.Error()
		s.m.rootexecRefused.Add(1)
		s.journal("rootexec", rec)
		send(rootExecEvent{Event: "refused", ID: id, Reason: rec.Reason})
		return
	}
	rec.Decision, rec.Pid = "allow", cmd.Process.Pid
	s.m.rootexecRun.Add(1)
	s.journal("rootexec", rec)
	send(rootExecEvent{Event: "started", ID: id, Pid: cmd.Process.Pid})
	t0 := time.Now()
	done := make(chan error, 1)
	s.goSafe("rootexec wait", func() { done <- cmd.Wait() })
	pgid := -cmd.Process.Pid
	kill := func(sig syscall.Signal) { _ = syscall.Kill(pgid, sig) }
	timer := time.NewTimer(r.timeout)
	defer timer.Stop()
	timedOut, clientGone := false, false
	var waitErr error
loop:
	for {
		select {
		case waitErr = <-done:
			break loop
		case <-timer.C:
			timedOut = true
			kill(syscall.SIGTERM)
			timer.Reset(rootExecKillGrace)
			s.goSafe("rootexec kill", func() { time.Sleep(rootExecKillGrace); kill(syscall.SIGKILL) })
		case n := <-sigc:
			kill(syscall.Signal(n))
		case <-gone:
			if !clientGone {
				clientGone = true
				kill(syscall.SIGTERM)
				s.goSafe("rootexec kill", func() { time.Sleep(rootExecKillGrace); kill(syscall.SIGKILL) })
			}
			gone = nil // the channel is closed: do not spin
		case <-r.ctx.Done():
			kill(syscall.SIGTERM)
			s.goSafe("rootexec kill", func() { time.Sleep(rootExecKillGrace); kill(syscall.SIGKILL) })
			waitErr = <-done
			break loop
		}
	}
	code := childExitCode(waitErr)
	sig := ""
	var ee *exec.ExitError
	if errors.As(waitErr, &ee) {
		if ws, ok := ee.Sys().(syscall.WaitStatus); ok && ws.Signaled() {
			sig = ws.Signal().String()
		}
	}
	s.journal("rootexec_exit", map[string]any{"id": id, "digest": digest, "pid": cmd.Process.Pid, "exit": code, "signal": sig,
		"timedOut": timedOut, "clientGone": clientGone, "durationMs": time.Since(t0).Milliseconds()})
	if !clientGone {
		send(rootExecEvent{Event: "done", ID: id, Exit: code, Signal: sig, TimedOut: timedOut})
	}
}

// cardMeta: what the card shows besides the signed envelope. The class and the "delegating" note
// make every client treat the card as dangerous; rootExec carries the who and the how long.
func (r *rootExecServer) cardMeta(req *rootExecRequest, rec *rootExecRecord, rule *policy.Rule, hw *hwRecord) map[string]any {
	as := r.runUser
	if r.runUID == 0 {
		as = "root"
	}
	meta := map[string]any{"class": string(policy.ClassRootExec), "rule": rule.ID, "path": req.Argv[0], "syscall": "rootexec",
		"callerExe":  rec.Requester.Exe,
		"delegating": "runs as " + as + " outside the gate: the full access of that user for this command and everything it starts",
		"rootExec": map[string]any{"runAsUid": r.runUID, "runAsUser": r.runUser, "requesterUid": rec.Requester.UID, "requesterPid": rec.Requester.Pid,
			"timeoutMs": r.timeout.Milliseconds(), "note": rule.Note}}
	if hm := r.s.hardwareMeta(hw); hm != nil {
		meta["hardware"] = hm
	}
	return meta
}

// pinExecutable resolves argv0 (a path relative to cwd, or a name on the fixed root PATH), opens
// the file and checks what a root launch of it must satisfy: a regular executable file owned by
// root (or by the wardend user), not writable by group or others, not the agent's own file, not
// under the agent's home. The open descriptor is the file the command will run: a later swap of
// the path changes nothing.
func (r *rootExecServer) pinExecutable(argv0, cwd string) (*os.File, string, string) {
	var cand []string
	if strings.Contains(argv0, "/") {
		p := argv0
		if !filepath.IsAbs(p) {
			p = filepath.Join(cwd, p)
		}
		cand = []string{filepath.Clean(p)}
	} else {
		if argv0 == "" || argv0 == "." || argv0 == ".." {
			return nil, "", "argv[0]: not a program name"
		}
		for _, d := range strings.Split(rootExecPATH, ":") {
			cand = append(cand, filepath.Join(d, argv0))
		}
	}
	for _, p := range cand {
		st, err := os.Stat(p)
		if err != nil || !st.Mode().IsRegular() || st.Mode().Perm()&0o111 == 0 {
			continue
		}
		real, err := filepath.EvalSymlinks(p)
		if err != nil {
			return nil, "", "argv[0]: " + err.Error()
		}
		f, err := os.OpenFile(real, os.O_RDONLY|unix.O_CLOEXEC, 0)
		if err != nil {
			return nil, "", "argv[0]: " + err.Error()
		}
		var fst unix.Stat_t
		if err := unix.Fstat(int(f.Fd()), &fst); err != nil || fst.Mode&unix.S_IFMT != unix.S_IFREG {
			f.Close()
			return nil, "", "argv[0]: not a regular file"
		}
		if fst.Mode&0o022 != 0 {
			f.Close()
			return nil, "", fmt.Sprintf("%s is writable by group or others (mode %#o): not a root launch candidate", real, fst.Mode&0o777)
		}
		if int(fst.Uid) != 0 && int(fst.Uid) != r.runUID {
			f.Close()
			return nil, "", fmt.Sprintf("%s is owned by uid %d, not by root: not a root launch candidate", real, fst.Uid)
		}
		// With a separate agent user its files and its home are off limits (a single-user run has
		// no such boundary: wardend itself lives in that home).
		if r.uid != r.runUID {
			if int(fst.Uid) == r.uid {
				f.Close()
				return nil, "", real + " is the agent's own file"
			}
			if home := r.s.pol.AgentHome(); home != "" && home != "/" && (real == home || strings.HasPrefix(real, home+"/")) {
				f.Close()
				return nil, "", real + " is under the agent's home"
			}
		}
		return f, real, ""
	}
	return nil, "", "argv[0]: " + argv0 + ": not found on " + rootExecPATH + " (or not executable)"
}

// Built-in refusals that no policy can lift: the gate itself, privilege and namespace tools,
// account and sudoers changes, and any argument that names wardend's files, unit, sysctl or
// polkit rule. Not a proof of safety (docker can mount /etc), a stop for the obvious way to
// switch the guard off with a distracted human.
var (
	rootExecGuardTools = map[string]bool{"usermod": true, "useradd": true, "userdel": true, "adduser": true, "deluser": true,
		"gpasswd": true, "groupmod": true, "groupadd": true, "groupdel": true, "passwd": true, "chpasswd": true,
		"visudo": true, "vipw": true, "vigr": true, "loginctl": true, "chsh": true}
	rootExecGuardText = []string{"/etc/wardend", "/var/lib/wardend", "/run/wardend", "/usr/local/bin/wardend", "/usr/local/bin/wardenctl",
		"/usr/local/share/wardend", "wardend.service", "/etc/sudoers", "/etc/polkit-1", "60-wardend", "ptrace_scope", "/etc/passwd", "/etc/shadow",
		"/etc/group", "/etc/gshadow"}
)

func (r *rootExecServer) guard(argv []string, real string) string {
	base := filepath.Base(real)
	a0 := filepath.Base(argv[0])
	if r.s.pol.GuardExe(real) || base == "wardend" || base == "wardenctl" {
		return "the gate itself is never run through rootexec"
	}
	if policy.PrivilegeTool(base) || policy.PrivilegeTool(a0) {
		return base + ": privilege and namespace tools are refused (a root card for them is an unbounded root)"
	}
	if rootExecGuardTools[base] || rootExecGuardTools[a0] {
		return base + ": accounts, groups and sudoers are not changed through rootexec"
	}
	text := strings.Join(argv, " ")
	// the same tools as words anywhere in the arguments (sh -c "gpasswd …", env X=1 sudo …)
	for _, w := range rootExecWordRx.FindAllString(text, -1) {
		if b := filepath.Base(w); rootExecGuardTools[b] || policy.PrivilegeTool(b) {
			return "argument names " + b + ": privilege, account and sudoers tools are off limits"
		}
	}
	for _, g := range rootExecGuardText {
		if strings.Contains(text, g) {
			return "argument names " + g + ": wardend's own files, unit and guards are off limits"
		}
	}
	if (base == "systemctl" || a0 == "systemctl") && strings.Contains(text, "wardend") {
		return "systemctl on wardend is off limits"
	}
	return ""
}

// peerUnderGate: "" if pid is under this wardend's filter and descends from the supervised
// command (or is an orphan of the tree re-parented to wardend), else why not. Every read error
// counts as "not under the gate".
func (s *supervisor) peerUnderGate(pid int) string {
	own, ok1 := seccompFilters(os.Getpid())
	peer, ok2 := seccompFilters(pid)
	if !ok1 || !ok2 {
		return "cannot read the seccomp filter count"
	}
	if peer <= own {
		return "not under the wardend filter"
	}
	if s.childPid <= 0 {
		return "the supervised command has not started"
	}
	cur := pid
	for i := 0; i < maxAncestors && cur > 1; i++ {
		if cur == s.childPid || cur == s.supPid {
			return ""
		}
		pp, ok := ppidOf(cur)
		if !ok {
			return "cannot read the parent chain"
		}
		cur = pp
	}
	return "not a descendant of the supervised command"
}

func peerCred(c *net.UnixConn) (pid, uid int, ok bool) {
	raw, err := c.SyscallConn()
	if err != nil {
		return 0, 0, false
	}
	var cred *unix.Ucred
	_ = raw.Control(func(fd uintptr) {
		cred, _ = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
	})
	if cred == nil {
		return 0, 0, false
	}
	return int(cred.Pid), int(cred.Uid), true
}

// readRootExecRequest reads the first message: the JSON line and the three descriptors that
// travel with its first bytes.
func readRootExecRequest(c *net.UnixConn) (*rootExecRequest, []*os.File, error) {
	buf := make([]byte, rootExecReqMax)
	oob := make([]byte, unix.CmsgSpace(3*4))
	_ = c.SetReadDeadline(time.Now().Add(10 * time.Second))
	n, oobn, _, _, err := c.ReadMsgUnix(buf, oob)
	_ = c.SetReadDeadline(time.Time{})
	if err != nil {
		return nil, nil, err
	}
	var fds []int
	if oobn > 0 {
		msgs, err := unix.ParseSocketControlMessage(oob[:oobn])
		if err != nil {
			return nil, nil, fmt.Errorf("control message: %w", err)
		}
		for _, m := range msgs {
			if got, err := unix.ParseUnixRights(&m); err == nil {
				fds = append(fds, got...)
			}
		}
	}
	files := make([]*os.File, 0, len(fds))
	for i, fd := range fds {
		unix.CloseOnExec(fd)
		files = append(files, os.NewFile(uintptr(fd), "rootexec-fd-"+strconv.Itoa(i)))
	}
	closeAll := func() {
		for _, f := range files {
			f.Close()
		}
	}
	if len(files) != 3 {
		closeAll()
		return nil, nil, fmt.Errorf("expected 3 descriptors (stdin, stdout, stderr), got %d", len(files))
	}
	line := buf[:n]
	for !strings.Contains(string(line), "\n") {
		if len(line) >= rootExecReqMax {
			closeAll()
			return nil, nil, errors.New("request line too long")
		}
		_ = c.SetReadDeadline(time.Now().Add(10 * time.Second))
		m, err := c.Read(buf[len(line):])
		_ = c.SetReadDeadline(time.Time{})
		if err != nil {
			closeAll()
			return nil, nil, err
		}
		line = buf[:len(line)+m]
	}
	first, _, _ := strings.Cut(string(line), "\n")
	var req rootExecRequest
	if err := json.Unmarshal([]byte(first), &req); err != nil {
		closeAll()
		return nil, nil, fmt.Errorf("json: %w", err)
	}
	if req.V != 1 {
		closeAll()
		return nil, nil, fmt.Errorf("request v%d: this wardend speaks v1", req.V)
	}
	return &req, files, nil
}

// readRootExecClient: lines after the request are {"event":"signal","signal":N}; EOF closes gone.
func readRootExecClient(c *net.UnixConn, sigc chan<- int, gone chan<- struct{}) {
	defer close(gone)
	sc := bufio.NewScanner(c)
	sc.Buffer(make([]byte, 4096), 64<<10)
	for sc.Scan() {
		var m struct {
			Event  string `json:"event"`
			Signal int    `json:"signal"`
		}
		if json.Unmarshal(sc.Bytes(), &m) != nil || m.Event != "signal" {
			continue
		}
		switch syscall.Signal(m.Signal) {
		case syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP, syscall.SIGQUIT, syscall.SIGUSR1, syscall.SIGUSR2, syscall.SIGWINCH:
			select {
			case sigc <- m.Signal:
			default:
			}
		}
	}
}
