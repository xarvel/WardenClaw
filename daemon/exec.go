// SPDX-License-Identifier: AGPL-3.0-or-later

package main

// The exec decision: classify the call, ask for a ticket when the policy says so, and remember a
// fresh denial so a shell searching PATH does not ask a second time.

import (
	"errors"
	"fmt"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"github.com/xarvel/WardenClaw/daemon/envelope"
	"github.com/xarvel/WardenClaw/daemon/policy"
)

// decide1: classification and (for roots) waiting for a ticket. Returns the decision, errno,
// the post-check mode and the caller's pidfd (for SIGKILL on TOCTOU; -1 if none).
func (s *supervisor) decide1(ev *execEvent, rec *execRecord) (bool, unix.Errno, toctouMode, int) {
	if ev.Target == "" {
		if ev.Path == "" && ev.ReadError != "" {
			// The caller's memory could not be read, so even the path is unknown: Yama
			// ptrace_scope=2 without CAP_SYS_PTRACE, or a caller that is not our descendant.
			// Nothing to classify: fail closed and say why in the journal.
			rec.Class = "unreadable"
			rec.Reason = ev.ReadError
			if s.cfg.Mode == "observe" {
				return true, 0, toctouOff, -1
			}
			return false, unix.EPERM, toctouOff, -1
		}
		// No file: the kernel would return ENOENT anyway (execvp's PATH search tries directories
		// one by one). We answer ourselves, without a ticket and without CONTINUE (otherwise the
		// file could appear between the check and the exec).
		rec.Class = "missing"
		errno := unix.ENOENT
		var en syscall.Errno
		if errors.As(ev.TargetErr, &en) {
			errno = unix.Errno(en)
		}
		rec.Reason = fmt.Sprint(ev.TargetErr)
		if s.cfg.Mode == "observe" {
			return true, 0, toctouOff, -1
		}
		return false, errno, toctouOff, -1
	}
	// The helper's first exec is the command the operator started (the gateway). It passes,
	// but does NOT become an approved root: otherwise the whole tree would inherit the permission.
	if ev.Tgid == s.childPid {
		first := false
		s.initialDone.Do(func() { first = true })
		if first {
			rec.Class = "supervised_cmd"
			return true, 0, toctouOff, -1
		}
	}
	pe := &policy.Exec{Path: ev.Target, Argv: ev.Argv, CallerExe: ev.CallerExe, Cwd: ev.Cwd, Chain: chainExes(ev.Chain), Pid: ev.Tgid}
	v := classifyExec(s.cfg.PolicyMode, s.pol, s.tracker, pe, ev.Tgid, time.Now())
	// Path resolution bypass through a foreign mount namespace: if the caller quietly ended up in
	// another mount ns (via the unshare(2) syscall, without the delegating unshare/nsenter binary),
	// wardend resolves the path in its own ns and sees a different file than the kernel will run.
	// This must not pass as logged/implied/inherit/service: only a card (deny/refuse block anyway).
	if s.foreignMountNs(ev) && !v.NeedsTicket() && v.Class != policy.ClassDeny && v.Class != policy.ClassRefuse {
		v = policy.Verdict{Class: policy.ClassTripwire, Hit: &policy.Hit{Category: "mount-ns", Rule: "foreign", Family: "mount-ns"}, RootPid: v.RootPid}
	}
	// Self-built executable: the target belongs to the agent or is writable by it, so the name
	// does not prove what it is. In tripwire mode a launch not recognized by the rules (logged)
	// and not allowed by a pair (implied) becomes a card with the file's provenance. Harness
	// service launches (service, from packages) are trusted and not escalated; the command's
	// first exec (supervised_cmd) does not get here: it is allowed above.
	var prov *provInfo
	if s.cfg.PolicyMode == policy.ModeTripwire && agentWritable(ev) &&
		(v.Class == policy.ClassLogged || v.Class == policy.ClassImplied) {
		prov = provenance(ev.Target)
		v = policy.Verdict{Class: policy.ClassTripwire, Hit: &policy.Hit{Category: "self-built", Rule: provKind(prov), Family: "self-built"}, RootPid: v.RootPid}
	}
	// Loader variables: with LD_PRELOAD, LD_AUDIT or LD_LIBRARY_PATH the program runs code from a
	// foreign library, however harmless argv looks. A launch outside an approved root that would
	// pass without a card (logged, service) becomes a card of its own tripwire category
	// "loader-env"; cards (root, delegating, tripwire) keep their class and category, and the
	// hardware-key rule is also looked up by "loader-env". Inside an approved root (inherit,
	// implied) it is not gated. The app does not approve such cards on its own: it sees the
	// variables in the envelope's signed env.
	loader := envelope.LoaderVars(ev.Env)
	rec.LoaderEnv = loader
	if len(loader) > 0 && (v.Class == policy.ClassLogged || v.Class == policy.ClassService) && s.tracker.InheritedRoot(ev.Tgid) == 0 {
		v = policy.Verdict{Class: policy.ClassTripwire, Hit: &policy.Hit{Category: policy.CatLoaderEnv, Rule: strings.ToLower(loader[0]), Family: policy.CatLoaderEnv}}
	}
	cat := v.Category()
	var hwRule *policy.HWRule
	escalated := false
	switch v.Class {
	case policy.ClassInherit, policy.ClassImplied:
		// a descendant of a root approved WITHOUT a key does not inherit permission for what
		// requires a key
		if r := s.pol.HardwareStaticCat(pe, v.Class, cat); r != nil && !s.tracker.RootHardware(v.RootPid) {
			hwRule, escalated = r, true
			if v.Class == policy.ClassImplied {
				v = policy.Verdict{Class: policy.ClassTripwire, Hit: v.Hit, Rule: v.Rule, RootPid: v.RootPid}
			} else {
				v = policy.Verdict{Class: policy.ClassRoot, RootPid: v.RootPid}
			}
		}
	case policy.ClassRoot, policy.ClassDelegating, policy.ClassTripwire:
		hwRule = s.pol.HardwareStaticCat(pe, v.Class, cat)
		if hwRule == nil && len(loader) > 0 && cat != policy.CatLoaderEnv {
			hwRule = s.pol.HardwareStaticCat(pe, policy.ClassTripwire, policy.CatLoaderEnv)
		}
	}
	if hwRule != nil {
		rec.Hardware = &hwRecord{Required: true, Rule: hwRule.ID, Escalated: escalated}
	}
	if ms, ok := s.pol.HardwareMinScoreCat(pe, v.Class, cat); ok && v.NeedsTicket() {
		if rec.Hardware == nil {
			rec.Hardware = &hwRecord{}
		}
		rec.Hardware.MinScore = &ms
	}
	rec.Class, rec.Rule, rec.RootPid = string(v.Class), v.RuleID(), v.RootPid
	if v.Hit != nil {
		rec.Category, rec.Detail = v.Hit.Category, v.Hit.Detail
	}
	rec.Provenance = prov
	if !ev.ArgvOK && v.Class != policy.ClassDeny {
		// argv was not read completely: a decision must not be based on a fragment
		rec.Reason = "argv unreadable"
		if s.cfg.Mode == "observe" {
			return true, 0, toctouOff, -1
		}
		return false, unix.EPERM, toctouOff, -1
	}
	switch s.cfg.Mode {
	case "observe":
		// Everything is allowed; the journal shows what would have happened. Roots and hits are
		// "approved" automatically so that observation shows the real number of tickets (children
		// of such roots are inherit, in tripwire implied).
		switch {
		case v.NeedsTicket():
			rec.Reason = "observe: would require ticket"
			if hwRule != nil {
				rec.Reason += " + hardware key (" + hwRule.ID + ")"
			}
			s.tracker.AddRoot(&policy.Root{Pid: ev.Tgid, Start: ev.Start, ApprovedAt: time.Now(), Digest: "observe", Hardware: hwRule != nil, Family: hitFamily(v)})
		case v.Class == policy.ClassDeny:
			rec.Reason = "observe: would deny (" + v.RuleID() + ")"
		case v.Class == policy.ClassRefuse:
			rec.Reason = "observe: would refuse: " + v.Reason
		case v.Inherits() && s.cfg.PolicyMode == policy.ModeRoot:
			s.tracker.AddRoot(&policy.Root{Pid: ev.Tgid, Start: ev.Start, ApprovedAt: time.Now(), Digest: "service"})
		}
		return true, 0, toctouOff, -1
	case "deny-list":
		if v.Class == policy.ClassDeny {
			return false, unix.EPERM, toctouOff, -1
		}
		return true, 0, toctouOff, -1
	}
	// ticket
	switch v.Class {
	case policy.ClassDeny:
		rec.Reason = "deny_always: " + v.RuleID()
		return false, unix.EPERM, toctouOff, -1
	case policy.ClassRefuse:
		// a card would be useless: setuid under no_new_privs will not raise privileges
		rec.Reason = "refused without a card: " + v.Reason
		return false, unix.EPERM, toctouOff, -1
	case policy.ClassService:
		if v.Inherits() && s.cfg.PolicyMode == policy.ModeRoot {
			// a harness probe with helpers: its subtree inherits (package, "inherit")
			s.tracker.AddRoot(&policy.Root{Pid: ev.Tgid, Start: ev.Start, ApprovedAt: time.Now(), Digest: "service"})
		}
		return true, 0, toctouMode(s.cfg.ToctouService), s.pidfdIf(ev, toctouMode(s.cfg.ToctouService))
	case policy.ClassInherit, policy.ClassImplied, policy.ClassLogged:
		return true, 0, toctouOff, -1
	}
	// root, delegating or tripwire hit → ticket
	dkey := fmt.Sprintf("%d:%d:%s:%s", ev.Tgid, ev.Start, ev.Target, pe.ArgvJSON)
	if reason, ok := s.recentDenial(dkey); ok {
		rec.Reason = "repeat of denied request (PATH retry): " + reason
		return false, unix.EPERM, toctouOff, -1
	}
	cookie, pidfd := pidfdCookie(ev.Tgid, ev.Start)
	env := &envelope.Exec{Argv: ev.Argv, Cwd: ev.Cwd, Exe: ev.Target, UID: ev.UID, GID: ev.GID, PpidChain: ev.Chain,
		Env: ev.Env, EnvHash: ev.EnvHash, Requester: envelope.Requester{Host: s.host, SupervisorID: s.supervisorID}, PidfdCookie: cookie,
		Ts: envelope.NowMs(), Nonce: envelope.NewNonce()}
	_, digest, err := env.Canonical()
	if err != nil {
		rec.Reason = err.Error() + " (non-UTF-8 argv/cwd/exe/env: the envelope cannot be built)"
		closeFd(pidfd)
		return false, unix.EPERM, toctouOff, -1
	}
	em := env.Map()
	rec.Digest, rec.Envelope = digest, em
	now := time.Now()
	it := &pendingItem{ID: envelope.PendingID(digest), Kind: "exec", Digest: digest, Envelope: em, Meta: s.cardMeta(ev, v, prov, loader, rec.Hardware),
		CreatedAt: now.UnixMilli(), ExpiresAt: now.Add(s.cfg.TicketTTL.Duration).UnixMilli(), pe: pe, class: v.Class, category: cat, hwRule: hwRule}
	if err := s.q.add(it); err != nil {
		s.m.queueFull.Add(1)
		rec.Reason = "pending queue full (max " + fmt.Sprint(s.cfg.MaxPending) + ")"
		s.rememberDenial(dkey, rec.Reason)
		closeFd(pidfd)
		return false, unix.EAGAIN, toctouOff, -1
	}
	defer s.q.remove(it.ID)
	s.ntfy.poke()
	s.push.notify(it.ID, time.UnixMilli(it.ExpiresAt))
	tw := time.Now()
	var res ticketResult
	select {
	case res = <-it.done:
	case <-time.After(s.cfg.TicketTTL.Duration):
		res = ticketResult{Reason: "ttl expired"}
		s.m.ticketsTTL.Add(1)
	}
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
		s.rememberDenial(dkey, res.Reason)
		if res.Body != nil {
			s.m.ticketsDenied.Add(1)
		}
		closeFd(pidfd)
		return false, unix.EPERM, toctouOff, -1
	}
	s.m.ticketsOK.Add(1)
	// the root is registered BEFORE CONTINUE: the first children will already see it (in tripwire
	// children inherit only hits of the same family, policy.ImpliedBy)
	s.tracker.AddRoot(&policy.Root{Pid: ev.Tgid, Start: ev.Start, Digest: digest, DeviceID: res.Body.DeviceID, Hardware: res.Hardware != nil,
		ApprovedAt: time.Now(), Family: hitFamily(v)})
	return true, 0, toctouMode(s.cfg.ToctouRoots), pidfd
}

// recentDenial: the reason of a denial of the same request (deniedReq key) that is still fresh.
func (s *supervisor) recentDenial(key string) (string, bool) {
	s.denyMu.Lock()
	defer s.denyMu.Unlock()
	d, ok := s.denyCache[key]
	if !ok || !time.Now().Before(d.until) {
		return "", false
	}
	return d.reason, true
}

// rememberDenial caches a denial for denyCacheTTL and drops the expired ones.
func (s *supervisor) rememberDenial(key, reason string) {
	s.denyMu.Lock()
	defer s.denyMu.Unlock()
	now := time.Now()
	for k, d := range s.denyCache {
		if now.After(d.until) {
			delete(s.denyCache, k)
		}
	}
	s.denyCache[key] = deniedReq{until: now.Add(denyCacheTTL), reason: reason}
}

// cardMeta: what the card shows besides the signed envelope (class, rule, hit, provenance,
// loader variables, the second factor).
func (s *supervisor) cardMeta(ev *execEvent, v policy.Verdict, prov *provInfo, loader []string, hw *hwRecord) map[string]any {
	meta := map[string]any{"class": string(v.Class), "rule": v.RuleID(), "path": ev.Path, "syscall": ev.Syscall, "callerExe": ev.CallerExe}
	if v.Class == policy.ClassDelegating && v.Rule != nil {
		meta["delegating"] = v.Rule.Note
	}
	if v.Hit != nil {
		meta["category"] = v.Hit.Category
		if v.Hit.Detail != "" {
			meta["detail"] = v.Hit.Detail
		}
		if note := policy.HitNote(v.Hit); note != "" {
			meta["delegating"] = note // the card warns as it does for a delegating launch
		}
	}
	if prov != nil {
		meta["provenance"] = prov // file provenance for the judge and the human
	}
	if v.RootPid > 0 {
		meta["insideRoot"] = v.RootPid
	}
	if len(loader) > 0 {
		meta["loaderEnv"] = loader // a hint; the app looks at the envelope's signed env
	}
	if hm := s.hardwareMeta(hw); hm != nil {
		meta["hardware"] = hm
	}
	return meta
}

// classifyExec: classification of an exec in the policy mode (shared by the supervisor and
// replay). The tracker is walked for every exec: this way the chain to an approved root survives
// the death of intermediate processes.
func classifyExec(mode string, pol *policy.Config, tr *policy.Tracker, pe *policy.Exec, tgid int, now time.Time) policy.Verdict {
	inh := tr.InheritedRoot(tgid)
	if mode == policy.ModeRoot {
		return pol.Classify(pe, inh)
	}
	var parent *policy.Root
	if inh > 0 {
		parent = tr.Root(inh)
	}
	return pol.ClassifyTripwire(pe, parent, now)
}

// hitFamily: the family of a tripwire hit for inheritance pairs ("" for a root in root mode).
func hitFamily(v policy.Verdict) string {
	if v.Hit == nil {
		return ""
	}
	return v.Hit.Family
}

// chainExes: exe of the caller and its ancestors ([0] is the caller).
func chainExes(ch []envelope.Link) []string {
	out := make([]string, len(ch))
	for i, l := range ch {
		out[i] = l.Exe
	}
	return out
}

// foreignMountNs: the caller is in a mount namespace different from the supervisor's. Empty on
// either side (could not read /proc/<pid>/ns/mnt) counts as "not foreign", so that a transient
// read error does not block legitimate work; a confirmed mismatch means escalation.
func (s *supervisor) foreignMountNs(ev *execEvent) bool {
	return s.supMntNs != "" && ev.MntNs != "" && ev.MntNs != s.supMntNs
}

func (s *supervisor) pidfdIf(ev *execEvent, m toctouMode) int {
	if m == toctouOff {
		return -1
	}
	fd, err := unix.PidfdOpen(ev.Tgid, 0)
	if err != nil {
		return -1
	}
	return fd
}

func closeFd(fd int) {
	if fd >= 0 {
		unix.Close(fd)
	}
}
