// SPDX-License-Identifier: AGPL-3.0-or-later

package policy

import (
	"os"
	"strconv"
	"strings"

	"github.com/xarvel/WardenClaw/daemon/envelope"
)

// Class is the verdict class of an exec.
type Class string

// Verdict classes. Every launch outside an approved subtree is a card the phone signs (root,
// delegating, service); a launch inside the live subtree of an approved root passes by
// inheritance. deny_always and refuse are the only answers wardend gives on its own, and both
// are a refusal: the daemon never allows anything without a signature. The one launch that passes
// without a card of its own is the gate's rootexec client (rootexec_client): what it asks for is
// the card.
const (
	ClassDeny       Class = "deny_always"
	ClassService    Class = "service"    // harness plumbing (packs, service_allow): a card the phone may sign by rule
	ClassInherit    Class = "inherit"    // inside the live subtree of an approved root
	ClassDelegating Class = "delegating" // execution leaves the gate: a new root, ticket required
	ClassRoot       Class = "root"       // ticket required
	ClassRefuse     Class = "refuse"     // refused with reason, no card (sudo under no_new_privs)
	ClassRootExec   Class = "rootexec"   // `wardend rootexec` request: always a card, never inherited (rootexec.go)
	// ClassRootExecClient: the gate's own binary run as `wardend rootexec …` or through its sudo/docker
	// shim. Plumbing, journaled but not a card: the client executes nothing itself, it only carries a
	// request over the socket, and that request is judged by rootexec as a card of its own (or
	// refused). A card here would only double it; nothing inherits from the client.
	ClassRootExecClient Class = "rootexec_client"
)

// Verdict is the result of Classify.
type Verdict struct {
	Class   Class
	Rule    *Rule  // matched rule (deny/service/delegating)
	Hit     *Hit   // risk hint (tripwire.go): what the launch does, for the card and the journal
	RootPid int    // for inherit: pid of the approved root
	Reason  string // refuse: reason for the journal
}

// NeedsTicket reports whether a ticket is required: every launch that is neither inherited nor
// refused (root, delegating, service).
func (v Verdict) NeedsTicket() bool {
	return v.Class == ClassRoot || v.Class == ClassDelegating || v.Class == ClassService
}

// Inherits reports whether this is a service probe whose helpers inherit once it is approved.
func (v Verdict) Inherits() bool { return v.Class == ClassService && v.Rule != nil && v.Rule.Inherit }

// RuleID returns the id of what decided the verdict: the matched rule, else "category/rule" of
// the risk hint ("" if none).
func (v Verdict) RuleID() string {
	if v.Rule != nil {
		return v.Rule.ID
	}
	if v.Hit != nil {
		return v.Hit.ID()
	}
	return ""
}

// Category returns the category of the risk hint ("" if none).
func (v Verdict) Category() string {
	if v.Hit == nil {
		return ""
	}
	return v.Hit.Category
}

// ensureJSON fills ArgvJSON if the caller has not.
func (e *Exec) ensureJSON() {
	if e.ArgvJSON == "" {
		if b, err := envelope.Canonical(e.Argv); err == nil {
			e.ArgvJSON = string(b)
		}
	}
}

// Hint returns the risk hint of a launch: harness CLI verbs that change agent settings
// (agent-config from packs), custom tripwire rules, then the built-in categories (tripwire.go).
// nil when nothing is known about the launch. A hint never decides on its own: it is shown on the
// card and journaled, and it keeps a launch that matches a service rule from passing as service.
func (c *Config) Hint(e *Exec) *Hit {
	e.ensureJSON()
	if h := c.agentConfigHit(e); h != nil {
		return h
	}
	if r := first(c.Tripwire, e, true); r != nil {
		return &Hit{Category: r.Category, Rule: r.ID}
	}
	return c.tripwireCheck(e)
}

// Classify: deny_always -> service_allow and packs (only without a risk hint: `claude mcp add`
// must not pass as claude itself) -> sudo refusal (before the delegating rules: a card for a
// setuid binary under no_new_privs would be useless, so it is refused even inside an approved
// subtree) -> delegating -> inherit -> root.
// inheritedRoot is the pid of the approved root whose live subtree contains the caller (0 if none).
func (c *Config) Classify(e *Exec, inheritedRoot int) Verdict {
	e.ensureJSON()
	if r := c.MatchDeny(e); r != nil {
		return Verdict{Class: ClassDeny, Rule: r}
	}
	// the gate's own binary run as the rootexec client (or through the sudo shim) is plumbing: the
	// request it carries is a card of its own (rootexec.go), so argv0 "sudo" is no hint here and
	// the client's exec is not a card either (ClassRootExecClient)
	if c.RootExecClient(e) {
		return Verdict{Class: ClassRootExecClient, Rule: rootExecClientRule, RootPid: inheritedRoot}
	}
	hint := c.Hint(e)
	if hint == nil {
		if r := c.MatchService(e); r != nil {
			return Verdict{Class: ClassService, Rule: r, RootPid: inheritedRoot}
		}
	}
	if hint != nil && hint.Refuse {
		if why := c.refuseReason(e, hint); why != "" {
			return Verdict{Class: ClassRefuse, Hit: hint, Reason: why}
		}
		hint.Refuse = false // not setuid (e.g. a custom sudo shim): normal card
	}
	if r := c.MatchDelegating(e); r != nil {
		return Verdict{Class: ClassDelegating, Rule: r, Hit: hint, RootPid: inheritedRoot}
	}
	if inheritedRoot > 0 {
		return Verdict{Class: ClassInherit, Hit: hint, RootPid: inheritedRoot}
	}
	return Verdict{Class: ClassRoot, Hit: hint}
}

// ---------- sudo refusal ----------

// SysInfo provides the system information needed for refusing without a card.
type SysInfo interface {
	// NoNewPrivs returns the no_new_privs flag for pid (known=false if unreadable).
	NoNewPrivs(pid int) (set, known bool)
	// Setuid reports whether the file has the setuid or setgid bit.
	Setuid(path string) bool
}

// sysInfo is the SysInfo of the running host (/proc and the file system).
type sysInfo struct{}

func (sysInfo) NoNewPrivs(pid int) (bool, bool) {
	if pid <= 0 {
		return false, false
	}
	b, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/status")
	if err != nil {
		return false, false
	}
	for _, line := range strings.Split(string(b), "\n") {
		if v, ok := strings.CutPrefix(line, "NoNewPrivs:"); ok {
			return strings.TrimSpace(v) == "1", true
		}
	}
	return false, false
}

func (sysInfo) Setuid(path string) bool {
	st, err := os.Stat(path)
	return err == nil && st.Mode()&(os.ModeSetuid|os.ModeSetgid) != 0
}

// refuseReason returns the reason for refusing without a card, or "" (then a normal card is
// needed): a setuid privilege-escalation binary under no_new_privs will not escalate anyway,
// so a ticket would be useless. wardend helper sets no_new_privs for the whole tree and it
// cannot be unset, so "could not read" is treated as "is set".
func (c *Config) refuseReason(e *Exec, h *Hit) string {
	if !c.Sys.Setuid(e.Path) {
		return ""
	}
	if set, known := c.Sys.NoNewPrivs(e.Pid); known && !set {
		return ""
	}
	return h.Rule + ": setuid does not raise privileges under no_new_privs (wardend sets it for the whole agent tree), " +
		"so a ticket would not help; run privileged commands outside the agent"
}
