// SPDX-License-Identifier: AGPL-3.0-or-later

package policy

import (
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/xarvel/WardenClaw/daemon/envelope"
)

// Class is the verdict class of an exec.
type Class string

// Verdict classes of root mode, then of tripwire mode.
const (
	ClassDeny       Class = "deny_always"
	ClassService    Class = "service"
	ClassInherit    Class = "inherit"
	ClassDelegating Class = "delegating" // new root, ticket required
	ClassRoot       Class = "root"       // ticket required
	// tripwire mode
	ClassTripwire Class = "tripwire" // rule triggered: ticket required
	ClassImplied  Class = "implied"  // trigger under an approved exec of the same family
	ClassRefuse   Class = "refuse"   // refused with reason, no card (sudo under no_new_privs)
	ClassRootExec Class = "rootexec" // `wardend rootexec` request: always a card, never inherited (rootexec.go)
	ClassLogged   Class = "logged"   // no rule triggered: allowed and logged
)

// Classification modes (config key policy_mode).
const (
	ModeTripwire = "tripwire"
	ModeRoot     = "root"
)

// ImpliedTTL is how long after a tripwire exec is approved its children of the same family
// pass without a card (and no longer than the chain to the root is alive).
const ImpliedTTL = 10 * time.Minute

// Verdict is the result of Classify or ClassifyTripwire.
type Verdict struct {
	Class   Class
	Rule    *Rule  // matched rule (deny/service/delegating, custom tripwire rule)
	Hit     *Hit   // tripwire trigger (tripwire, implied, refuse)
	RootPid int    // for inherit/implied: pid of the approved root
	Reason  string // refuse: reason for the journal
}

// NeedsTicket reports whether a ticket is required: root (incl. delegating) or tripwire trigger.
func (v Verdict) NeedsTicket() bool {
	return v.Class == ClassRoot || v.Class == ClassDelegating || v.Class == ClassTripwire
}

// Inherits reports whether this is a service probe whose helpers inherit (root mode).
func (v Verdict) Inherits() bool { return v.Class == ClassService && v.Rule != nil && v.Rule.Inherit }

// RuleID returns the id of what decided the verdict: "category/rule" for a tripwire hit,
// otherwise the rule id ("" if none).
func (v Verdict) RuleID() string {
	if v.Hit != nil {
		return v.Hit.ID()
	}
	if v.Rule == nil {
		return ""
	}
	return v.Rule.ID
}

// Category returns the tripwire category ("" if none).
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

// Classify implements root mode: deny_always -> service_allow -> delegating -> inherit -> root.
// inheritedRoot is the pid of the approved root whose live subtree contains the caller (0 if none).
func (c *Config) Classify(e *Exec, inheritedRoot int) Verdict {
	e.ensureJSON()
	if r := c.MatchDeny(e); r != nil {
		return Verdict{Class: ClassDeny, Rule: r}
	}
	if r := c.MatchService(e); r != nil {
		return Verdict{Class: ClassService, Rule: r, RootPid: inheritedRoot}
	}
	if c.RootExecClient(e) {
		return Verdict{Class: ClassService, Rule: rootExecClientRule, RootPid: inheritedRoot}
	}
	if r := c.MatchDelegating(e); r != nil {
		return Verdict{Class: ClassDelegating, Rule: r, RootPid: inheritedRoot}
	}
	if inheritedRoot > 0 {
		return Verdict{Class: ClassInherit, RootPid: inheritedRoot}
	}
	return Verdict{Class: ClassRoot}
}

// ClassifyTripwire implements tripwire mode: deny_always -> harness CLI verbs that change agent
// settings (agent-config from packs: checked before service rules, otherwise `claude mcp add`
// would pass as claude itself) -> service (packs, service_allow) -> custom tripwire rules ->
// built-in categories -> sudo refusal -> implied -> tripwire; no match: logged.
// parent is the approved tripwire root whose live chain contains the caller (nil if none);
// now is the decision time (replay passes the entry timestamp).
func (c *Config) ClassifyTripwire(e *Exec, parent *Root, now time.Time) Verdict {
	e.ensureJSON()
	if r := c.MatchDeny(e); r != nil {
		return Verdict{Class: ClassDeny, Rule: r}
	}
	hit := c.agentConfigHit(e)
	var rule *Rule
	if hit == nil {
		if r := c.MatchService(e); r != nil {
			return Verdict{Class: ClassService, Rule: r}
		}
		if c.RootExecClient(e) {
			return Verdict{Class: ClassService, Rule: rootExecClientRule}
		}
		if r := first(c.Tripwire, e, true); r != nil {
			rule = r
			hit = &Hit{Category: r.Category, Rule: r.ID, Family: "rule:" + r.ID}
		} else {
			hit = c.tripwireCheck(e)
		}
	}
	if hit == nil {
		return Verdict{Class: ClassLogged}
	}
	if hit.Refuse {
		if why := c.refuseReason(e, hit); why != "" {
			return Verdict{Class: ClassRefuse, Hit: hit, Reason: why}
		}
		hit.Refuse = false // not setuid (e.g. a custom sudo shim): normal card
	}
	if parent != nil && ImpliedBy(hit.Family, parent.Family) && now.Sub(parent.ApprovedAt) <= ImpliedTTL {
		return Verdict{Class: ClassImplied, Hit: hit, Rule: rule, RootPid: parent.Pid}
	}
	return Verdict{Class: ClassTripwire, Hit: hit, Rule: rule}
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
