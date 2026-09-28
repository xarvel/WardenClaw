// SPDX-License-Identifier: AGPL-3.0-or-later

// Package policy holds the wardend exec policy. Two classification modes (policy_mode):
//
// tripwire (default): every exec is checked against rules (tripwire.go); no subtree trust:
//
//	(a) deny_always   - EPERM unconditionally;
//	(b) service       - harness service execs (harness packs, service_allow): pass;
//	(c) tripwire      - user "tripwire" rules and built-in categories (remote execution,
//	                    delegation, package install, publish, destruction, protected paths
//	                    and secrets, agent settings, adb ...) -> ticket required;
//	                    sudo/su/doas/pkexec under no_new_privs - refused with reason, no card;
//	(d) implied       - trigger inside an approved tripwire exec of the same family
//	                    (ssh under scp, eas under npx eas-cli) within ImpliedTTL -> pass;
//	(e) logged        - everything else passes and is written to the journal.
//
// root ("approved root", previous behavior):
//
//	(a) deny_always   - regex on argv/exe -> EPERM unconditionally, even inside an approved tree;
//	(b) service_allow - harness service execs (packs and service_allow) by exe+argv pattern:
//	                    pass without a ticket, logged, do NOT inherit (their children are checked
//	                    independently), except probes with "inherit";
//	(c) inherit       - caller is a descendant of an approved root, the subtree is still alive
//	                    (Tracker) and the exec is not delegating -> pass;
//	(d) delegating    - setsid/systemd-run/docker/tmux/...: exec leaves supervision
//	                    (or detaches from the tree) -> always a new root, ticket required;
//	(e) everything else - root: ticket required (device signature over the envelope).
package policy

import (
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// maxMinScore is the upper bound of require_hardware min_score (risk scores are 0..100).
const maxMinScore = 100

// Rule matches an exec when all set fields match (AND). Regexps use Go RE2 syntax, no anchors
// by default (add ^...$ yourself). ${VAR} are installation path variables (vars.go).
type Rule struct {
	ID       string   `json:"id"`
	Note     string   `json:"note,omitempty"`
	Path     string   `json:"path,omitempty"`      // realpath of the executed file
	Argv0    string   `json:"argv0,omitempty"`     // basename(argv[0]); for deny: also basename(path)
	Caller   string   `json:"caller,omitempty"`    // exe of the calling process (before exec)
	ArgvText string   `json:"argv_text,omitempty"` // argv joined with spaces (handy for deny; ambiguous for allow)
	ArgvJSON string   `json:"argv_json,omitempty"` // canonical JSON of argv (unambiguous; for allow)
	ArgvNone string   `json:"argv_none,omitempty"` // none of argv[1:] must match
	Argv     []string `json:"argv,omitempty"`      // element-by-element, exact length; each regexp anchored ^(?:...)$
	// Process chain (pack selection by harness): Under is the exe of the caller or one ancestor
	// (up to the wardend command); ChainAll is the exe of each of them; ChainMax limits chain length.
	Under    string `json:"under,omitempty"`
	ChainAll string `json:"chain_all,omitempty"`
	ChainMax int    `json:"chain_max,omitempty"`
	// Inherit (service, root mode): the probe's own helpers inherit (the probe registers as
	// a root without a ticket).
	Inherit bool `json:"inherit,omitempty"`
	// Category (tripwire mode only): trigger category, default "custom".
	Category string `json:"category,omitempty"`
	// Ticket (root_exec only): false lets a matching rootexec request run without a card, as
	// root, journaled; absent or true is a card. For read-only housekeeping (docker ps, logs)
	// that would otherwise interrupt the human ten times a day; the guard and the pinned file
	// still apply.
	Ticket *bool `json:"ticket,omitempty"`

	pack                                              string
	path, argv0, caller, argvText, argvJSON, argvNone *regexp.Regexp
	under, chainAll                                   *regexp.Regexp
	argv                                              []*regexp.Regexp
}

// Config is the exec policy: rules from JSON plus what Setup assembles for an installation.
type Config struct {
	DenyAlways   []*Rule `json:"deny_always"`
	ServiceAllow []*Rule `json:"service_allow"`
	Delegating   []*Rule `json:"delegating"`
	// Tripwire holds custom tripwire rules (tripwire mode); checked before built-in categories.
	Tripwire []*Rule `json:"tripwire,omitempty"`
	// RootExec lists what `wardend rootexec` may ask to run as wardend's own user (root in the
	// hardened install). A request that matches no rule is refused without a card; a matching one
	// is always a card (class rootexec), never inherited from an approved tree. Empty: rootexec is
	// refused altogether. argv0 matches basename(argv[0]) only, not the real file (the exact file
	// is the pinned exe on the card).
	RootExec []*Rule `json:"root_exec,omitempty"`
	// RequireHardware is a ticket overlay, not a class: a matching root is approved only with
	// a ticket carrying a second hardware-key signature (protocol/HARDWARE.md).
	RequireHardware []*HWRule `json:"require_hardware"`
	// Zones holds built-in path zones for tripwire (zones.go); packs and config extend them.
	Zones ZoneSpec `json:"zones,omitempty"`
	// Guard is the regexp matching live gate binaries (guard rule) by realpath.
	Guard string `json:"guard,omitempty"`

	// populated after Setup
	opts        Options
	vars        Vars
	home        string
	packs       []*Pack
	packRules   []*Rule
	agentConfig []*AgentConfigRule
	zones       *Zones
	guardExe    *regexp.Regexp
	// Sys provides system checks for sudo refusal (substituted in tests and replay).
	Sys SysInfo `json:"-"`
}

// Options is the installation against which rules are assembled (variables, packs, zones).
type Options struct {
	AgentHome   string              // ${AGENT_HOME}; "" means $HOME
	Packs       []string            // nil: all built-ins; []: none
	PackVars    map[string][]string // override for pack variables
	WorkDirs    []string            // working directories (work zone); empty: everything outside other zones
	ScratchDirs []string            // additional scratch directories
	Command     []string            // command wardend was started with (pack auto-detection)
	GuardExe    []string            // paths of this wardend/wardenctl binaries (guard rule)
}

// HWRule is a require_hardware rule: Rule fields (AND) plus
//
//	class      regexp on verdict class: root | delegating | inherit | tripwire | implied
//	           ("" matches any);
//	category   regexp on tripwire category (remote, device ...; only for tripwire and implied);
//	min_score  if set, the rule fires only when the ticket has payload.risk >= min_score
//	           (app judge score; checked at decide time). Without min_score the rule is
//	           static: known at queue time; meta.hardware.required is sent to the app immediately.
//
// A root inside an approved tree (inherit, implied) that matches a static rule does NOT
// inherit the approval if its root was approved without a hardware key: it becomes a new root.
type HWRule struct {
	Rule
	Class    string `json:"class,omitempty"`
	HWCat    string `json:"category,omitempty"`
	MinScore *int   `json:"min_score,omitempty"`

	class, cat *regexp.Regexp
}

//go:embed defaults.json
var defaultsJSON []byte

// DefaultsJSON returns the raw JSON of the built-in rules.
func DefaultsJSON() []byte { return append([]byte(nil), defaultsJSON...) }

// Defaults returns the built-in rules with all built-in packs under $HOME.
func Defaults() (*Config, error) { return Parse(defaultsJSON) }

// Load parses the policy file at path; "" means the built-in rules.
func Load(path string) (*Config, error) {
	if path == "" {
		return Defaults()
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return Parse(b)
}

// Parse parses rules from JSON and assembles them for the default installation
// (Setup(Options{})). A file without "zones" and "guard" keys (e.g. captured by
// `wardend policy-defaults` before tripwire mode) receives the built-in values: otherwise
// secrets and protected paths would silently stop being zones.
func Parse(b []byte) (*Config, error) {
	var c Config
	if err := json.Unmarshal(b, &c); err != nil {
		return nil, fmt.Errorf("policy: %w", err)
	}
	var keys map[string]json.RawMessage
	_ = json.Unmarshal(b, &keys)
	_, hasZones := keys["zones"]
	_, hasGuard := keys["guard"]
	if !hasZones || !hasGuard {
		var d Config
		if err := json.Unmarshal(defaultsJSON, &d); err != nil {
			return nil, fmt.Errorf("policy defaults: %w", err)
		}
		if !hasZones {
			c.Zones = d.Zones
		}
		if !hasGuard {
			c.Guard = d.Guard
		}
	}
	if err := c.Setup(Options{}); err != nil {
		return nil, err
	}
	return &c, nil
}

// Setup assembles rules for an installation: variables, packs, zones. Calling it again
// rebuilds everything with new options.
func (c *Config) Setup(o Options) error {
	home := o.AgentHome
	if home == "" {
		home, _ = os.UserHomeDir()
	}
	if home == "" {
		home = "/nonexistent"
	}
	home = filepath.Clean(home)
	v := Vars{"AGENT_HOME": {home}}
	// packs: auto-detect from command -> defaults -> config (config wins)
	names := o.Packs
	if names == nil {
		names = BuiltinPacks()
	}
	var packs []*Pack
	for _, n := range names {
		p, err := LoadPack(n)
		if err != nil {
			return err
		}
		packs = append(packs, p)
	}
	for _, p := range packs {
		det, err := p.detectVars(o.Command)
		if err != nil {
			return err
		}
		for k, def := range p.Vars {
			if isReservedVar(k) {
				return fmt.Errorf("pack %s: variable %s is reserved", p.Name, k)
			}
			v[k] = append(v[k], append(append([]string(nil), det[k]...), def...)...)
		}
	}
	for k, vals := range o.PackVars {
		if isReservedVar(k) {
			return fmt.Errorf("pack_vars: %s is reserved (use agent_home)", k)
		}
		v[k] = append([]string(nil), vals...)
	}
	if err := v.resolveDefaults(); err != nil {
		return err
	}
	c.opts, c.vars, c.home, c.packs = o, v, home, packs

	for _, set := range [][]*Rule{c.DenyAlways, c.ServiceAllow, c.Delegating, c.Tripwire, c.RootExec} {
		for _, r := range set {
			if err := r.compile(v); err != nil {
				return fmt.Errorf("policy rule %q: %w", r.ID, err)
			}
		}
	}
	for _, r := range c.Tripwire {
		if r.Category == "" {
			r.Category = "custom"
		}
	}
	for _, r := range c.RequireHardware {
		if err := r.compile(v); err != nil {
			return err
		}
	}

	// pack rules
	c.packRules, c.agentConfig = nil, nil
	specs := []ZoneSpec{c.Zones}
	for _, p := range packs {
		var rt string
		if p.Runtime != "" {
			var err error
			if rt, err = v.Regex(p.Runtime); err != nil {
				return fmt.Errorf("pack %s: runtime: %w", p.Name, err)
			}
		}
		for _, r := range p.Service {
			q := *r
			q.pack = p.Name
			q.ID = "pack:" + p.Name + "/" + r.ID
			if q.Under == "runtime" {
				if rt == "" {
					return fmt.Errorf("pack %s: rule %s: under runtime, but the pack has no runtime", p.Name, r.ID)
				}
				q.Under = rt
			}
			if err := q.compile(v); err != nil {
				return fmt.Errorf("pack %s: rule %q: %w", p.Name, r.ID, err)
			}
			c.packRules = append(c.packRules, &q)
		}
		for _, r := range p.AgentConfig {
			q := *r
			q.pack, q.family = p.Name, p.Family
			if q.family == "" {
				q.family = p.Name
			}
			if err := q.compile(v); err != nil {
				return fmt.Errorf("pack %s: %w", p.Name, err)
			}
			c.agentConfig = append(c.agentConfig, &q)
		}
		specs = append(specs, p.Zones)
	}
	var work, scratch []PathPattern
	for _, d := range o.WorkDirs {
		work = append(work, PathPattern{Prefix: d})
	}
	for _, d := range o.ScratchDirs {
		scratch = append(scratch, PathPattern{Prefix: d})
	}
	specs = append(specs, ZoneSpec{Work: work, Scratch: scratch})
	z, err := buildZones(specs, v)
	if err != nil {
		return err
	}
	c.zones = z
	guard := c.Guard
	for _, g := range o.GuardExe {
		if g != "" {
			if guard != "" {
				guard += "|"
			}
			guard += "^" + regexp.QuoteMeta(g) + "$"
		}
	}
	c.guardExe = nil
	if guard != "" {
		if c.guardExe, err = compileVar(guard, v); err != nil {
			return fmt.Errorf("policy guard: %w", err)
		}
	}
	if c.Sys == nil {
		c.Sys = sysInfo{}
	}
	return nil
}

// AgentHome returns ${AGENT_HOME} for this rule assembly.
func (c *Config) AgentHome() string { return c.home }

// VarValues returns a copy of the variables for this rule assembly.
func (c *Config) VarValues() Vars { return c.vars.Clone() }

// PackNames returns the loaded harness pack names.
func (c *Config) PackNames() []string {
	var out []string
	for _, p := range c.packs {
		out = append(out, p.Name)
	}
	return out
}

// Zone returns the zone of a path (for debugging and tests).
func (c *Config) Zone(p string) string { return c.zones.Zone(p) }

func (r *Rule) compile(v Vars) error {
	var err error
	c := func(s string) *regexp.Regexp {
		if s == "" || err != nil {
			return nil
		}
		x, e := v.Regex(s)
		if e != nil {
			err = e
			return nil
		}
		re, e := regexp.Compile(x)
		if e != nil {
			err = e
		}
		return re
	}
	r.path, r.argv0, r.caller = c(r.Path), c(r.Argv0), c(r.Caller)
	r.argvText, r.argvJSON, r.argvNone = c(r.ArgvText), c(r.ArgvJSON), c(r.ArgvNone)
	r.under, r.chainAll = c(r.Under), c(r.ChainAll)
	r.argv = nil
	for _, a := range r.Argv {
		r.argv = append(r.argv, c(anchored(a)))
	}
	if r.ID == "" {
		return errors.New("id required")
	}
	return err
}

// compile compiles the Rule part and the class and category regexps; errors name the rule.
func (r *HWRule) compile(v Vars) error {
	if err := r.Rule.compile(v); err != nil {
		return fmt.Errorf("policy rule %q: %w", r.ID, err)
	}
	r.class, r.cat = nil, nil
	if r.Class != "" {
		re, err := regexp.Compile(anchored(r.Class))
		if err != nil {
			return fmt.Errorf("policy rule %q: class: %w", r.ID, err)
		}
		r.class = re
	}
	if r.HWCat != "" {
		re, err := regexp.Compile(anchored(r.HWCat))
		if err != nil {
			return fmt.Errorf("policy rule %q: category: %w", r.ID, err)
		}
		r.cat = re
	}
	if r.MinScore != nil && (*r.MinScore < 0 || *r.MinScore > maxMinScore) {
		return fmt.Errorf("policy rule %q: min_score must be 0..100", r.ID)
	}
	return nil
}

// anchored makes a regexp match the whole string.
func anchored(re string) string { return "^(?:" + re + ")$" }

// Exec holds the data on which the policy makes its decision.
type Exec struct {
	Path      string   // realpath of the executed file ("" if unresolved)
	Argv      []string // as passed to execve
	CallerExe string   // exe of the calling process
	ArgvJSON  string   // canonical JSON of argv (filled by Match if empty)
	Cwd       string   // cwd of the caller (argv paths are resolved relative to it)
	Chain     []string // exe of caller and ancestors up to wardend command ([0] is the caller)
	Pid       int      // tgid of the caller (no_new_privs check for sudo refusal; 0 if unknown)
}

func (r *Rule) match(e *Exec, lenientArgv0 bool) bool {
	if r.path != nil && !r.path.MatchString(e.Path) {
		return false
	}
	if r.argv0 != nil {
		a0 := ""
		if len(e.Argv) > 0 {
			a0 = filepath.Base(e.Argv[0])
		}
		ok := r.argv0.MatchString(a0)
		if !ok && lenientArgv0 && e.Path != "" {
			// deny: `exec -a innocent rm -rf /` - also check the real file name
			ok = r.argv0.MatchString(filepath.Base(e.Path))
		}
		if !ok {
			return false
		}
	}
	if r.caller != nil && !r.caller.MatchString(e.CallerExe) {
		return false
	}
	if r.argvText != nil && !r.argvText.MatchString(strings.Join(e.Argv, " ")) {
		return false
	}
	if r.argvJSON != nil && !r.argvJSON.MatchString(e.ArgvJSON) {
		return false
	}
	if r.Argv != nil {
		if len(e.Argv) != len(r.argv) {
			return false
		}
		for i, re := range r.argv {
			if !re.MatchString(e.Argv[i]) {
				return false
			}
		}
	}
	if r.argvNone != nil && len(e.Argv) > 1 {
		for _, a := range e.Argv[1:] {
			if r.argvNone.MatchString(a) {
				return false
			}
		}
	}
	if r.ChainMax > 0 && len(e.Chain) > r.ChainMax {
		return false
	}
	if r.chainAll != nil {
		if len(e.Chain) == 0 {
			return false
		}
		for _, x := range e.Chain {
			if !r.chainAll.MatchString(x) {
				return false
			}
		}
	}
	if r.under != nil {
		ok := false
		for _, x := range e.Chain {
			if r.under.MatchString(x) {
				ok = true
				break
			}
		}
		if !ok {
			return false
		}
	}
	return true
}

// first returns the first rule that matches e (lenient: argv0 also matches basename(path)).
func first(rules []*Rule, e *Exec, lenient bool) *Rule {
	for _, r := range rules {
		if r.match(e, lenient) {
			return r
		}
	}
	return nil
}

// MatchDeny returns the first deny_always rule that matches e.
func (c *Config) MatchDeny(e *Exec) *Rule { return first(c.DenyAlways, e, true) }

// MatchService matches service_allow first, then pack rules.
func (c *Config) MatchService(e *Exec) *Rule {
	if r := first(c.ServiceAllow, e, false); r != nil {
		return r
	}
	return first(c.packRules, e, false)
}

// MatchDelegating returns the first delegating rule that matches e.
func (c *Config) MatchDelegating(e *Exec) *Rule { return first(c.Delegating, e, true) }

// MatchRootExec returns the first root_exec rule that matches e (strict argv0: what the agent
// asked for, the real file is pinned separately).
func (c *Config) MatchRootExec(e *Exec) *Rule { return first(c.RootExec, e, false) }

// GuardExe reports whether path is one of the live gate binaries (wardend, wardenctl): the guard
// rule of tripwire mode, and what rootexec never runs.
func (c *Config) GuardExe(path string) bool { return c.guardExe != nil && c.guardExe.MatchString(path) }

// RootExecClient reports whether e is wardend's own rootexec client: the gate binary run as
// `wardend rootexec …` or through its `sudo` shim (a symlink named sudo to the gate binary, the
// realpath tells them apart from a real sudo). Its exec is a service launch: the request itself
// is judged by rootexec (its own card or refusal), a second card here would only double it.
func (c *Config) RootExecClient(e *Exec) bool {
	if c.guardExe == nil || !c.guardExe.MatchString(e.Path) || len(e.Argv) == 0 {
		return false
	}
	if rootExecShims[filepath.Base(e.Argv[0])] {
		return true
	}
	return len(e.Argv) > 1 && e.Argv[1] == "rootexec"
}

// NeedsTicket reports whether a root_exec rule asks for a card (absent ticket field: yes).
func (r *Rule) NeedsTicket() bool { return r == nil || r.Ticket == nil || *r.Ticket }

// rootExecShims are the names under which the gate binary acts as the rootexec client for a
// familiar command: `sudo …` and `docker …` on the agent's PATH (rootexec_client.go).
var rootExecShims = map[string]bool{"sudo": true, "docker": true}

// RootExecShim reports whether name is one of the shim names.
func RootExecShim(name string) bool { return rootExecShims[name] }

// rootExecClientRule is the synthetic service rule of RootExecClient (for cards and the journal).
var rootExecClientRule = &Rule{ID: "rootexec-client", Note: "wardend's rootexec client or its sudo shim: the request is judged by rootexec"}

// PrivilegeTool reports whether name is a privilege or namespace tool of the tripwire
// "privilege" category (sudo, su, nsenter, unshare, chroot ...): rootexec refuses them, a card for
// them would hand the agent an unbounded root.
func PrivilegeTool(name string) bool { return privTools[name] }

// hwMatch checks the class and exec fields (argv0 like deny: also basename of the real file,
// so `exec -a innocent sudo` cannot bypass the rule).
func (r *HWRule) hwMatch(e *Exec, class Class, category string) bool {
	switch class {
	case ClassRoot, ClassDelegating, ClassInherit, ClassTripwire, ClassImplied, ClassRootExec:
	default:
		return false
	}
	if r.class != nil && !r.class.MatchString(string(class)) {
		return false
	}
	if r.cat != nil && (category == "" || !r.cat.MatchString(category)) {
		return false
	}
	return r.Rule.match(e, true)
}

// HardwareStatic returns the first rule without min_score that matches the exec for the given class.
func (c *Config) HardwareStatic(e *Exec, class Class) *HWRule {
	return c.HardwareStaticCat(e, class, "")
}

// HardwareStaticCat is the same as HardwareStatic but also matches the tripwire category.
func (c *Config) HardwareStaticCat(e *Exec, class Class, category string) *HWRule {
	for _, r := range c.RequireHardware {
		if r.MinScore == nil && r.hwMatch(e, class, category) {
			return r
		}
	}
	return nil
}

// HardwareMinScore returns the smallest min_score among rules matching by class/exec
// (hint for the app); ok=false means no such rules.
func (c *Config) HardwareMinScore(e *Exec, class Class) (int, bool) {
	return c.HardwareMinScoreCat(e, class, "")
}

// HardwareMinScoreCat is the same as HardwareMinScore but also matches the tripwire category.
func (c *Config) HardwareMinScoreCat(e *Exec, class Class, category string) (int, bool) {
	best, ok := 0, false
	for _, r := range c.RequireHardware {
		if r.MinScore != nil && r.hwMatch(e, class, category) && (!ok || *r.MinScore < best) {
			best, ok = *r.MinScore, true
		}
	}
	return best, ok
}

// HardwareByScore returns the first rule with min_score <= score that matches by class/exec.
func (c *Config) HardwareByScore(e *Exec, class Class, score int) *HWRule {
	return c.HardwareByScoreCat(e, class, "", score)
}

// HardwareByScoreCat is the same as HardwareByScore but also matches the tripwire category.
func (c *Config) HardwareByScoreCat(e *Exec, class Class, category string, score int) *HWRule {
	for _, r := range c.RequireHardware {
		if r.MinScore != nil && score >= *r.MinScore && r.hwMatch(e, class, category) {
			return r
		}
	}
	return nil
}

// HWRuleInfo is the require_hardware rule exposed in status: the app shows the user
// "Key required for: ..." using rule names, not counts. Argv and path matchers are not exposed.
type HWRuleInfo struct {
	ID       string `json:"id"`
	Note     string `json:"note,omitempty"`
	Class    string `json:"class,omitempty"`
	Category string `json:"category,omitempty"`
	MinScore *int   `json:"minScore,omitempty"`
}

// HardwareRulesInfo returns require_hardware rules in policy order (empty slice, not nil).
func (c *Config) HardwareRulesInfo() []HWRuleInfo {
	out := make([]HWRuleInfo, 0, len(c.RequireHardware))
	for _, r := range c.RequireHardware {
		info := HWRuleInfo{ID: r.ID, Note: r.Note, Class: r.Class, Category: r.HWCat}
		if r.MinScore != nil {
			v := *r.MinScore
			info.MinScore = &v
		}
		out = append(out, info)
	}
	return out
}
